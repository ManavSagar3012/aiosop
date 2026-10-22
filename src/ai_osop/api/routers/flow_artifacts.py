"""Owner-only immutable Flow artifacts; raw bytes, never execution surfaces.

Upload: POST /flows/{flow_id}/artifacts?name=notes.txt&expected_revision=0&expected_authorization_version=1
Content-Type: application/octet-stream, payload <= 2 MiB.

GET collection and GET /{artifact_id} require the same explicit revision and
signed ROE version. Files are stored in PostgreSQL BYTEA, not filesystem paths.

Read-only resource manifest and bounded ZIP_STORED export do not mirror
resources into an execution container or working directory.
"""

import hashlib
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from ai_osop.api.deps import state, verify_token
from ai_osop.memory.flow_artifacts import (
    ArtifactDenied,
    FlowArtifactStore,
    MAX_BYTES,
)
from ai_osop.memory.flow_resource_exports import FlowResourceExports, make_bundle

router = APIRouter(prefix="/flows", tags=["flow-artifacts"])


async def _operator(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer(auto_error=False)),
) -> Dict[str, Any]:
    if (
        credentials is None
        or credentials.scheme.lower() != "bearer"
        or "token" in request.query_params
    ):
        raise HTTPException(status_code=401, detail="Operator bearer header required")
    operator = await verify_token(credentials=credentials, token=None)
    if operator.get("role") not in {"operator", "senior_operator"}:
        raise HTTPException(status_code=403, detail="Verified operator role required")
    # A shared API key or unsigned identity is never a tenant owner. Require
    # signed JWT identity/expiry, whether local HMAC or configured OIDC.
    claims = operator.get("claims")
    if (
        not isinstance(claims, dict)
        or type(claims.get("exp")) is not int
        or not isinstance(operator.get("sub"), str)
    ):
        raise HTTPException(status_code=403, detail="Signed operator identity required")
    return operator


def _store() -> FlowArtifactStore:
    orch = state.get("orchestrator")
    memory = getattr(orch, "session_memory", None)
    if memory is None:
        raise HTTPException(status_code=503, detail="Durable Flow artifacts unavailable")
    return FlowArtifactStore(memory)


def _failure(exc: ArtifactDenied) -> HTTPException:
    return HTTPException(status_code=exc.status, detail=str(exc))


@router.post("/{flow_id}/artifacts", status_code=201)
async def upload_flow_artifact(
    flow_id: str,
    request: Request,
    name: str = Query(min_length=1, max_length=128),
    expected_revision: int = Query(ge=0),
    expected_authorization_version: int = Query(ge=1),
    operator: Dict[str, Any] = Depends(_operator),
) -> Dict[str, Any]:
    # Streaming the raw body (not a multipart parser) keeps our upper bound
    # enforceable before PostgreSQL is touched. No MIME type is trusted for
    # inline rendering; reads are always attachment/octet-stream.
    if (
        request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        != "application/octet-stream"
    ):
        raise HTTPException(status_code=415, detail="Binary upload content type required")
    length = request.headers.get("content-length")
    if length is not None:
        try:
            if int(length) > MAX_BYTES:
                raise HTTPException(status_code=413, detail="Flow artifact exceeds size limit")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid upload length") from exc
    blob = bytearray()
    try:
        async for chunk in request.stream():
            if len(chunk) > MAX_BYTES - len(blob):
                raise HTTPException(status_code=413, detail="Flow artifact exceeds size limit")
            blob.extend(chunk)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Flow artifact upload interrupted") from exc
    try:
        return await _store().upload(
            flow_id,
            operator["sub"],
            expected_revision,
            expected_authorization_version,
            name,
            bytes(blob),
        )
    except ArtifactDenied as exc:
        raise _failure(exc) from exc


@router.get("/{flow_id}/artifacts")
async def list_flow_artifacts(
    flow_id: str,
    response: Response,
    expected_revision: int = Query(ge=0),
    expected_authorization_version: int = Query(ge=1),
    operator: Dict[str, Any] = Depends(_operator),
) -> Dict[str, Any]:
    try:
        artifacts = await _store().list(
            flow_id,
            operator["sub"],
            expected_revision,
            expected_authorization_version,
        )
    except ArtifactDenied as exc:
        raise _failure(exc) from exc
    response.headers["Cache-Control"] = "private, no-store"
    return {"items": artifacts, "total": len(artifacts)}


@router.get("/{flow_id}/artifacts/resource-manifest")
async def export_flow_resource_manifest(
    flow_id: str,
    response: Response,
    expected_revision: int = Query(ge=0),
    expected_authorization_version: int = Query(ge=1),
    operator: Dict[str, Any] = Depends(_operator),
) -> Dict[str, Any]:
    """Signed owner-only SHA-verified, inert artifact resource manifest."""
    try:
        manifest, _ = await FlowResourceExports(_store()).prepare(
            flow_id,
            operator["sub"],
            expected_revision,
            expected_authorization_version,
        )
    except ArtifactDenied as exc:
        raise _failure(exc) from exc
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Resource-Manifest-SHA256"] = manifest["manifest_sha256"]
    return manifest


@router.get("/{flow_id}/artifacts/resource-bundle")
async def export_flow_resource_bundle(
    flow_id: str,
    expected_revision: int = Query(ge=0),
    expected_authorization_version: int = Query(ge=1),
    operator: Dict[str, Any] = Depends(_operator),
) -> Response:
    """In-memory stored ZIP only; never extract, execute, or write host files."""
    try:
        manifest, snapshot = await FlowResourceExports(_store()).prepare(
            flow_id,
            operator["sub"],
            expected_revision,
            expected_authorization_version,
        )
        packed = make_bundle(snapshot, manifest)
    except ArtifactDenied as exc:
        raise _failure(exc) from exc
    return Response(
        content=packed,
        media_type="application/zip",
        headers={
            "Content-Disposition": 'attachment; filename="flow-resources.zip"',
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "private, no-store",
            "X-Resource-Manifest-SHA256": manifest["manifest_sha256"],
            "X-Resource-Archive-SHA256": hashlib.sha256(packed).hexdigest(),
        },
    )


@router.get("/{flow_id}/artifacts/{artifact_id}")
async def read_flow_artifact(
    flow_id: str,
    artifact_id: str,
    expected_revision: int = Query(ge=0),
    expected_authorization_version: int = Query(ge=1),
    operator: Dict[str, Any] = Depends(_operator),
) -> Response:
    try:
        info, blob = await _store().read(
            flow_id,
            artifact_id,
            operator["sub"],
            expected_revision,
            expected_authorization_version,
        )
    except ArtifactDenied as exc:
        raise _failure(exc) from exc
    return Response(
        content=blob,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{info["name"]}"',
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "private, no-store",
            "X-Artifact-SHA256": info["sha256"],
        },
    )
