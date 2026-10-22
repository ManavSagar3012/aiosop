"""Test-only controlled target ownership oracle over genuine ASGI HTTP requests.

Nothing here runs against an external domain or application database. A lab
attestation is not evidence that an unrelated deployed target is vulnerable.
"""

import hashlib
import json
from copy import deepcopy

import httpx
import pytest
from fastapi import FastAPI, HTTPException, Request

from ai_osop.core.target_authority_proof import (
    TargetAuthorityDenied,
    verify_target_authority_proof,
)
from tests.test_target_authority_proof_20261016 import proof_case  # noqa: F401


def _controlled_target(*, bug: bool, publicly_readable: bool) -> FastAPI:
    app = FastAPI()
    # Target-side truth, never provided by a model, browser receipt, or API client.
    records = {"123": {"owner": "account_a", "data": "controlled-object-123"}}

    @app.get("/api/record/123")
    async def read_owned(request: Request):
        actor = {
            "Bearer source-test-session": "account_a",
            "Bearer target-test-session": "account_b",
        }.get(request.headers.get("authorization", ""))
        obj = records["123"]
        if actor is None and not publicly_readable:
            raise HTTPException(status_code=403, detail="Not authenticated")
        if actor not in {obj["owner"], None} and not bug and not publicly_readable:
            raise HTTPException(status_code=403, detail="Not your resource")
        return obj

    return app


def _response_digest(*, engagement: str, response_body: dict) -> str:
    canonical = json.dumps(
        response_body,
        separators=(",", ":"),
        sort_keys=True,
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(
        b"osop-signed-replay-v1:" + engagement.encode() + b":wf-tenant:step-resource:" + canonical
    ).hexdigest()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bug,public,valid",
    [
        (True, False, True),
        (False, False, False),
        (True, True, False),
    ],
)
async def test_real_controlled_http_ownership_oracle_fences_candidate(
    proof_case,
    bug: bool,
    public: bool,
    valid: bool,
) -> None:
    app = _controlled_target(bug=bug, publicly_readable=public)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://controlled-target.local"
    ) as client:
        source = await client.get(
            "/api/record/123", headers={"Authorization": "Bearer source-test-session"}
        )
        target = await client.get(
            "/api/record/123", headers={"Authorization": "Bearer target-test-session"}
        )
        anonymous = await client.get("/api/record/123")

    assert source.status_code == 200
    assert source.json()["owner"] == "account_a"
    assert (target.status_code == 200 and anonymous.status_code == 403) is valid
    case = proof_case
    case.source.result["response_body_sha256"] = _response_digest(
        engagement=case.source.engagement_id,
        response_body=source.json(),
    )
    if target.status_code == 200:
        case.target.result["response_body_sha256"] = _response_digest(
            engagement=case.target.engagement_id,
            response_body=target.json(),
        )
    else:
        case.target.result["http_status_code"] = target.status_code
    statement = deepcopy(case.claims)
    statement["source_response_sha256"] = case.source.result["response_body_sha256"]
    statement["target_response_sha256"] = case.target.result["response_body_sha256"]
    statement["target_http_status"] = target.status_code
    statement["anonymous_http_status"] = anonymous.status_code
    statement["public_access"] = public
    statement["resource_visibility"] = "public" if public else "private"
    statement["resource_owner_identity"] = source.json()["owner"]
    statement["cross_identity_disclosure_confirmed"] = valid
    proof, signature = case.signed_bytes(statement)
    if valid:
        outcome = await verify_target_authority_proof(
            claims_json=proof,
            signature_b64url=signature,
            **case.context,
        )
        assert outcome.independent_target_authority_verified is True
        assert outcome.finding_verified is False
        assert outcome.authorization_violation_verified is False
        assert outcome.report_release_approved is False
    else:
        with pytest.raises(TargetAuthorityDenied):
            await verify_target_authority_proof(
                claims_json=proof,
                signature_b64url=signature,
                **case.context,
            )
        assert case.replay.calls == []
