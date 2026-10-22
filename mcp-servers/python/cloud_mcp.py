"""Local Terraform MCP using Checkov; never claims live cloud IAM access."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import math
import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.routing import APIRoute
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict

app = FastAPI(title="Local IaC MCP")
_SERVER = "cloud-mcp"
_MAX_OUTPUT = 2_000_000
_MAX_EXECUTE_BODY = 8192
_LABEL = re.compile(r"[A-Za-z0-9_./:-]{1,160}\Z")
_CHECK = re.compile(r"CKV(?:2)?_[A-Za-z0-9_]{1,64}\Z")
_REQUEST = re.compile(r"req-[A-Za-z0-9_-]{1,120}\Z")


def _unique_json_pairs(pairs: list[tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate Cloud request JSON key")
        result[key] = value
    return result


def _finite_json_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("Nonfinite Cloud request JSON number")
    return number


class _BoundedCloudExecuteRoute(APIRoute):
    """Pre-FastAPI/Pydantic wire bounds for host-gated static IaC dispatch."""

    def get_route_handler(self):
        original = super().get_route_handler()
        if self.path != "/mcp/execute":
            return original

        async def bounded(request: Request):
            types = request.headers.getlist("content-type")
            if len(types) != 1 or types[0].lower().split(";", 1)[0].strip() != "application/json":
                raise HTTPException(415, "Strict Cloud request JSON required")
            lengths = request.headers.getlist("content-length")
            if len(lengths) > 1 or (
                lengths
                and (
                    not lengths[0]
                    or len(lengths[0]) > 4
                    or not lengths[0].isascii()
                    or not lengths[0].isdecimal()
                    or int(lengths[0]) > _MAX_EXECUTE_BODY
                )
            ):
                raise HTTPException(413, "Cloud request exceeds wire bounds")
            raw = bytearray()
            async for chunk in request.stream():
                if len(raw) + len(chunk) > _MAX_EXECUTE_BODY:
                    raise HTTPException(413, "Cloud request exceeds wire bounds")
                raw.extend(chunk)
            try:
                payload = json.loads(
                    bytes(raw).decode("utf-8", errors="strict"),
                    object_pairs_hook=_unique_json_pairs,
                    parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
                    parse_float=_finite_json_float,
                )
            except (ValueError, UnicodeError, RecursionError, OverflowError, TypeError) as exc:
                raise HTTPException(422, "Strict Cloud request JSON required") from exc
            if type(payload) is not dict:
                raise HTTPException(422, "Cloud request object required")
            request._body = bytes(raw)
            return await original(request)

        return bounded


# Set on the actual FastAPI router before its handlers are registered.
app.router.route_class = _BoundedCloudExecuteRoute


class _ExecuteRequest(BaseModel):
    # Never silently ignore client-side claims of cloud IAM/target verification
    # or caller-selected paths. Even if the response is inert, unknown intent
    # is a malformed operator-gated dispatch rather than accepted metadata.
    model_config = ConfigDict(extra="forbid", strict=True)

    tool_name: str
    parameters: Dict[str, Any]
    request_id: Optional[str] = None
    # MCPRegistry serializes this optional field even for a default execution.
    # It is never interpreted as an operator-selected command or target.
    timeout_override: Optional[int] = None


def _response(status_code: int, content: Dict[str, Any]) -> JSONResponse:
    return JSONResponse(
        content=content, status_code=status_code, headers={"Cache-Control": "no-store"}
    )


def _safe_path(path: Path, *, root: Optional[Path] = None) -> None:
    """Deny symlink/junction/reparse paths, including intermediate directories."""
    current = path
    while True:
        meta = current.lstat()
        if (
            stat.S_ISLNK(meta.st_mode)
            or current.is_symlink()
            or bool(
                getattr(meta, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
            )
            or (getattr(current, "is_junction", lambda: False)())
        ):
            raise ValueError("Unapproved local IaC link or reparse point")
        if current == current.parent or (root is not None and current == root):
            break
        current = current.parent


def _source_bytes(root: Path) -> tuple[Dict[str, bytes], str]:
    """Read exact bounded current bytes, rejecting link swaps during each read."""
    _safe_path(root)
    entries = sorted(root.rglob("*"))
    if not 1 <= len(entries) <= 50:
        raise ValueError("Local IaC file count unavailable")
    blobs: Dict[str, bytes] = {}
    total = 0
    for entry in entries:
        relative = entry.relative_to(root).as_posix()
        if entry.suffix != ".tf" or _LABEL.fullmatch(relative) is None or not entry.is_file():
            raise ValueError("Local IaC tree must contain only Terraform files")
        _safe_path(entry, root=root)
        before = entry.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError("Only independent regular Terraform files permitted")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(entry, flags)
        try:
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise ValueError("IaC source changed at open")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                data = stream.read(1_000_001 - total)
            after = entry.lstat()
            if (
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
                or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
                or len(data) != opened.st_size
            ):
                raise ValueError("IaC source changed while reading")
            _safe_path(entry, root=root)
        finally:
            os.close(fd)
        total += len(data)
        if total > 1_000_000:
            raise ValueError("Local IaC source exceeds limit")
        blobs[relative] = data
    digests = [f"{name}:{hashlib.sha256(data).hexdigest()}" for name, data in blobs.items()]
    manifest = hashlib.sha256("\n".join(digests).encode("ascii")).hexdigest()
    return blobs, manifest


def _configuration() -> tuple[Path, Path, str, str]:
    """Read one operator-pinned, bounded local tree; no caller-selected paths."""
    root = Path(os.getenv("OSOP_CLOUD_MCP_IAC_ROOT", ""))
    executable = Path(os.getenv("OSOP_CLOUD_MCP_CHECKOV_PYTHON", ""))
    token = os.getenv("OSOP_CLOUD_MCP_BEARER_TOKEN", "")
    if (
        os.getenv("OSOP_CLOUD_MCP_LOCAL_IAC_ENABLED") != "1"
        or not root.is_absolute()
        or not executable.is_absolute()
        or not 32 <= len(token) <= 512
        or not token.isascii()
        or any(not 33 <= ord(char) <= 126 for char in token)
        or root.is_symlink()
        or executable.is_symlink()
        or not root.is_dir()
        or not executable.is_file()
    ):
        raise ValueError("Local IaC source unavailable")
    _safe_path(root)
    _safe_path(executable)
    root = root.resolve(strict=True)
    executable = executable.resolve(strict=True)
    _, manifest = _source_bytes(root)
    return root, executable, token, manifest


def _findings(document: Any, root: Path) -> list[Dict[str, Any]]:
    reports = document if isinstance(document, list) else [document]
    if not 1 <= len(reports) <= 4:
        raise ValueError("Checkov report unavailable")
    findings: list[Dict[str, Any]] = []
    for report in reports:
        if not isinstance(report, dict) or report.get("check_type") != "terraform":
            raise ValueError("Checkov framework unavailable")
        results = report.get("results")
        failed = results.get("failed_checks") if isinstance(results, dict) else None
        if not isinstance(failed, list) or len(failed) > 500:
            raise ValueError("Checkov failures unavailable")
        for item in failed:
            if not isinstance(item, dict):
                raise ValueError("Checkov finding unavailable")
            check_id, file_path, resource = (
                item.get("check_id"),
                item.get("file_path"),
                item.get("resource"),
            )
            lines = item.get("file_line_range")
            relative_file = (
                file_path.replace("\\", "/").lstrip("/") if isinstance(file_path, str) else ""
            )
            # Checkov uses leading '/' for paths relative to --directory.
            # Never re-label an absolute Windows drive path, nonexistent file,
            # symlink escape or arbitrary scanner-provided path as originating
            # from the operator-approved Terraform tree.
            source = root / relative_file
            try:
                within_root = (
                    source.is_file()
                    and not source.is_symlink()
                    and source.resolve(strict=True).is_relative_to(root.resolve(strict=True))
                )
            except (OSError, RuntimeError):
                within_root = False
            if (
                not isinstance(check_id, str)
                or _CHECK.fullmatch(check_id) is None
                or _LABEL.fullmatch(relative_file) is None
                or relative_file.startswith("../")
                or "/../" in relative_file
                or ":" in relative_file
                or source.suffix != ".tf"
                or not within_root
                or not isinstance(resource, str)
                or _LABEL.fullmatch(resource) is None
                or not isinstance(lines, list)
                or len(lines) != 2
                or any(type(line) is not int or not 0 <= line <= 1_000_000 for line in lines)
            ):
                raise ValueError("Checkov finding identity unavailable")
            findings.append(
                {
                    "check_id": check_id,
                    "file": relative_file,
                    "resource": resource,
                    "line": lines[0],
                    "validation_state": "STATIC_IAC_ONLY",
                }
            )
            if len(findings) >= 100:
                return findings
    return findings


async def _scan(root: Path, executable: Path) -> list[Dict[str, Any]]:
    environment = {
        key: os.environ[key]
        for key in ("PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP")
        if key in os.environ
    }
    environment["BC_API_KEY"] = ""
    # Checkov's platform-key module calls Path.home() during import. Without
    # HOME/USERPROFILE it fails before scanning on Windows; forwarding the real
    # host home would instead expose local credentials/config to Checkov.
    # Give this one inert, static-IaC subprocess a fresh disposable home only.
    # The initial manifest in mcp_execute is only an admission fence. The
    # scanner must NEVER parse the mutable live tree directly: own a private
    # frozen copy and reconcile the original manifest before and after work.
    original, original_manifest = _source_bytes(root)
    with tempfile.TemporaryDirectory(prefix="osop-checkov-stage-") as stage:
        stage_root = Path(stage)
        for relative, data in original.items():
            destination = stage_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open("xb") as stream:
                stream.write(data)
        if _source_bytes(stage_root)[1] != original_manifest:
            raise ValueError("Frozen IaC stage differs from readback")
        if _source_bytes(root)[1] != original_manifest:
            raise ValueError("Operator-pinned IaC bytes changed during staging")
        result = await _scan_frozen(stage_root, executable)
        # Neither an invoked parser nor a same-user process may silently
        # rewrite the private source and preserve a stale original SHA claim.
        if _source_bytes(stage_root)[1] != original_manifest:
            raise ValueError("Staged IaC bytes changed during Checkov")
        if _source_bytes(root)[1] != original_manifest:
            raise ValueError("Operator-pinned IaC bytes changed during Checkov")
        return result


async def _scan_frozen(root: Path, executable: Path) -> list[Dict[str, Any]]:
    """Run Checkov against only the private, read-only-equivalent staged copy."""
    with tempfile.TemporaryDirectory(prefix="osop-checkov-home-") as home:
        # A private sitecustomize audit hook prevents Python-level Checkov
        # sockets and nested shell/subprocess launches even if an upstream
        # version ignores --skip-download. This is NOT an OS network sandbox:
        # native extensions or a compromised interpreter need a separate
        # unprivileged network namespace/firewall for full isolation.
        Path(home, "sitecustomize.py").write_text(
            "import sys\n"
            "def _deny_cloud_iac_io(event, args):\n"
            "    if event in ('socket.connect', 'socket.getaddrinfo', "
            "'subprocess.Popen', 'os.system'):\n"
            "        raise PermissionError('Offline static-IaC subprocess policy')\n"
            "sys.addaudithook(_deny_cloud_iac_io)\n",
            encoding="ascii",
        )
        environment = {
            key: os.environ[key]
            for key in ("PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP")
            if key in os.environ
        }
        environment["BC_API_KEY"] = ""
        environment["PYTHONPATH"] = home
        environment["HOME"] = home
        environment["USERPROFILE"] = home
        process = await asyncio.wait_for(
            asyncio.create_subprocess_exec(
                str(executable),
                "-c",
                "from checkov.main import Checkov; raise SystemExit(Checkov().run())",
                "--directory",
                str(root),
                "--framework",
                "terraform",
                "--output",
                "json",
                "--skip-download",
                "--download-external-modules",
                "false",
                "--compact",
                cwd=str(root),
                env=environment,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            ),
            timeout=10,
        )
        try:
            assert process.stdout is not None
            output = await asyncio.wait_for(process.stdout.read(_MAX_OUTPUT + 1), timeout=60)
            if len(output) > _MAX_OUTPUT:
                raise ValueError("Checkov output exceeds limit")
            await asyncio.wait_for(process.wait(), timeout=5)
            if process.returncode not in (0, 1):
                raise ValueError("Checkov execution failed")
            return _findings(json.loads(output), root)
        finally:
            if process.returncode is None:
                process.kill()
                # Reaping cannot hold a cancelled HTTP request forever.
                await asyncio.wait_for(process.wait(), timeout=5)


@app.get("/health")
async def health() -> JSONResponse:
    try:
        _configuration()
    except (OSError, ValueError):
        return _response(status_code=503, content={"server_id": _SERVER, "status": "unavailable"})
    return _response(
        200,
        {
            "server_id": _SERVER,
            "status": "ready",
            "capability": "local_iac_only",
            "live_cloud_account_verified": False,
        },
    )


@app.post("/mcp/initialize")
async def mcp_initialize() -> JSONResponse:
    try:
        _configuration()
    except (OSError, ValueError):
        return _response(
            200,
            {
                "server_id": _SERVER,
                "version": "1.2.0",
                "status": "unavailable",
                "capabilities": [],
                "tools": [],
            },
        )
    return _response(
        200,
        {
            "server_id": _SERVER,
            "version": "1.2.0",
            "status": "ready",
            "capabilities": ["local_iac_static_unverified"],
            "tools": [
                {
                    "name": "scan_local_iac",
                    "description": "Scan operator-pinned local Terraform with Checkov.",
                    "parameters": [],
                    "returns": {"findings": "array"},
                    "side_effect_class": "READ_ONLY",
                    "requires_approval": True,
                    "scope_check": True,
                    "timeout_seconds": 70,
                }
            ],
        },
    )


@app.post("/mcp/execute")
async def mcp_execute(
    request: _ExecuteRequest, authorization: Optional[str] = Header(default=None)
) -> JSONResponse:
    try:
        root, executable, token, manifest = _configuration()
    except (OSError, ValueError):
        return _response(503, {"status": "error", "error": "local_iac_unavailable"})
    if (
        not isinstance(authorization, str)
        or not authorization.startswith("Bearer ")
        or not hmac.compare_digest(authorization[7:], token)
    ):
        return _response(401, {"status": "error", "error": "unauthorized"})
    if (
        request.tool_name != "scan_local_iac"
        or request.parameters != {}
        or request.timeout_override is not None
        and (type(request.timeout_override) is not int or not 1 <= request.timeout_override <= 70)
        or not isinstance(request.request_id, str)
        or _REQUEST.fullmatch(request.request_id) is None
    ):
        return _response(422, {"status": "error", "error": "invalid_request"})
    try:
        findings = await _scan(root, executable)
        if _configuration()[3] != manifest:
            raise ValueError("Local IaC changed during scan")
    except (OSError, ValueError, asyncio.TimeoutError, json.JSONDecodeError):
        return _response(503, {"status": "error", "error": "scan_unknown"})
    return _response(
        200,
        {
            "request_id": request.request_id,
            "status": "success",
            "result": {
                "findings": findings,
                "findings_count": len(findings),
                "input_manifest_sha256": manifest,
                "source": "CHECKOV_LOCAL_IAC_UNVERIFIED",
                "live_cloud_account_verified": False,
                "target_effect_verified": False,
            },
        },
    )


if __name__ == "__main__":
    import argparse

    import uvicorn

    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8097)
    args = parser.parse_args()
    uvicorn.run(app, host="127.0.0.1", port=args.port)
