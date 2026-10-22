"""Local native Browser MCP runtime and signed capture evidence boundaries.

No actual Playwright launch, live target, application database or provider I/O.
Exercise FastAPI's real handler, journal and filesystem with fake page bytes.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.mcp.receipt_attestation import provider_receipt_is_signed
from tests.test_browser_mcp_signed_provider import (
    SID,
    TASK,
    USER,
    _binding,
    _post,
    _request,
    provider,
)


_PNG = b"\x89PNG\r\n\x1a\n" + b"controlled-local-png-data"
_HTML = "<html><body>authenticated local fixture</body></html>"


async def _establish_page(provider: SimpleNamespace) -> None:
    established = (await _post(provider, _request("req-runtime-open"))).json()
    assert established["status"] == "success"
    page = provider.browser.created[0].page
    page.screenshot = AsyncMock(return_value=_PNG)
    page.content = AsyncMock(return_value=_HTML)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "action,request_id,extension,expected",
    [
        ("screenshot", "req-runtime-shot", ".png", _PNG),
        ("dom_snapshot", "req-runtime-dom", ".html", _HTML.encode("utf-8")),
    ],
)
async def test_signed_capture_pins_original_bytes_to_owner_mount(
    provider: SimpleNamespace,
    action: str,
    request_id: str,
    extension: str,
    expected: bytes,
) -> None:
    await _establish_page(provider)
    response = (await _post(provider, _request(request_id, action))).json()
    assert response["status"] == "success"
    assert provider_receipt_is_signed(
        response["provider_receipt"],
        "browser-mcp",
        request_id,
        SID,
        TASK,
    )
    result = response["result"]
    assert result["path"].startswith("captures/")
    assert result["path"].endswith(extension)
    assert result["exists"] is True
    assert result["capture_task_id"] == TASK
    assert result["mount_sha256"] == provider.digest
    assert result["size_bytes"] == len(expected)
    assert result["resource_sha256"] == hashlib.sha256(expected).hexdigest()
    assert (provider.root / SID / result["path"]).read_bytes() == expected
    assert not (provider.root / "eng-other-fixture" / result["path"]).exists()
    assert "manual-evidence" not in json.dumps(response)
    assert "authenticated local fixture" not in json.dumps(response)
    assert "path" not in response["provider_receipt"]


@pytest.mark.asyncio
@pytest.mark.parametrize("action", ["screenshot", "dom_snapshot"])
async def test_signed_capture_requires_existing_page_without_creating_one(
    provider: SimpleNamespace,
    action: str,
) -> None:
    request_id = f"req-empty-{action}"
    denied = (await _post(provider, _request(request_id, action))).json()
    assert denied["status"] == "error"
    assert "provider_receipt" not in denied
    assert provider.browser.created == []
    unknown = (await _post(provider, _binding(request_id), url="/mcp/request/status")).json()
    assert unknown["result"]["status"] == "unknown"


@pytest.mark.asyncio
async def test_signed_capture_error_dictionary_never_becomes_signed_success(
    provider: SimpleNamespace,
) -> None:
    await _establish_page(provider)
    provider.module.manager.screenshot = AsyncMock(
        return_value={
            "path": "",
            "error": "screenshot device failed",
            "url": "https://with-secret.invalid/",
        }
    )
    request_id = "req-signed-capture-error"
    denied = (await _post(provider, _request(request_id, "screenshot"))).json()
    assert denied["status"] == "error" and "provider_receipt" not in denied
    assert "with-secret" not in json.dumps(denied)
    assert "device failed" not in json.dumps(denied)
    unknown = (await _post(provider, _binding(request_id), url="/mcp/request/status")).json()
    assert unknown["result"]["status"] == "unknown"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "action,value",
    [
        pytest.param("screenshot", b"not-a-png", id="invalid-png"),
        pytest.param(
            "screenshot",
            b"\x89PNG\r\n\x1a\n" + b"X" * (4 * 1024 * 1024),
            id="oversize-png",
        ),
        pytest.param("dom_snapshot", "x" * (1024 * 1024 + 1), id="oversize-dom"),
    ],
)
async def test_invalid_or_oversize_signed_capture_never_persists_or_attests(
    provider: SimpleNamespace,
    action: str,
    value: object,
) -> None:
    await _establish_page(provider)
    page = provider.browser.created[0].page
    if action == "screenshot":
        page.screenshot.return_value = value
    else:
        page.content.return_value = value
    request_id = f"req-deny-{action}-{len(value)}"
    denied = (await _post(provider, _request(request_id, action))).json()
    assert denied["status"] == "error" and "provider_receipt" not in denied
    assert list((provider.root / SID / "captures").iterdir()) == []
    unknown = (await _post(provider, _binding(request_id), url="/mcp/request/status")).json()
    assert unknown["result"]["status"] == "unknown"


@pytest.mark.asyncio
async def test_signed_capture_revoked_mount_during_page_response_remains_unknown(
    provider: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await _establish_page(provider)

    async def revoke_during_capture(**kwargs: object) -> bytes:
        monkeypatch.setenv(
            "OSOP_AUTHENTICATED_HAR_MOUNT_DIGESTS",
            json.dumps({SID: "0" * 64}),
        )
        return _PNG

    provider.browser.created[0].page.screenshot.side_effect = revoke_during_capture
    response = (await _post(provider, _request("req-mount-revoked", "screenshot"))).json()
    assert response["status"] == "error" and "provider_receipt" not in response
    assert list((provider.root / SID / "captures").iterdir()) == []
    assert provider.module.RequestJournal(_binding("req-mount-revoked")).read() == "unknown"


@pytest.mark.asyncio
async def test_signed_capture_corrupt_readback_never_signed(
    provider: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await _establish_page(provider)
    original_read = provider.module._regular_blob

    def corrupted_artifact(path: Path, size: int) -> bytes:
        if path.suffix == ".png":
            return b"modified after write"
        return original_read(path, size)

    monkeypatch.setattr(provider.module, "_regular_blob", corrupted_artifact)
    response = (await _post(provider, _request("req-corrupt-readback", "screenshot"))).json()
    assert response["status"] == "error" and "provider_receipt" not in response
    assert provider.module.RequestJournal(_binding("req-corrupt-readback")).read() == "unknown"


@pytest.mark.asyncio
async def test_browser_start_rejects_missing_trust_without_launch(
    provider: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = provider.module
    runtime = module.BrowserManager()
    monkeypatch.setenv("OSOP_ENVIRONMENT", "production")
    monkeypatch.delenv("OSOP_BROWSER_MCP_RECEIPT_PRIVATE_KEY_B64")
    launch = AsyncMock(side_effect=AssertionError("Playwright must not start"))
    monkeypatch.setattr(module, "async_playwright", launch)
    with pytest.raises(ValueError, match="prerequisites unavailable"):
        await runtime.start()
    launch.assert_not_awaited()
    assert runtime._started is False and runtime.browser is None


@pytest.mark.asyncio
async def test_browser_start_failed_chromium_launch_stops_playwright_driver(
    provider: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = provider.module
    runtime = module.BrowserManager()
    monkeypatch.setenv("OSOP_ENVIRONMENT", "production")
    # Satisfy source configuration inspection ONLY to reach the independent
    # launch-failure cleanup path. No real source HTTP or browser I/O occurs.
    monkeypatch.setattr(
        module,
        "_source_configuration",
        lambda: (
            "https://127.0.0.1:18443/native-browser/source-preflight",
            "offline-ca.pem",
            "fake-service-token",
            {"kid": b"a" * 32},
        ),
    )
    driver = SimpleNamespace(
        chromium=SimpleNamespace(launch=AsyncMock(side_effect=RuntimeError("local launch failed"))),
        stop=AsyncMock(),
    )
    monkeypatch.setattr(
        module, "async_playwright", lambda: SimpleNamespace(start=AsyncMock(return_value=driver))
    )
    with pytest.raises(RuntimeError, match="local launch failed"):
        await runtime.start()
    driver.stop.assert_awaited_once()
    assert runtime._started is False and runtime.browser is None


@pytest.mark.asyncio
async def test_browser_stop_clears_cached_signed_identity_even_if_browser_close_fails(
    provider: SimpleNamespace,
) -> None:
    await _establish_page(provider)
    runtime = provider.module.manager
    assert runtime.pages and runtime.contexts and runtime.meta
    runtime.browser.close = AsyncMock(side_effect=RuntimeError("driver disconnected"))
    driver = SimpleNamespace(stop=AsyncMock())
    runtime.playwright = driver
    with pytest.raises(RuntimeError, match="driver disconnected"):
        await runtime.stop()
    driver.stop.assert_awaited_once()
    assert not runtime._started
    assert runtime.browser is None and runtime.playwright is None
    assert not runtime.pages and not runtime.contexts and not runtime.meta


@pytest.mark.asyncio
async def test_journal_directory_sync_error_keeps_reserved_request_unknown_without_effect(
    provider: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = provider.module
    monkeypatch.setattr(
        module,
        "_sync_directory",
        lambda path: (_ for _ in ()).throw(OSError("directory sync failed")),
    )
    request_id = "req-dir-sync-unavailable"
    outcome = (await _post(provider, _request(request_id))).json()
    assert outcome["status"] == "error" and "provider_receipt" not in outcome
    assert provider.browser.created == []
    assert module.RequestJournal(_binding(request_id)).read() == "unknown"
