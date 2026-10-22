"""Opt-in-safe offline real local Chromium -> native signed Browser MCP proof.

All browser page traffic is restricted to one owned 127.0.0.1 listener by
Playwright route interception plus an independent local deny HTTP proxy. This
is real Playwright execution, NOT independently signed target/Flow authority.
No downloads, external sites, app databases, scanners or external providers.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from ai_osop.mcp.receipt_attestation import provider_receipt_is_signed
from tests.qualification.native_browser_local_helper_20261020 import (
    ENGAGEMENT,
    FOREIGN,
    LABEL,
    TASK,
    native_browser_local,
    real_chromium_executable,
)


def _binding(request_id: str, engagement: str = ENGAGEMENT) -> dict[str, str]:
    return {
        "request_id": request_id,
        "engagement_id": engagement,
        "task_id": TASK,
        "server_id": "browser-mcp",
    }


def _execute(
    request_id: str,
    action: str,
    *,
    url: str = "",
    engagement: str = ENGAGEMENT,
) -> dict[str, object]:
    return {
        "tool_name": "execute",
        "request_id": request_id,
        "session_id": engagement,
        "execution_binding": _binding(request_id, engagement),
        "parameters": {
            "action": action,
            "url": url,
            "user_label": LABEL,
            "engagement_id": engagement,
            "workflow_id": "wf-native-local",
            "step_id": "step-native-local",
        },
    }


def _verify_ack(response: dict, request_id: str) -> None:
    assert response["status"] == "success", response
    assert provider_receipt_is_signed(
        response["provider_receipt"],
        "browser-mcp",
        request_id,
        ENGAGEMENT,
        TASK,
    )
    assert not provider_receipt_is_signed(
        response["provider_receipt"],
        "browser-mcp",
        request_id,
        FOREIGN,
        TASK,
    )


@pytest.mark.asyncio
async def test_offline_browser_cache_probe() -> None:
    path, status = await real_chromium_executable()
    if path is None:
        pytest.skip(status)
    assert path.is_file()
    assert "chromium" in path.name.lower() or "chrome" in path.name.lower()
    assert status == "cached_offline_chromium_present"


@pytest.mark.asyncio
async def test_native_browser_production_without_playwright_cannot_claim_ready(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Real ASGI contract remains useful when cached Chromium is unavailable."""
    import importlib.util
    import sys

    path = Path(__file__).resolve().parents[2] / "mcp-servers" / "python" / "browser_mcp.py"
    spec = importlib.util.spec_from_file_location("_native_browser_without_process_20261020", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    monkeypatch.setenv("OSOP_ENVIRONMENT", "production")
    monkeypatch.delenv("OSOP_BROWSER_MCP_BEARER_TOKEN", raising=False)
    monkeypatch.delenv("OSOP_BROWSER_MCP_RECEIPT_PRIVATE_KEY_B64", raising=False)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=module.app),
        base_url="http://local-only.invalid",
        timeout=3.0,
    ) as client:
        status = await client.get("/health")
        discovery = await client.post("/mcp/initialize", json={"session_id": "api-bootstrap"})
        execution = await client.post("/mcp/execute", json=_execute("req-no-runtime", "navigate"))
    assert status.status_code == 503
    assert status.json()["playwright_started"] is False
    assert discovery.status_code == 401
    assert execution.status_code == 401
    assert module.manager.contexts == {} and module.manager.pages == {}


@pytest.mark.asyncio
async def test_actual_offline_chromium_signed_loopback_transport_and_journal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with native_browser_local(tmp_path, monkeypatch, legacy_fixture=True) as native:
        async with native.client() as client:
            health = await client.get("/health")
            assert health.status_code == 200
            assert health.json()["playwright_started"] is True
            assert health.json()["signed_provider_ready"] is True

            bootstrap = await client.post(
                "/mcp/initialize",
                json={"session_id": "api-bootstrap"},
                headers=native.headers(),
            )
            assert bootstrap.status_code == 200
            assert {"mcp_bound_receipts_v1", "mcp_request_status_v1"}.issubset(
                set(bootstrap.json()["capabilities"])
            )
            tenant_init = await client.post(
                "/mcp/initialize",
                json={"session_id": ENGAGEMENT},
                headers=native.headers(),
            )
            assert tenant_init.status_code == 200
            foreign_init = await client.post(
                "/mcp/initialize",
                json={"session_id": FOREIGN},
                headers=native.headers(),
            )
            # This helper is explicitly a legacy transport fixture; metadata
            # initialization is not source authorization or tenant execution.
            assert foreign_init.status_code == 200

            unauthorized = await client.post(
                "/mcp/execute",
                json=_execute("req-unauthorized", "navigate", url=native.base_url),
            )
            assert unauthorized.status_code == 401
            mismatch = _execute("req-forged-binding", "navigate", url=native.base_url)
            mismatch["execution_binding"]["server_id"] = "foreign-browser-mcp"
            denied = await client.post("/mcp/execute", json=mismatch, headers=native.headers())
            assert denied.json()["status"] == "error"
            assert "provider_receipt" not in denied.json()
            assert not native.page_hits

            forged_tenant = await client.post(
                "/mcp/execute",
                json=_execute(
                    "req-foreign-tenant",
                    "navigate",
                    url=native.base_url,
                    engagement=FOREIGN,
                ),
                headers=native.headers(),
            )
            assert forged_tenant.json()["status"] == "error"
            assert "provider_receipt" not in forged_tenant.json()
            assert not native.page_hits

            navigation_id = "req-native-real-nav"
            navigate = await client.post(
                "/mcp/execute",
                json=_execute(navigation_id, "navigate", url=native.base_url + "/"),
                headers=native.headers(),
            )
            assert navigate.status_code == 200
            original = navigate.json()
            _verify_ack(original, navigation_id)
            assert original["result"]["status_code"] == 200
            assert original["result"]["current_url"].rstrip("/") == native.base_url
            assert native.page_hits.count("/") == 1
            assert not native.blocked

            # Exact request replay cannot navigate a second time, even after
            # its durable status has been signed successfully.
            replay = await client.post(
                "/mcp/execute",
                json=_execute(navigation_id, "navigate", url=native.base_url + "/"),
                headers=native.headers(),
            )
            assert replay.json()["status"] == "duplicate_request"
            assert native.page_hits.count("/") == 1
            assert native.native.RequestJournal(_binding(navigation_id)).read() == "succeeded"
            status = await client.post(
                "/mcp/request/status",
                json=_binding(navigation_id),
                headers=native.headers(),
            )
            assert status.status_code == 200
            _verify_ack(
                {"status": "success", "provider_receipt": status.json()["result"]}, navigation_id
            )

            for action, extension in (("screenshot", "png"), ("dom_snapshot", "html")):
                request_id = f"req-native-real-{action}"
                captured = await client.post(
                    "/mcp/execute",
                    json=_execute(request_id, action),
                    headers=native.headers(),
                )
                assert captured.status_code == 200
                result = captured.json()
                _verify_ack(result, request_id)
                details = result["result"]
                assert details["path"].startswith("captures/") and details["path"].endswith(
                    extension
                )
                actual = (native.tenant / details["path"]).read_bytes()
                assert actual and hashlib.sha256(actual).hexdigest() == details["resource_sha256"]
                assert details["size_bytes"] == len(actual)
                assert (
                    details["mount_sha256"]
                    == json.loads(__import__("os").environ["OSOP_AUTHENTICATED_HAR_MOUNT_DIGESTS"])[
                        ENGAGEMENT
                    ]
                )
                assert details["capture_task_id"] == TASK
                assert "LOCAL_ONLY_BROWSER_PROOF" not in captured.text
                if action == "screenshot":
                    assert actual.startswith(b"\x89PNG\r\n\x1a\n")
                else:
                    assert b"LOCAL_ONLY_BROWSER_PROOF" in actual

            # A revoked mount prohibits reuse of cached signed identity and
            # leaves no misleading receipt. Restore only to flush local HAR.
            import os

            previous_pin = os.environ["OSOP_AUTHENTICATED_HAR_MOUNT_DIGESTS"]
            monkeypatch.setenv(
                "OSOP_AUTHENTICATED_HAR_MOUNT_DIGESTS",
                json.dumps({ENGAGEMENT: "0" * 64}),
            )
            pin_denied = await client.post(
                "/mcp/execute",
                json=_execute(
                    "req-native-real-stale",
                    "capture_state",
                ),
                headers=native.headers(),
            )
            assert pin_denied.json()["status"] == "error"
            assert "provider_receipt" not in pin_denied.json()
            monkeypatch.setenv("OSOP_AUTHENTICATED_HAR_MOUNT_DIGESTS", previous_pin)

            # Real Playwright context.close() writes a real HAR to the signed
            # tenant mount; native bytes and durable receipt must be valid.
            flush_id = "req-native-real-flush"
            flushed = await client.post(
                "/mcp/execute",
                json=_execute(flush_id, "flush_har"),
                headers=native.headers(),
            )
            assert flushed.status_code == 200
            final = flushed.json()
            _verify_ack(final, flush_id)
            entry = final["result"]
            har = (native.tenant / entry["path"]).read_bytes()
            assert hashlib.sha256(har).hexdigest() == entry["resource_sha256"]
            parsed = json.loads(har)
            assert isinstance(parsed["log"]["entries"], list)
            assert any(
                item["request"]["url"].startswith(native.base_url)
                for item in parsed["log"]["entries"]
            )
            assert "LOCAL_ONLY_BROWSER_PROOF" not in flushed.text

            # Real Chromium receives the controlled local 302. Playwright's
            # route guard or the independently owned 403-only loopback proxy
            # blocks the remote destination without reaching external network.
            # A blocked external redirect must leave an UNKNOWN journal,
            # never become a signed successful provider receipt.
            redirect_id = "req-native-real-redirect"
            escaped = await client.post(
                "/mcp/execute",
                json=_execute(
                    redirect_id,
                    "navigate",
                    url=native.base_url + "/redirect",
                ),
                headers=native.headers(),
            )
            assert native.page_hits.count("/redirect") == 1
            assert any(
                "browser-external-must-not-resolve.invalid" in uri
                for uri in (*native.blocked, *native.proxy_attempts)
            ), "browser redirect was not intercepted by the local transport guards"
            assert escaped.json()["status"] == "error"
            assert "provider_receipt" not in escaped.json()
            assert native.native.RequestJournal(_binding(redirect_id)).read() == "unknown"

            # This explicit legacy transport fixture does not exercise production
            # origin-policy revocation. The joined real-PG source test covers
            # current production authority; receipt signatures alone do not.

            # The original request cannot add a second origin through its
            # parameters, even with a syntactically correct Task binding.
            out_of_origin = await client.post(
                "/mcp/execute",
                json=_execute(
                    "req-native-forged-origin",
                    "navigate",
                    url="https://new-scope.invalid/",
                ),
                headers=native.headers(),
            )
            assert out_of_origin.json()["status"] == "error"
            assert "provider_receipt" not in out_of_origin.json()

            # With no terminal ACK, retrying that very request cannot contact
            # the page again or upgrade UNKNOWN to succeeded.
            replay_redirect = await client.post(
                "/mcp/execute",
                json=_execute(
                    redirect_id,
                    "navigate",
                    url=native.base_url + "/redirect",
                ),
                headers=native.headers(),
            )
            assert replay_redirect.json()["status"] == "duplicate_request"
            assert native.page_hits.count("/redirect") == 1
            assert native.native.RequestJournal(_binding(redirect_id)).read() == "unknown"

        # Every browser request either reached the owned loopback port or was
        # explicitly blocked before transport. The proxy never forwarded I/O.
        assert native.page_hits
        # Proxy requests, if any, were handled by the owned 403-only loopback
        # server. They do not represent externally delivered HTTP requests.
        assert all(
            url.startswith(native.base_url) or url in native.blocked for url in native.intercepted
        )


@pytest.mark.asyncio
async def test_native_signed_origin_policy_rejects_malformed_and_ambiguous_hostnames(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Destination authority originates from deployment configuration only."""
    async with native_browser_local(tmp_path, monkeypatch, legacy_fixture=True) as native:
        for forged in (
            "http://user@127.0.0.1:8080",
            "http://127.0.0.1:8080/extra",
            "http://127.0.0.1:8080?secret=x",
            "https://example.com.",
            "http://untrusted.example",
            "https://examp\\le.com",
            "https://example.com:99999",
        ):
            monkeypatch.setenv(
                "OSOP_BROWSER_MCP_SIGNED_ORIGINS_JSON",
                json.dumps({ENGAGEMENT: [forged]}),
            )
            with pytest.raises(ValueError):
                native.native._signed_allowed_origins(ENGAGEMENT)
        for invalid_json in ("", "{}", "[]", '{"eng-native-local-browser":[]}'):
            monkeypatch.setenv("OSOP_BROWSER_MCP_SIGNED_ORIGINS_JSON", invalid_json)
            with pytest.raises(ValueError):
                native.native._signed_allowed_origins(ENGAGEMENT)


@pytest.mark.asyncio
async def test_native_signed_navigation_rejects_http_302_without_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Adversarial provider response: 3xx cannot be promoted to terminal proof."""
    async with native_browser_local(tmp_path, monkeypatch, legacy_fixture=True) as native:
        # Keep a genuine signer, mount and local journal, but return a synthetic
        # Playwright response with HTTP 302 without contacting any page.
        request_id = "req-native-simulated-302"
        fake_page = SimpleNamespace(
            url=native.base_url,
            goto=AsyncMock(return_value=SimpleNamespace(status=302)),
            wait_for_load_state=AsyncMock(),
        )
        monkeypatch.setattr(native.native.manager, "get_page", AsyncMock(return_value=fake_page))
        async with native.client() as client:
            outcome = await client.post(
                "/mcp/execute",
                json=_execute(request_id, "navigate", url=native.base_url),
                headers=native.headers(),
            )
        assert outcome.json()["status"] == "error"
        assert "provider_receipt" not in outcome.json()
        assert fake_page.goto.await_count == 1
        assert not native.page_hits
        assert native.native.RequestJournal(_binding(request_id)).read() == "unknown"


@pytest.mark.asyncio
async def test_native_signed_navigation_rejects_200_after_foreign_redirect_hop(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Even a forged final HTTP200 on the allowed origin cannot launder a hop."""
    async with native_browser_local(tmp_path, monkeypatch, legacy_fixture=True) as native:
        initial = SimpleNamespace(url=native.base_url, redirected_from=None)
        foreign = SimpleNamespace(url="https://foreign-redirect.invalid/", redirected_from=initial)
        final = SimpleNamespace(url=native.base_url + "/", redirected_from=foreign)
        page = SimpleNamespace(
            url=native.base_url,
            goto=AsyncMock(return_value=SimpleNamespace(status=200, request=final)),
            wait_for_load_state=AsyncMock(),
        )
        monkeypatch.setattr(native.native.manager, "get_page", AsyncMock(return_value=page))
        # Exercise the production redirect validator directly. Legacy test
        # mode intentionally has no central source and cannot qualify an
        # independently signed action through the full provider handler.
        with pytest.raises(ValueError, match="redirect"):
            native.native._verified_navigation_chain(
                SimpleNamespace(status=200, request=final),
                native.base_url,
                frozenset({native.base_url}),
                native.base_url,
            )
        page.goto.assert_not_awaited()
        assert native.page_hits == []
