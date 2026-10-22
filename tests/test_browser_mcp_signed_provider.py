"""The actual browser MCP HTTP producer, with fake Playwright only.

All requests use FastAPI's in-memory ASGI transport. No Playwright browser,
application database, external HTTP target, or model provider is started.
"""

import asyncio
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ai_osop.mcp.receipt_attestation import provider_receipt_is_signed

SID = "eng-provider-fixture"
OTHER = "eng-other-fixture"
USER = "user-a"
WORKFLOW = "wf-1"
TASK = "task-provider-har"
TOKEN = "test-only-secret-provider-bearer"
IMAGE_SHA = "a" * 64


class FakeTrace:
    async def start(self, **_kwargs):
        return None

    async def stop(self, *, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_bytes(b"trace")


class FakePage:
    def __init__(self):
        self.url = ""
        self.goto = AsyncMock(side_effect=self._goto)
        self.wait_for_load_state = AsyncMock()
        self.click = AsyncMock()
        self.fill = AsyncMock()
        self.evaluate = AsyncMock(return_value={"token": "SHOULD_NOT_ESCAPE"})

    async def _goto(self, url, **_kwargs):
        self.url = url
        # Playwright's real response carries a final Request and bounded
        # redirect ancestry. Model the genuine no-redirect response contract.
        return SimpleNamespace(
            status=200,
            request=SimpleNamespace(url=url, redirected_from=None),
        )


class FakeContext:
    def __init__(self, *, record_har_path=None, **_kwargs):
        # New governed navigation with evidence_mode='none' deliberately
        # creates NO HAR destination. Model real Playwright's optional HAR,
        # rather than making production create unreviewed capture bytes.
        self.path = Path(record_har_path) if record_har_path else None
        self.tracing = FakeTrace()
        self.page = FakePage()
        self.new_page = AsyncMock(return_value=self.page)
        self.route = AsyncMock()
        self.close = AsyncMock(side_effect=self._close)
        self.cookies = AsyncMock(return_value=[])

    async def _close(self):
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_bytes(
            json.dumps(
                {
                    "log": {
                        "entries": [
                            {
                                "request": {
                                    "url": "https://example.test/api/profile",
                                    "method": "GET",
                                    "headers": [],
                                },
                                "response": {"status": 200, "content": {"size": 0}},
                            },
                        ]
                    }
                },
                separators=(",", ":"),
            ).encode()
        )


class FakeBrowser:
    def __init__(self):
        self.created = []

    async def new_context(self, **kwargs):
        ctx = FakeContext(**kwargs)
        self.created.append(ctx)
        return ctx


@pytest.fixture
def provider(tmp_path, monkeypatch):
    path = Path(__file__).resolve().parents[1] / "mcp-servers" / "python" / "browser_mcp.py"
    spec = importlib.util.spec_from_file_location("browser_mcp_signed_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    keys = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    raw_public = keys.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    monkeypatch.setenv(
        "OSOP_BROWSER_MCP_RECEIPT_PRIVATE_KEY_B64",
        base64.b64encode(bytes(range(32))).decode("ascii"),
    )
    monkeypatch.setenv("OSOP_BROWSER_MCP_RECEIPT_KID", "browser-test-key")
    monkeypatch.setenv(
        "OSOP_MCP_RECEIPT_TRUSTED_KEYS_JSON",
        json.dumps({"browser-mcp": {"browser-test-key": base64.b64encode(raw_public).decode()}}),
    )
    monkeypatch.setenv("OSOP_BROWSER_MCP_BEARER_TOKEN", TOKEN)
    journal = tmp_path / "journal"
    journal.mkdir()
    monkeypatch.setenv("OSOP_BROWSER_MCP_JOURNAL_ROOT", str(journal))
    root = tmp_path / "signed-shared"
    for sid in (SID, OTHER):
        tenant = root / sid
        tenant.mkdir(parents=True)
    descriptor = {
        "engagement_id": SID,
        "mount_id": "browser-volume",
        "container_image_sha256": IMAGE_SHA,
    }
    data = json.dumps(descriptor, separators=(",", ":")).encode()
    (root / SID / ".osop-har-mount.json").write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    monkeypatch.setenv("OSOP_AUTHENTICATED_HAR_ROOT", str(root))
    monkeypatch.setenv("OSOP_AUTHENTICATED_HAR_MOUNT_DIGESTS", json.dumps({SID: digest}))
    monkeypatch.setenv("OSOP_EVIDENCE_ROOT", str(tmp_path / "manual-evidence"))
    # Deliberately fake historical Playwright provider fixture. Signed
    # production and unset/staging modes require independent central source;
    # the legacy signed fake-capture contract is allowed only in explicit test.
    monkeypatch.setenv("OSOP_ENVIRONMENT", "test")
    module.EVIDENCE_ROOT = str(tmp_path / "manual-evidence")
    fake_browser = FakeBrowser()
    module.manager = module.BrowserManager()
    module.manager.browser = fake_browser
    module.manager._started = True
    return SimpleNamespace(
        module=module,
        browser=fake_browser,
        digest=digest,
        root=root,
        journal=journal,
    )


def _binding(request_id, *, engagement=SID, task=TASK):
    return {
        "request_id": request_id,
        "engagement_id": engagement,
        "task_id": task,
        "server_id": "browser-mcp",
    }


def _request(request_id, action="navigate", *, binding=True, engagement=SID, task=TASK, **extra):
    return {
        "tool_name": "execute",
        "request_id": request_id,
        "session_id": engagement,
        "parameters": {
            "url": "https://example.test/",
            "action": action,
            "user_label": USER,
            "engagement_id": engagement,
            "workflow_id": WORKFLOW,
            **extra,
        },
        **(
            {"execution_binding": _binding(request_id, engagement=engagement, task=task)}
            if binding
            else {}
        ),
    }


async def _post(provider, payload, *, url="/mcp/execute", bearer=True):
    transport = httpx.ASGITransport(app=provider.module.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://localhost") as client:
        return await client.post(
            url,
            json=payload,
            headers={"Authorization": f"Bearer {TOKEN}"} if bearer else {},
        )


async def _health(provider):
    transport = httpx.ASGITransport(app=provider.module.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://localhost") as client:
        return await client.get("/health")


@pytest.mark.asyncio
async def test_declared_capabilities_require_verified_signer_and_bearer(provider, monkeypatch):
    good = await _post(provider, {"session_id": SID}, url="/mcp/initialize")
    assert good.status_code == 200
    assert {"mcp_bound_receipts_v1", "mcp_request_status_v1"} <= set(good.json()["capabilities"])
    monkeypatch.delenv("OSOP_BROWSER_MCP_RECEIPT_PRIVATE_KEY_B64")
    untrusted = await _post(provider, {"session_id": SID}, url="/mcp/initialize")
    assert "mcp_bound_receipts_v1" not in untrusted.json()["capabilities"]
    monkeypatch.setenv("OSOP_ENVIRONMENT", "production")
    assert (await _post(provider, {"session_id": SID}, url="/mcp/initialize")).status_code == 503
    assert (
        await _post(provider, {"session_id": SID}, url="/mcp/initialize", bearer=False)
    ).status_code == 401


@pytest.mark.asyncio
async def test_production_bootstrap_advertises_bound_capabilities_without_fake_tenant_mount(
    provider,
    monkeypatch,
):
    monkeypatch.setenv("OSOP_ENVIRONMENT", "production")
    bootstrap = await _post(provider, {"session_id": "api-bootstrap"}, url="/mcp/initialize")
    # A provider signer and tenant mount cannot independently grant central
    # source authority. No enrolled central HTTPS signer => no production boot.
    assert bootstrap.status_code == 503
    assert (
        await _post(
            provider,
            {"session_id": OTHER},
            url="/mcp/initialize",
        )
    ).status_code == 503
    assert (
        await _post(
            provider,
            {"session_id": ""},
            url="/mcp/initialize",
        )
    ).status_code == 503
    assert (
        await _post(
            provider,
            _request("req-unpinned-tenant", engagement=OTHER),
        )
    ).json()["status"] == "error"
    assert not provider.browser.created


@pytest.mark.asyncio
async def test_production_health_refuses_missing_signer_bearer_or_durable_journal(
    provider,
    monkeypatch,
):
    monkeypatch.setenv("OSOP_ENVIRONMENT", "production")
    initial = await _health(provider)
    assert initial.status_code == 503
    assert initial.json()["status"] == "unhealthy"
    assert initial.json()["signed_provider_ready"] is False
    signer = os.environ["OSOP_BROWSER_MCP_RECEIPT_PRIVATE_KEY_B64"]
    token = os.environ["OSOP_BROWSER_MCP_BEARER_TOKEN"]
    journal = os.environ["OSOP_BROWSER_MCP_JOURNAL_ROOT"]
    for variable in (
        "OSOP_BROWSER_MCP_RECEIPT_PRIVATE_KEY_B64",
        "OSOP_BROWSER_MCP_BEARER_TOKEN",
        "OSOP_BROWSER_MCP_JOURNAL_ROOT",
    ):
        monkeypatch.delenv(variable)
        unhealthy = await _health(provider)
        assert unhealthy.status_code == 503
        assert unhealthy.json()["status"] == "unhealthy"
        assert unhealthy.json()["signed_provider_ready"] is False
        assert "secret" not in str(unhealthy.json()).lower()
        monkeypatch.setenv(
            variable,
            {
                "OSOP_BROWSER_MCP_RECEIPT_PRIVATE_KEY_B64": signer,
                "OSOP_BROWSER_MCP_BEARER_TOKEN": token,
                "OSOP_BROWSER_MCP_JOURNAL_ROOT": journal,
            }[variable],
        )
    assert (await _health(provider)).status_code == 503


@pytest.mark.asyncio
async def test_signed_navigate_emits_original_bound_ed25519_terminal_receipt(provider):
    request_id = "req-test-nav-1"
    response = await _post(provider, _request(request_id))
    assert response.status_code == 200
    result = response.json()
    assert result["status"] == "success"
    assert result["result"]["status_code"] == 200
    assert result["result"]["current_url"] == "https://example.test/"
    proof = result["provider_receipt"]
    assert proof["request_id"] == request_id
    assert proof["status"] == "succeeded" and proof["verified"] is True
    assert provider_receipt_is_signed(proof, "browser-mcp", request_id, SID, TASK)
    assert not provider_receipt_is_signed(proof, "browser-mcp", request_id, OTHER, TASK)
    assert len(provider.browser.created) == 1


def _imported_state(token="secret-cookie-a"):
    return {
        "cookies": [
            {
                "name": "sid",
                "value": token,
                "domain": "example.test",
                "path": "/",
                "httpOnly": True,
                "secure": True,
            }
        ],
        "origins": [],
    }


@pytest.mark.asyncio
async def test_signed_context_pins_canonical_storage_digest_across_navigation(provider):
    initial = _imported_state()
    first = (
        await _post(
            provider,
            _request(
                "req-storage-new",
                storage_state=initial,
            ),
        )
    ).json()
    assert first["status"] == "success"
    ctx = provider.browser.created[0]
    key = (SID, USER)
    assert len(provider.module.manager.meta[key]["storage_state_sha256"]) == 64
    assert "secret-cookie-a" not in repr(provider.module.manager.meta[key])
    # Identical identity content with differently ordered JSON keys must pin
    # to the same canonical digest, not fail on textual serialization order.
    reordered = {
        "origins": [],
        "cookies": [
            dict(reversed(list(initial["cookies"][0].items()))),
        ],
    }
    second = (
        await _post(
            provider,
            _request(
                "req-storage-same",
                storage_state=reordered,
            ),
        )
    ).json()
    assert second["status"] == "success"
    assert ctx.page.goto.await_count == 2
    assert len(provider.browser.created) == 1


@pytest.mark.asyncio
async def test_signed_navigation_rotated_or_missing_credentials_fail_closed(provider):
    start = (
        await _post(
            provider,
            _request(
                "req-storage-before-rotation",
                storage_state=_imported_state(),
            ),
        )
    ).json()
    assert start["status"] == "success"
    page = provider.browser.created[0].page
    changed = (
        await _post(
            provider,
            _request(
                "req-storage-after-rotation",
                storage_state=_imported_state("rotated"),
            ),
        )
    ).json()
    assert changed["status"] == "error" and "provider_receipt" not in changed
    missing = (await _post(provider, _request("req-storage-missing"))).json()
    assert missing["status"] == "error" and "provider_receipt" not in missing
    assert page.goto.await_count == 1
    assert len(provider.browser.created) == 1
    assert "secret-cookie-a" not in json.dumps(changed)
    assert "rotated" not in json.dumps(missing)
    for request_id in ("req-storage-after-rotation", "req-storage-missing"):
        result = (await _post(provider, _binding(request_id), url="/mcp/request/status")).json()
        assert result["result"]["status"] == "unknown"
        assert "attestation" not in result["result"]


@pytest.mark.asyncio
async def test_signed_flush_without_fresh_storage_state_keeps_compatible_har(provider):
    created = (
        await _post(
            provider,
            _request(
                "req-storage-har-nav",
                storage_state=_imported_state(),
            ),
        )
    ).json()
    assert created["status"] == "success"
    flushed = (
        await _post(
            provider,
            _request(
                "req-storage-har-flush",
                "flush_har",
            ),
        )
    ).json()
    assert flushed["status"] == "success"
    path = provider.root / SID / flushed["result"]["path"]
    assert path.is_file()
    assert flushed["result"]["resource_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert provider_receipt_is_signed(
        flushed["provider_receipt"],
        "browser-mcp",
        "req-storage-har-flush",
        SID,
        TASK,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "invalid",
    [
        {"cookies": {}, "origins": []},
        {"cookies": [], "origins": [], "foreign": "credential"},
        {"cookies": [{"value": "a" * (128 * 1024)}], "origins": []},
        {"cookies": [{"value": float("nan")}], "origins": []},
        {"cookies": [{}] * 257, "origins": []},
    ],
)
async def test_signed_new_context_denies_unbounded_or_noncanonical_storage(provider, invalid):
    response = (
        await _post(
            provider,
            _request(
                "req-invalid-storage",
                storage_state=invalid,
            ),
        )
    ).json()
    assert response["status"] == "error"
    assert "provider_receipt" not in response
    assert len(provider.browser.created) == 0


@pytest.mark.asyncio
async def test_direct_concurrent_get_page_creates_exactly_one_page(provider):
    async def slow_create(**kwargs):
        await asyncio.sleep(0)
        ctx = FakeContext(**kwargs)

        async def slow_page():
            await asyncio.sleep(0.01)
            return ctx.page

        ctx.new_page = AsyncMock(side_effect=slow_page)
        provider.browser.created.append(ctx)
        return ctx

    provider.browser.new_context = slow_create
    calls = [
        provider.module.manager.get_page(
            USER,
            engagement_id=SID,
            storage_state=_imported_state(),
            signed=True,
            require_fresh_state=True,
        )
        for _ in range(8)
    ]
    pages = await asyncio.gather(*calls)
    assert all(page is pages[0] for page in pages)
    assert len(provider.browser.created) == 1
    assert provider.browser.created[0].new_page.await_count == 1


@pytest.mark.asyncio
async def test_same_identity_http_actions_serialize_complete_page_lifecycle(provider):
    entered = asyncio.Event()
    release = asyncio.Event()
    active = 0
    simultaneous = []

    async def slow_create(**kwargs):
        ctx = FakeContext(**kwargs)

        async def navigate(url, **_kwargs):
            nonlocal active
            active += 1
            simultaneous.append(active)
            if url.endswith("/first"):
                entered.set()
                await release.wait()
            await asyncio.sleep(0)
            ctx.page.url = url
            active -= 1
            return SimpleNamespace(status=200)

        ctx.page.goto = AsyncMock(side_effect=navigate)
        provider.browser.created.append(ctx)
        return ctx

    provider.browser.new_context = slow_create
    a = asyncio.create_task(
        _post(
            provider,
            _request(
                "req-action-first",
                url="https://example.test/first",
                storage_state=_imported_state(),
            ),
        )
    )
    await asyncio.wait_for(entered.wait(), timeout=3)
    b = asyncio.create_task(
        _post(
            provider,
            _request(
                "req-action-second",
                url="https://example.test/second",
                storage_state=_imported_state(),
            ),
        )
    )
    try:
        await asyncio.sleep(0.05)
        assert provider.browser.created[0].page.goto.await_count == 1
    finally:
        release.set()
    first, second = await asyncio.gather(a, b)
    assert first.json()["status"] == second.json()["status"] == "success"
    assert first.json()["result"]["current_url"].endswith("/first")
    assert second.json()["result"]["current_url"].endswith("/second")
    assert simultaneous == [1, 1]
    assert provider.browser.created[0].page.goto.await_count == 2


@pytest.mark.asyncio
async def test_concurrent_credential_rotation_never_uses_old_context(provider):
    entered = asyncio.Event()
    release = asyncio.Event()

    async def fake_context(**kwargs):
        ctx = FakeContext(**kwargs)

        async def gated_navigate(url, **_kwargs):
            entered.set()
            await release.wait()
            ctx.page.url = url
            return SimpleNamespace(status=200)

        ctx.page.goto = AsyncMock(side_effect=gated_navigate)
        provider.browser.created.append(ctx)
        return ctx

    provider.browser.new_context = fake_context
    first = asyncio.create_task(
        _post(
            provider,
            _request(
                "req-rotation-racing-first",
                storage_state=_imported_state("before"),
            ),
        )
    )
    await asyncio.wait_for(entered.wait(), timeout=3)
    second = asyncio.create_task(
        _post(
            provider,
            _request(
                "req-rotation-racing-second",
                storage_state=_imported_state("after"),
            ),
        )
    )
    try:
        await asyncio.sleep(0.05)
        assert provider.browser.created[0].page.goto.await_count == 1
    finally:
        release.set()
    a, b = await asyncio.gather(first, second)
    assert a.json()["status"] == "success"
    assert b.json()["status"] == "error"
    assert "provider_receipt" not in b.json()
    assert len(provider.browser.created) == 1
    assert provider.browser.created[0].page.goto.await_count == 1


@pytest.mark.asyncio
async def test_flush_waits_for_same_identity_in_flight_navigation(provider):
    entered = asyncio.Event()
    release = asyncio.Event()

    async def slow_create(**kwargs):
        ctx = FakeContext(**kwargs)

        async def navigate(url, **_kwargs):
            entered.set()
            await release.wait()
            ctx.page.url = url
            return SimpleNamespace(status=200)

        ctx.page.goto = AsyncMock(side_effect=navigate)
        provider.browser.created.append(ctx)
        return ctx

    provider.browser.new_context = slow_create
    nav_task = asyncio.create_task(
        _post(
            provider,
            _request(
                "req-flush-after-nav",
                storage_state=_imported_state(),
            ),
        )
    )
    await asyncio.wait_for(entered.wait(), timeout=3)
    flush_task = asyncio.create_task(
        _post(
            provider,
            _request("req-flush-serialized", "flush_har"),
        )
    )
    try:
        await asyncio.sleep(0.05)
        assert provider.browser.created[0].close.await_count == 0
        assert (SID, USER) in provider.module.manager.contexts
    finally:
        release.set()
    navigation, flush = await asyncio.gather(nav_task, flush_task)
    assert navigation.json()["status"] == "success"
    assert flush.json()["status"] == "success"
    assert provider.browser.created[0].close.await_count == 1


@pytest.mark.asyncio
async def test_signed_navigation_without_http_status_is_unknown_not_attested(provider):
    async def missing_http_status(**kwargs):
        ctx = FakeContext(**kwargs)
        ctx.page.goto = AsyncMock(return_value=None)
        provider.browser.created.append(ctx)
        return ctx

    provider.browser.new_context = missing_http_status
    result = (await _post(provider, _request("req-status-missing"))).json()
    assert result["status"] == "error"
    assert "provider_receipt" not in result
    persisted = (
        await _post(
            provider,
            _binding("req-status-missing"),
            url="/mcp/request/status",
        )
    ).json()
    assert persisted["result"]["status"] == "unknown"
    assert "attestation" not in persisted["result"]


@pytest.mark.asyncio
async def test_live_signed_har_relative_path_matches_real_flushed_bytes_and_consumer(provider):
    assert (await _post(provider, _request("req-nav-for-capture"))).json()["status"] == "success"
    flush_id = "req-flush-capture"
    result = (await _post(provider, _request(flush_id, "flush_har"))).json()
    assert result["status"] == "success"
    evidence = result["result"]
    assert evidence["path"].startswith("captures/") and evidence["path"].endswith(".har")
    assert evidence["engagement_id"] == SID
    assert evidence["user_label"] == USER
    assert evidence["workflow_id"] == WORKFLOW
    assert evidence["capture_task_id"] == TASK
    assert evidence["mount_sha256"] == provider.digest
    assert evidence["container_image_sha256"] == IMAGE_SHA
    on_disk = provider.root / SID / evidence["path"]
    assert on_disk.is_file()
    assert evidence["resource_sha256"] == hashlib.sha256(on_disk.read_bytes()).hexdigest()
    assert provider_receipt_is_signed(
        result["provider_receipt"],
        "browser-mcp",
        flush_id,
        SID,
        TASK,
    )
    # Real downstream snapshot parser, not a mocked digest verifier.
    from ai_osop.memory.authenticated_resource_paths import snapshot_local_har

    doc, sha = snapshot_local_har(SID, evidence["path"], signed=True)
    assert len(doc["log"]["entries"]) == 1 and sha == evidence["resource_sha256"]
    assert not (provider.root / OTHER / evidence["path"]).exists()


@pytest.mark.asyncio
async def test_same_label_in_distinct_engagements_never_reuses_page_or_cookie_context(provider):
    a = await provider.module.manager.get_page(USER, engagement_id=SID)
    b = await provider.module.manager.get_page(USER, engagement_id=OTHER)
    assert a is not b and len(provider.browser.created) == 2
    assert provider.browser.created[0].path != provider.browser.created[1].path
    assert (SID, USER) in provider.module.manager.contexts
    assert (OTHER, USER) in provider.module.manager.contexts


@pytest.mark.asyncio
async def test_signed_context_cannot_be_adopted_by_manual_request_or_vice_versa(provider):
    first = (await _post(provider, _request("req-signed-isolation"))).json()
    assert first["status"] == "success"
    refused = (await _post(provider, _request("req-manual-adopt", binding=False))).json()
    assert refused["status"] == "error"
    # The dangerous path is flush: it must not close or return an absolute
    # signed HAR path to an unauthenticated/manual caller.
    flush = (
        await _post(
            provider,
            _request(
                "req-manual-steal-har",
                "flush_har",
                binding=False,
            ),
        )
    ).json()
    assert flush["status"] == "error"
    assert "result" not in flush
    assert (SID, USER) in provider.module.manager.contexts
    assert provider.browser.created[0].close.await_count == 0
    assert len(provider.browser.created) == 1
    assert (
        await _post(provider, _request("req-manual-other", binding=False, engagement=OTHER))
    ).json()["status"] == "success"
    signed_other = (await _post(provider, _request("req-signed-adopt", engagement=OTHER))).json()
    assert signed_other["status"] == "error"
    assert len(provider.browser.created) == 2


@pytest.mark.asyncio
async def test_reject_bad_binding_before_any_browser_effect_or_journal_reservation(provider):
    bad = _request("req-spoof")
    bad["execution_binding"]["task_id"] = "task-foreign"
    bad["execution_binding"]["server_id"] = "other-server"
    result = (await _post(provider, bad)).json()
    assert result["status"] == "error"
    assert not provider.browser.created
    assert list(provider.journal.iterdir()) == []


@pytest.mark.asyncio
async def test_signed_capture_state_redacts_cookie_and_eval_cannot_run(provider):
    initial = (await _post(provider, _request("req-signed-state-init"))).json()
    assert initial["status"] == "success"
    state = (await _post(provider, _request("req-signed-state", "capture_state"))).json()
    assert state["status"] == "success"
    assert state["result"]["state"] == "redacted"
    assert "SHOULD_NOT_ESCAPE" not in json.dumps(state)
    script = (
        await _post(provider, _request("req-signed-eval", "eval", expression="document.cookie"))
    ).json()
    assert script["status"] == "error"
    assert "SHOULD_NOT_ESCAPE" not in json.dumps(script)
    assert provider.browser.created[0].page.evaluate.await_count == 0


@pytest.mark.asyncio
async def test_signed_without_bearer_or_signer_fails_before_navigation(provider, monkeypatch):
    request = _request("req-auth-fail")
    assert (await _post(provider, request, bearer=False)).status_code == 401
    assert not provider.browser.created
    monkeypatch.delenv("OSOP_BROWSER_MCP_RECEIPT_PRIVATE_KEY_B64")
    result = (await _post(provider, request)).json()
    assert result["status"] == "error"
    assert not provider.browser.created
    assert list(provider.journal.iterdir()) == []


@pytest.mark.asyncio
async def test_non_enrolled_private_signer_is_not_trusted_before_any_target_effect(
    provider, monkeypatch
):
    other_key = bytes(reversed(range(32)))
    monkeypatch.setenv(
        "OSOP_BROWSER_MCP_RECEIPT_PRIVATE_KEY_B64",
        base64.b64encode(other_key).decode(),
    )
    result = (await _post(provider, _request("req-foreign-key"))).json()
    assert result["status"] == "error"
    assert not provider.browser.created
    assert list(provider.journal.iterdir()) == []


@pytest.mark.asyncio
async def test_production_requires_bearer_and_validated_binding(provider, monkeypatch):
    monkeypatch.setenv("OSOP_ENVIRONMENT", "production")
    # A deployed operator must supply independent tenant destination pins.
    # This test signs a fake example.test response, never contacts the host.
    monkeypatch.setenv(
        "OSOP_BROWSER_MCP_SIGNED_ORIGINS_JSON",
        json.dumps({SID: ["https://example.test"]}),
    )
    assert (await _post(provider, _request("req-unbound", binding=False))).status_code == 403
    assert (
        await _post(provider, _request("req-unbound", binding=False), bearer=False)
    ).status_code == 401
    assert not provider.browser.created
    signed = (await _post(provider, _request("req-prod-signed"))).json()
    # Caller-authenticated Task binding + origin pin are not central one-shot
    # authorization, and therefore cannot create a signed success receipt.
    assert signed["status"] == "error"
    assert "provider_receipt" not in signed
    assert not provider.browser.created


@pytest.mark.asyncio
async def test_durable_reservation_duplicate_never_replays_and_status_can_recover(provider):
    request = _request("req-durable")
    first = (await _post(provider, request)).json()
    assert first["status"] == "success"
    assert len(provider.browser.created) == 1
    provider.module.manager = provider.module.BrowserManager()
    provider.module.manager.browser = provider.browser
    replay = (await _post(provider, request)).json()
    assert replay["status"] == "duplicate_request"
    assert len(provider.browser.created) == 1
    observed = (
        await _post(
            provider,
            _binding("req-durable"),
            url="/mcp/request/status",
        )
    ).json()
    assert observed["status"] == "success"
    receipt = observed["result"]
    assert provider_receipt_is_signed(receipt, "browser-mcp", "req-durable", SID, TASK)
    wrong = (
        await _post(
            provider,
            _binding("req-durable", task="task-foreign"),
            url="/mcp/request/status",
        )
    ).json()
    assert wrong["result"]["status"] == "unknown"


@pytest.mark.asyncio
async def test_status_after_signer_trust_revocation_is_unknown(provider, monkeypatch):
    completed = (await _post(provider, _request("req-revoked-status"))).json()
    assert completed["status"] == "success"
    monkeypatch.setenv("OSOP_MCP_RECEIPT_TRUSTED_KEYS_JSON", "{}")
    response = (
        await _post(
            provider,
            _binding("req-revoked-status"),
            url="/mcp/request/status",
        )
    ).json()
    assert response["result"]["status"] == "unknown"
    assert "attestation" not in response["result"]


@pytest.mark.asyncio
async def test_reserved_unknown_never_replays_and_cannot_be_promoted_to_finished(provider):
    binding = _binding("req-unknown")
    journal = provider.module.RequestJournal(binding)
    assert journal.reserve()
    result = (await _post(provider, _request("req-unknown"))).json()
    assert result["status"] == "duplicate_request"
    assert not provider.browser.created
    status = (await _post(provider, binding, url="/mcp/request/status")).json()
    assert status["result"]["status"] == "unknown"
    assert "attestation" not in status["result"]


@pytest.mark.asyncio
async def test_corrupt_unknown_journal_cannot_be_upgraded_to_signed_success(provider):
    journal = provider.module.RequestJournal(_binding("req-corrupt"))
    assert journal.reserve()
    journal.path.write_bytes(json.dumps({"binding": {"untrusted": "foo"}}).encode())
    with pytest.raises(ValueError, match="terminal state unavailable"):
        journal.finish("succeeded")
    result = (await _post(provider, _request("req-corrupt"))).json()
    assert result["status"] == "duplicate_request"
    status = (await _post(provider, _binding("req-corrupt"), url="/mcp/request/status")).json()
    assert status["result"]["status"] == "unknown"
    assert "attestation" not in status["result"]


@pytest.mark.asyncio
async def test_missing_local_har_after_context_close_never_returns_producer_proof(provider):
    assert (await _post(provider, _request("req-create-for-missing-har"))).json()[
        "status"
    ] == "success"
    context = provider.browser.created[0]
    context.close = AsyncMock(return_value=None)  # no actual HAR written
    response = (await _post(provider, _request("req-missing-flush", "flush_har"))).json()
    assert response["status"] == "error"
    assert "provider_receipt" not in response
    status = (
        await _post(provider, _binding("req-missing-flush"), url="/mcp/request/status")
    ).json()
    assert status["result"]["status"] == "unknown"


@pytest.mark.asyncio
async def test_bad_mount_pin_blocks_new_signed_context_and_leaves_unknown_only(
    provider, monkeypatch
):
    monkeypatch.setenv("OSOP_AUTHENTICATED_HAR_MOUNT_DIGESTS", json.dumps({SID: "0" * 64}))
    outcome = (await _post(provider, _request("req-bad-pin"))).json()
    assert outcome["status"] == "error"
    assert not provider.browser.created
    assert list(provider.journal.iterdir()) == []


@pytest.mark.asyncio
async def test_legacy_manual_maintains_absolute_evidence_path_without_signed_receipt(provider):
    response = (await _post(provider, _request("req-manual", binding=False))).json()
    assert response["status"] == "success"
    assert "provider_receipt" not in response
    har = (await _post(provider, _request("req-manual-flush", "flush_har", binding=False))).json()
    assert har["status"] == "success"
    assert Path(har["result"]["path"]).is_absolute()
    assert har["result"]["exists"] is True
