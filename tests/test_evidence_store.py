"""ReceiptStore tests. DB-backed tests skip when Postgres is unavailable;
pure-function tests (signing) always run."""

import pytest

pytestmark = pytest.mark.integration


@pytest.fixture
async def sa_engine():
    """Real SQLAlchemy AsyncEngine from SessionMemory (mirrors session_memory.py:321).

    Cleans the exploit_receipts table before yield so tests remain idempotent
    when Postgres is running (multiple runs reuse the same receipt ids)."""
    from ai_osop.memory.session_memory import SessionMemory

    sm = SessionMemory()
    try:
        await sm.connect()
    except Exception as e:
        pytest.skip(f"Postgres not available: {e}")
    try:
        from sqlalchemy import text

        async with sm._pg_engine.begin() as conn:
            await conn.execute(text("DELETE FROM exploit_receipts"))
    except Exception:
        # table may not exist yet on the very first run; tests create it
        pass
    yield sm._pg_engine
    await sm.close()


async def test_ensure_schema_creates_table(sa_engine):
    from sqlalchemy import text

    from ai_osop.evidence.migrations import ensure_schema

    await ensure_schema(sa_engine)
    async with sa_engine.connect() as conn:
        row = await conn.execute(text("SELECT to_regclass('public.exploit_receipts')"))
        assert row.scalar_one() == "exploit_receipts"


def test_signature_is_deterministic_and_key_dependent():
    from ai_osop.evidence.store import _sign_receipt_fields

    canonical = {"receipt_id": "rcpt-1", "engagement_id": "eng-1", "vuln_id": "v1"}
    sig1 = _sign_receipt_fields(b"key-a", "prev-x", canonical)
    sig2 = _sign_receipt_fields(b"key-a", "prev-x", canonical)
    sig3 = _sign_receipt_fields(b"key-b", "prev-x", canonical)
    sig4 = _sign_receipt_fields(b"key-a", "prev-y", canonical)
    assert sig1 == sig2
    assert sig1 != sig3 and sig1 != sig4


def test_blob_for_content_is_content_addressed(tmp_path):
    from ai_osop.evidence.store import ReceiptStore

    store = ReceiptStore(sa_engine=None, integrity=None, evidence_root=tmp_path)
    blob = store._blob_for_content(
        engagement_id="eng-1", kind="http_response", content='{"secret": "abc123xyz"}'
    )
    assert len(blob.sha256) == 64
    assert blob.artifact_id.startswith("art-")
    full = tmp_path / blob.blob_path
    assert full.exists()
    # persisted blob body is redacted at capture
    assert "abc123xyz" not in full.read_text()
    assert "[REDACTED" in full.read_text()


def _mk_receipt(rid: str, eng: str = "eng-9", vuln: str = "v-1") -> "ExploitReceipt":
    from ai_osop.evidence.models import ExploitReceipt

    return ExploitReceipt(
        receipt_id=rid,
        engagement_id=eng,
        vuln_id=vuln,
        approval_id="apr-1",
        verdict="confirmed",
        confidence=0.9,
        confirmation_note="n",
        scope_hash="sh",
    )


async def test_record_chains_receipts_hmac(sa_engine, tmp_path):
    from ai_osop.evidence.migrations import ensure_schema
    from ai_osop.evidence.store import ReceiptStore
    from ai_osop.safety.scope import AuditIntegrity

    await ensure_schema(sa_engine)
    store = ReceiptStore(
        sa_engine=sa_engine, integrity=AuditIntegrity(b"test-key-1"), evidence_root=tmp_path
    )

    h1 = await store.record(_mk_receipt("rcpt-a"))
    r1 = await store.get("rcpt-a")
    assert r1.integrity_sig == h1 and r1.prev_receipt_hash == ""

    await store.record(_mk_receipt("rcpt-b"))
    r2 = await store.get("rcpt-b")
    assert r2.prev_receipt_hash == h1


async def test_verify_chain_detects_tamper(sa_engine, tmp_path):
    from sqlalchemy import update

    from ai_osop.evidence.migrations import ensure_schema, exploit_receipts
    from ai_osop.evidence.models import ExploitReceipt
    from ai_osop.evidence.store import ReceiptStore
    from ai_osop.safety.scope import AuditIntegrity

    await ensure_schema(sa_engine)
    store = ReceiptStore(
        sa_engine=sa_engine, integrity=AuditIntegrity(b"k-verify"), evidence_root=tmp_path
    )
    for i, rid in enumerate(["ra-1", "ra-2", "ra-3"]):
        await store.record(_mk_receipt(rid, eng="eng-t", vuln=f"v-{i}"))
    assert await store.verify_chain("eng-t") is True

    async with sa_engine.begin() as conn:
        await conn.execute(
            update(exploit_receipts)
            .where(exploit_receipts.c.receipt_id == "ra-2")
            .values(verdict="not_confirmed")
        )
    assert await store.verify_chain("eng-t") is False


async def test_for_vulnerability_returns_only_matching(sa_engine, tmp_path):
    from ai_osop.evidence.migrations import ensure_schema
    from ai_osop.evidence.store import ReceiptStore
    from ai_osop.safety.scope import AuditIntegrity

    await ensure_schema(sa_engine)
    store = ReceiptStore(
        sa_engine=sa_engine, integrity=AuditIntegrity(b"k-q"), evidence_root=tmp_path
    )
    await store.record(_mk_receipt("rq-1", vuln="v-1"))
    await store.record(_mk_receipt("rq-2", vuln="v-2"))
    matches = await store.for_vulnerability("v-1")
    assert [m.receipt_id for m in matches] == ["rq-1"]


async def test_export_bundle_redacts_and_never_submits(sa_engine, tmp_path):
    from ai_osop.evidence.migrations import ensure_schema
    from ai_osop.evidence.models import ExploitReceipt
    from ai_osop.evidence.store import ReceiptStore
    from ai_osop.safety.scope import AuditIntegrity

    await ensure_schema(sa_engine)
    store = ReceiptStore(
        sa_engine=sa_engine, integrity=AuditIntegrity(b"k-exp"), evidence_root=tmp_path
    )
    await store.record(
        ExploitReceipt(
            receipt_id="rx-1",
            engagement_id="e-1",
            vuln_id="v-9",
            approval_id="apr-9",
            verdict="confirmed",
            confidence=0.95,
            confirmation_note="stored XSS via comment field",
            oracle_signals={"body_signature": 0.85},
            request_summary={
                "method": "POST",
                "url": "https://t/submit",
                "headers": {"Authorization": "[REDACTED:sha256:ab12]"},
            },
            response_summary={"http_code": 200},
            scope_hash="sh",
        )
    )
    bundle = await store.export_bundle("v-9")
    assert bundle["submitted"] is False
    assert bundle["receipt_count"] == 1
    assert "stored XSS" in bundle["markdown"]
    for rec in bundle["receipts"]:
        assert "Bearer" not in str(rec.get("request_summary", {}))


async def test_export_bundle_no_raw_secrets(sa_engine, tmp_path):
    """Gate (Task 26): an exported bundle must contain ZERO raw secrets.

    The receipt's artifacts are built the way capture builds them — content is
    routed through ReceiptStore._blob_for_content (capture-time redaction before
    persistence). The assertion then covers the full export surface: markdown,
    manifest (artifact model_dumps) and receipts (receipt model_dumps)."""
    from ai_osop.evidence.migrations import ensure_schema
    from ai_osop.evidence.models import ExploitReceipt
    from ai_osop.evidence.store import ReceiptStore
    from ai_osop.safety.scope import AuditIntegrity

    await ensure_schema(sa_engine)
    store = ReceiptStore(
        sa_engine=sa_engine,
        integrity=AuditIntegrity(b"k-secret-gate"),
        evidence_root=tmp_path,
    )

    # Secrets chosen so each redaction rule fires:
    #  - a 28-char alnum run            -> _TOKEN_RE
    #  - a Bearer value                 -> _BEARER_RE
    #  - a JSON "token" kv pair         -> _SECRET_KV_RE
    raw_token = "abcdefghijklmnopqrstuvwx1234"
    raw_bearer = "live-session-token-987654"
    raw_kv_secret = "s3cr3t-db-passw0rd!"
    secret_req_body = f"POST /login Authorization: Bearer {raw_bearer} " f"X-Api-Key: {raw_token}"
    secret_resp_body = f'{{"token": "{raw_kv_secret}", "status": "ok"}}'

    req_blob = store._blob_for_content(
        engagement_id="e-sec", kind="http_request", content=secret_req_body
    )
    resp_blob = store._blob_for_content(
        engagement_id="e-sec", kind="http_response", content=secret_resp_body
    )

    await store.record(
        ExploitReceipt(
            receipt_id="rx-sec",
            engagement_id="e-sec",
            vuln_id="v-sec",
            approval_id="apr-sec",
            verdict="confirmed",
            confidence=0.95,
            confirmation_note="chain completed",
            oracle_signals={},
            request_summary={
                "method": "POST",
                "url": "https://t/login",
                "headers": {"Authorization": "[REDACTED:sha256:a1b2]"},
            },
            response_summary={"http_code": 200},
            artifacts=[req_blob, resp_blob],
            scope_hash="sh-sec",
        )
    )

    bundle = await store.export_bundle("v-sec")
    md = bundle["markdown"]
    manifest_str = str(bundle["manifest"])
    receipts_str = str(bundle["receipts"])
    whole = md + manifest_str + receipts_str

    # 1. No raw secret surfaces anywhere in the exported bundle
    for raw in (raw_token, raw_bearer, raw_kv_secret):
        assert raw not in whole, f"export_bundle leaked raw secret {raw!r}"

    # 2. Redaction labels are present (proves the artifact content was scrubbed,
    #    not silently dropped)
    assert "[REDACTED" in manifest_str or "[REDACTED" in receipts_str

    # 3. Bundle contract still holds
    assert bundle["submitted"] is False
    assert bundle["receipt_count"] == 1

    # 4. On-disk blobs are redacted, raw material never persisted
    for blob in (req_blob, resp_blob):
        body = (tmp_path / blob.blob_path).read_text()
        for raw in (raw_token, raw_bearer, raw_kv_secret):
            assert raw not in body, f"on-disk blob leaked raw secret {raw!r}"
        assert "[REDACTED" in body
