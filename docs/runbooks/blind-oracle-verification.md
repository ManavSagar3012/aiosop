# Operational Runbook: Blind-Oracle Live Verification Against Juice Shop

This is the recipe for the live-fire verification pass described in
`docs/superpowers/plans/2026-08-01-proof-carrying-chains.md` Task 25. The goal
is to prove — with an on-disk, HMAC-chained receipt — that the blind-oracle
seam (`ExploitValidationAgent` → namespaced OAST token → HTTP sink callback →
`ReceiptStore.record` → `ReceiptStore.verify_chain`) hangs end-to-end against a
real vulnerable target, not just unit mocks.

## 1. Target bring-up

Start OWASP Juice Shop exactly the way `benchmarks/juiceshop/README.md` does:

```bash
docker run --rm -d -p 3000:3000 --name juice-shop bkimminich/juice-shop
# Wait for it to come up
curl -sS http://localhost:3000/ >/dev/null && echo "juice-shop up"
```

Scope note: the engagement must allow `localhost:3000` (or the loopback IP you
reach it as) in its `domains`/`ips` allowlists — the chain composer and the
OAST caller-side schema both refuse out-of-scope traffic before this recipe
can run.

## 2. Platform env flip

Receipts are **off by default**. Flip them on via env and point them at a
directory the operator controls:

```bash
export OSOP_EVIDENCE_RECEIPTS_ENABLED=true
export OSOP_EVIDENCE_ROOT=./evidence       # or an absolute path
```

`evidence_receipts_enabled` is the gate that `ExploitValidationAgent` and
`ChainExecutorAgent` consult before they record `ExploitReceipt`s; the SQL
schema (`exploit_receipts` table) must already exist — `ensure_schema` runs
on startup, or migrate manually.

## 3. Run a blind finding end-to-end

Drive the seam (a real scan against Juice Shop, or a targeted validation
task) until at least one blind-class interaction fires. The receipt shows up
in two places:

- **Postgres**: a row in `exploit_receipts` with `engagement_id`,
  `vuln_id`, `verdict`, `confidence`, `oracle_signals`, `prev_receipt_hash`,
  `integrity_sig`, `created_at`.
- **On disk**: an artifact blob per captured request/response, named
  `art-<sha256[:12]>` and stored under
  `evidence/<engagement_id>/art-<digest>.json`. Files are written
  redacted — secrets are scrubbed at capture time by `redact_text`, so the
  export path never re-emits them.

The on-disk name is content-addressed, so two receipts sharing the same
redacted blob body land on the same file and `redaction_map` is the only
place the original length/shape survives.

## 4. Verify the chain

From a Python shell with the platform importable (same env as the live
process):

```python
import asyncio
from pathlib import Path
from ai_osop.evidence.store import ReceiptStore
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.safety.scope import AuditIntegrity

async def main():
    sm = SessionMemory()
    await sm.connect()
    store = ReceiptStore(
        sa_engine=sm._pg_engine,
        integrity=AuditIntegrity(b"<the-same-signing-key-the-live-process-used>"),
        evidence_root=Path("./evidence"),
    )
    ok = await store.verify_chain("eng-1")
    print("verify_chain:", ok)
    await sm.aclose()      # async close; do not use close() (deprecated)

asyncio.run(main())
```

`verify_chain` replays the HMAC chain ordered by `created_at` for that
engagement. Any tampering (verdict flipped, confidence edited, row deleted)
makes the receipt at that index and all subsequent receipts fail verification
and `verify_chain` returns `False`.

## 5. Read the export bundle

`ReceiptStore.export_bundle(vuln_id, redact_secrets=True)` returns
`{"markdown", "manifest", "receipts", "receipt_count", "submitted": False,
"redact_secrets": True}`. The `markdown` is the bounty-grade snippet a
reviewer pastes into a report; `submitted=False` is hard-coded because the
bundle is a **staging area** — nothing here submits to H1/Bugcrowd.

The `manifest` enumerates each artifact (`artifact_id`, `kind`, `sha256`,
`blob_path`) so a downstream auditor can independently `sha256sum` the files
under `evidence/<engagement_id>/` and confirm capture-time integrity.

## 6. What to look for

- `receipts[i]["oracle_signals"]["oast_hit"]` is `True` for blind classes
  (blind_xss / blind_sqli / blind_ssti) that fired a real callback.
- `receipts[i]["verdict"] == "confirmed"` only when the OOB interaction was
  actually captured, or the deterministic body-signature dispatcher returned
  `>= 0.8`. A blind class can never flip to `confirmed` purely because the
  HTTP response looked suspicious.
- `receipts[i]["confidence"]` for blind_xss is `0.6` on OAST-only proof
  (spec §3.2). Blind_sqli and blind_ssti land at `0.9` under the same
  conditions. Dual-correlated (OAST + browser-mcp DOM) findings are reserved
  for `0.97`, which the executor does not emit yet — see Part IV backlog.

## 7. Shutting it down

```bash
docker stop juice-shop
unset OSOP_EVIDENCE_RECEIPTS_ENABLED OSOP_EVIDENCE_ROOT
```

The on-disk evidence root and Postgres rows persist between runs; rotate the
`AuditIntegrity` signing key when rotating any other platform signing key.
