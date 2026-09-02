# Release Hygiene Evidence

- Scope: working tree inspection only; no commit or push.
- Preserved: all uncertain or intentional source, test, deployment, audit, qualification, migration, documentation, and evidence changes.
- Fixed: trailing whitespace in `scripts/ops/calc_hash.py`; whitespace-only defects reported by `git diff --check` were normalized without changing program text.
- Deleted as proven malformed/generated root artifacts: `$null`, single-quote filename, `AsyncIterator[None]`, `None`, `stdout`, `window.clearTimeout(focusTimer)`, and `{`-prefixed malformed filename.
- Ignore hygiene: added `.runtime/` (local secrets), `.phase_*` (generated analysis scratch), and `/stdout`.
- Classification: tracked changes are intentional/uncertain implementation and release work; retained untracked source/tests/docs/migrations/evidence are potentially intentional; generated validation evidence was retained because release/audit provenance was uncertain.
- Validation: `git diff --check` exit code **0**, with no output.
