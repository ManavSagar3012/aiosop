# AI-OSOP Qualification Suite

Automated production readiness validation.

## Structure

| Suite | Purpose | Script |
|-------|---------|--------|
| Security | JWT, RBAC, WebSocket auth, session encryption | `test_security.py` |
| Reliability | Redis/Neo4j/Postgres/API/MCP restart survival | `test_reliability.py` |
| Ownership | Multi-tenant resource isolation | `test_ownership.py` |
| Scale | 100 tasks, API latency, graph capacity | `test_scale.py` |

## Running

### Individual suites
```bash
python scripts/qualification/test_security.py
python scripts/qualification/test_reliability.py
python scripts/qualification/test_ownership.py
python scripts/qualification/test_scale.py
```

### All suites + report
```bash
python scripts/qualification/run_all.py
```

Output: `PRODUCTION_READINESS_REPORT.md`

## Scoring

| Score | Status |
|-------|--------|
| >= 90% | Production ready |
| 70-89% | Address failed tests before production |
| < 70% | Significant work required |

## Safety

- Reliability tests restart docker-compose services. Run only in staging.
- Scale tests create many tasks. Clean up after with `scripts/ops/cleanup.py`.
- Ownership tests create test engagements. They are prefixed with `ownership-` for easy cleanup.
