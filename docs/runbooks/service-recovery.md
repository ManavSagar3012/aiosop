# Operational Runbook: Service Recovery

## 1. Redis Recovery
If Redis is unreachable:
1. `docker-compose restart redis`
2. Verify connectivity: `redis-cli ping`
3. Check orchestrator logs for task queue reconnection.

## 2. PostgreSQL Recovery
If Postgres is unreachable:
1. `docker-compose restart postgres`
2. Verify readiness: `docker exec ai-osop-postgres pg_isready`
3. Verify API connectivity in orchestrator logs.

## 3. Neo4j Recovery
If Neo4j is unreachable:
1. `docker-compose restart neo4j`
2. Monitor startup logs for bolt readiness.
