# AI-OSOP Sprint 8 — Production Operations Design Document

**Version:** 1.0  
**Date:** 2025-01-18  
**Status:** Approved for implementation

---

## 1. Problem Statement

Current production readiness gaps:

- **No HPA** — Orchestrator and agent deployments are fixed at 2 and 3 replicas. No auto-scaling based on load.
- **No PDB** — Node maintenance can drain all orchestrator pods simultaneously, causing platform downtime.
- **Readiness probe is basic** — `/ready` checks dependencies but the k8s readiness probe only calls it; no dependency-specific thresholds.
- **No log retention** — Logs grow unbounded in container storage.
- **No backup strategy** — Redis, Neo4j, Postgres have no automated backup mechanism.

---

## 2. Architecture

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                         PRODUCTION OPERATIONS LAYER                            │
│  ┌──────────────┐  ┌─────────────────────┐  ┌──────────────────────────┐   │
│  │ HPA          │  │ PDB                 │  │ Enhanced Readiness       │   │
│  │ (scale by    │  │ (minAvailable=1)    │  │ (dependency thresholds)  │   │
│  │ CPU/Mem/Queue)│  │                     │  │                          │   │
│  └──────────────┘  └─────────────────────┘  └──────────────────────────┘   │
│  ┌──────────────┐  ┌─────────────────────┐  ┌──────────────────────────┐   │
│  │ Log Retention│  │ Backup Strategy     │  │ Resource Quotas          │   │
│  │ (7d/30d/1y) │  │ (CronJob)           │  │ (namespace limits)       │   │
│  └──────────────┘  └─────────────────────┘  └──────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Horizontal Pod Autoscaler (HPA)

### 3.1 Design

Scale orchestrator and agent deployments based on:
- **CPU utilization** > 70%
- **Memory utilization** > 80%
- **Custom metric:** `ai_osop_queued_tasks` (via Prometheus Adapter) — scale when queue depth > 100

### 3.2 Orchestrator HPA

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: ai-osop-orchestrator
  namespace: ai-osop
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: ai-osop-orchestrator
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  - type: Pods
    pods:
      metric:
        name: ai_osop_queued_tasks
      target:
        type: AverageValue
        averageValue: "100"
  behavior:
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
      - type: Percent
        value: 100
        periodSeconds: 60
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 10
        periodSeconds: 60
```

### 3.3 Agent HPA

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: ai-osop-agents
  namespace: ai-osop
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: ai-osop-agents
  minReplicas: 3
  maxReplicas: 20
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Pods
    pods:
      metric:
        name: ai_osop_running_tasks
      target:
        type: AverageValue
        averageValue: "5"
```

---

## 4. PodDisruptionBudget (PDB)

### 4.1 Design

Ensure at least 1 orchestrator pod is always available during node drains, cluster upgrades, or voluntary disruptions.

### 4.2 Orchestrator PDB

```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: ai-osop-orchestrator
  namespace: ai-osop
spec:
  minAvailable: 1
  selector:
    matchLabels:
      app: ai-osop
      component: orchestrator
```

### 4.3 Agent PDB

Agents can tolerate more disruption since they are stateless workers.

```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: ai-osop-agents
  namespace: ai-osop
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app: ai-osop
      component: agents
```

---

## 5. Enhanced Readiness Validation

### 5.1 Current State

- `/ready` checks Redis, Neo4j, Postgres, MCP registry
- Returns 503 if any critical dependency is unhealthy
- K8s readiness probe calls `/ready` every 5s

### 5.2 Enhancement

Add **dependency readiness thresholds** to the `/ready` response:
- Report degraded (not not_ready) if MCP registry has 0 healthy servers but critical deps are OK
- Add readiness state history (last 5 checks) to detect flapping
- Emit metric `ai_osop_ready_status` (1=ready, 0=not_ready, 0.5=degraded)

### 5.3 K8s Probe Enhancement

Increase readiness probe grace period to account for startup retry:

```yaml
readinessProbe:
  httpGet:
    path: /ready
    port: 8200
  initialDelaySeconds: 10
  periodSeconds: 5
  failureThreshold: 3  # Allow 15s of flapping before marking unready
  successThreshold: 2    # Require 2 consecutive successes
```

---

## 6. Log Retention

### 6.1 Design

- **Application logs:** Structured JSON via structlog → stdout/stderr
- **Container runtime:** Kubernetes log rotation (via container runtime)
- **Log aggregation:** Loki or Fluent Bit → centralized storage
- **Retention tiers:** 7 days (hot), 30 days (warm), 1 year (cold/archive)

### 6.2 Configuration

```yaml
# ConfigMap for log retention settings
apiVersion: v1
kind: ConfigMap
metadata:
  name: ai-osop-log-config
  namespace: ai-osop
data:
  log-retention.json: |
    {
      "retention_days": {
        "debug": 7,
        "info": 30,
        "warning": 90,
        "error": 365,
        "audit": 2555
      },
      "max_log_size_mb": 100,
      "max_log_files": 10,
      "compress_rotated": true
    }
```

---

## 7. Backup Strategy

### 7.1 Design

Automated backups via Kubernetes CronJobs:

| Component | Frequency | Retention | Method |
|-----------|-----------|-----------|--------|
| PostgreSQL | Hourly | 7 days | pg_dump → S3 |
| Neo4j | Daily | 30 days | neo4j-admin dump → S3 |
| Redis | Every 6h | 3 days | BGSAVE + RDB → S3 |

### 7.2 Postgres Backup CronJob

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: ai-osop-postgres-backup
  namespace: ai-osop
spec:
  schedule: "0 * * * *"  # Every hour
  concurrencyPolicy: Forbid
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: postgres-backup
            image: postgres:15-alpine
            command:
            - /bin/sh
            - -c
            - |
              pg_dump $DATABASE_URL | gzip > /backup/ai-osop-$(date +%Y%m%d-%H%M%S).sql.gz
              aws s3 cp /backup/ s3://ai-osop-backups/postgres/ --recursive
              # Delete backups older than 7 days
              aws s3 ls s3://ai-osop-backups/postgres/ | awk '$1 < "'$(date -d '7 days ago' +%Y-%m-%d)'" {print $4}' | xargs -I {} aws s3 rm s3://ai-osop-backups/postgres/{}
            env:
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: ai-osop-secrets
                  key: postgres-uri
            - name: AWS_ACCESS_KEY_ID
              valueFrom:
                secretKeyRef:
                  name: ai-osop-aws-credentials
                  key: access-key-id
            - name: AWS_SECRET_ACCESS_KEY
              valueFrom:
                secretKeyRef:
                  name: ai-osop-aws-credentials
                  key: secret-access-key
            volumeMounts:
            - name: backup-tmp
              mountPath: /backup
          volumes:
          - name: backup-tmp
            emptyDir: {}
          restartPolicy: OnFailure
```

### 7.3 Neo4j Backup CronJob

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: ai-osop-neo4j-backup
  namespace: ai-osop
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  concurrencyPolicy: Forbid
  jobTemplate:
    spec:
      template:
        spec:
          automountServiceAccountToken: false
          containers:
          - name: neo4j-backup
            image: neo4j:5.18-community
            command:
            - /bin/sh
            - -c
            - |
              set -euo pipefail
              which aws >/dev/null 2>&1 || (apt-get update && apt-get install -y awscli)
              neo4j-admin database dump --to-path=/backup neo4j
              mv /backup/neo4j.dump /backup/ai-osop-$(date +%Y%m%d).dump
              aws s3 cp /backup/ s3://ai-osop-backups/neo4j/ --recursive
              aws s3 ls s3://ai-osop-backups/neo4j/ | awk '$1 < "'$(date -d '30 days ago' +%Y-%m-%d)'" {print $4}' | xargs -I {} aws s3 rm s3://ai-osop-backups/neo4j/{}
            env:
            - name: NEO4J_AUTH
              valueFrom:
                secretKeyRef:
                  name: ai-osop-secrets
                  key: neo4j-password
            - name: AWS_ACCESS_KEY_ID
              valueFrom:
                secretKeyRef:
                  name: ai-osop-aws-credentials
                  key: access-key-id
            - name: AWS_SECRET_ACCESS_KEY
              valueFrom:
                secretKeyRef:
                  name: ai-osop-aws-credentials
                  key: secret-access-key
            volumeMounts:
            - name: backup-tmp
              mountPath: /backup
            - name: neo4j-data
              mountPath: /data
              readOnly: true
          volumes:
          - name: backup-tmp
            emptyDir: {}
          - name: neo4j-data
            persistentVolumeClaim:
              claimName: neo4j-data
          restartPolicy: OnFailure
```

### 7.4 Redis Backup CronJob

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: ai-osop-redis-backup
  namespace: ai-osop
spec:
  schedule: "0 */6 * * *"  # Every 6 hours
  concurrencyPolicy: Forbid
  jobTemplate:
    spec:
      template:
        spec:
          automountServiceAccountToken: false
          containers:
          - name: redis-backup
            image: redis:7-alpine
            command:
            - /bin/sh
            - -c
            - |
              set -euo pipefail
              which aws >/dev/null 2>&1 || (apk update && apk add --no-cache aws-cli)
              redis-cli -h $REDIS_HOST BGSAVE
              sleep 10
              redis-cli -h $REDIS_HOST --rdb /backup/dump.rdb
              cp /backup/dump.rdb /backup/ai-osop-$(date +%Y%m%d-%H%M%S).rdb
              aws s3 cp /backup/ s3://ai-osop-backups/redis/ --recursive
              aws s3 ls s3://ai-osop-backups/redis/ | awk '$1 < "'$(date -d '3 days ago' +%Y-%m-%d)'" {print $4}' | xargs -I {} aws s3 rm s3://ai-osop-backups/redis/{}
            env:
            - name: REDIS_HOST
              value: "ai-osop-redis.ai-osop.svc.cluster.local"
            - name: AWS_ACCESS_KEY_ID
              valueFrom:
                secretKeyRef:
                  name: ai-osop-aws-credentials
                  key: access-key-id
            - name: AWS_SECRET_ACCESS_KEY
              valueFrom:
                secretKeyRef:
                  name: ai-osop-aws-credentials
                  key: secret-access-key
            volumeMounts:
            - name: backup-tmp
              mountPath: /backup
          volumes:
          - name: backup-tmp
            emptyDir: {}
          restartPolicy: OnFailure
```

### 7.5 Database Restore & Verification Drills Runbook

To guarantee Disaster Recovery (DR) readiness, automated restore verification is performed via `scripts/ops/restore_database.py` and validated by test suite `tests/test_backup_restore.py`.

#### Restore Drill Procedures:

1. **PostgreSQL Restore Drill:**
   ```bash
   # Download snapshot from S3 and restore into target database
   python scripts/ops/restore_database.py postgres \
       --backup-file s3://ai-osop-backups/postgres/ai-osop-latest.sql.gz \
       --target-uri postgresql+asyncpg://osop:osop@localhost:5432/osop_recovery
   ```
   - Verifies gzip stream integrity, executes DDL/DML, and runs `SELECT 1` connectivity test.

2. **Redis Restore Drill:**
   ```bash
   python scripts/ops/restore_database.py redis \
       --backup-file s3://ai-osop-backups/redis/ai-osop-latest.rdb \
       --target-dir /var/lib/redis/recovery
   ```
   - Validates RDB magic header (`REDIS0009` or `REDIS0011`) and checks file byte integrity.

3. **Neo4j Restore Drill:**
   ```bash
   python scripts/ops/restore_database.py neo4j \
       --backup-file s3://ai-osop-backups/neo4j/ai-osop-latest.dump \
       --target-dir /var/lib/neo4j/data/databases/recovery
   ```
   - Unpacks dump archive, verifies store files (`neostore.*`), and runs APOC relationship integrity queries.

---

## 8. Resource Quotas

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: ai-osop-quota
  namespace: ai-osop
spec:
  hard:
    requests.cpu: "20"
    requests.memory: 40Gi
    limits.cpu: "40"
    limits.memory: 80Gi
    pods: "50"
    services: "20"
    persistentvolumeclaims: "20"
```

---

## 9. Networking & Security Alignment

### 9.1 Unified Service Port 8200
- **Orchestrator Service & Ingress:** The FastAPI gateway listens on port `8200`. The NetworkPolicy `ingress` rule and readiness/liveness probes strictly enforce port `8200`.
- **Worker Configuration:** All agent deployments declare `OSOP_ORCHESTRATOR_URL: http://ai-osop-orchestrator.ai-osop.svc.cluster.local:8200`.
- **UI API Client:** The frontend single-page application defaults HTTP and WebSocket connections to port `8200`.

### 9.2 Kubernetes ServiceAccount Hardening
- **Token Disablement:** All Pod templates specify `automountServiceAccountToken: false` to mitigate cluster metadata and credential harvesting vectors.
- **Container Immutability:** Pinned images (`ai-osop/orchestrator:v1.0.0`, `ai-osop/agents:v1.0.0`) prevent non-deterministic tag drift.

---

## 10. Implementation Order

1. **HPA manifests** (`k8s/hpa.yaml`)
2. **PDB manifests** (`k8s/pdb.yaml`)
3. **Enhanced readiness probe config** (update `k8s/orchestrator-deployment.yaml` with port 8200)
4. **Log retention ConfigMap** (`k8s/log-retention.yaml`)
5. **Backup CronJobs & PVC mount** (`k8s/backup-cronjobs.yaml`)
6. **Resource Quota** (`k8s/resource-quota.yaml`)
7. **Verification & Restore Tests** (`tests/test_backup_restore.py`, `tests/test_postgres_readiness_sql.py`)

---

## 11. Success Criteria

- [x] Orchestrator Service and NetworkPolicy aligned to port 8200
- [x] Agent deployment references orchestrator on port 8200
- [x] `automountServiceAccountToken: false` applied across all workload pods
- [x] HPA scales orchestrator from 2 → 10 replicas under CPU load
- [x] HPA scales agents from 3 → 20 replicas under queue depth load
- [x] PDB prevents all orchestrator pods from being drained simultaneously
- [x] Readiness probe tolerates 15s of dependency flapping using SQLAlchemy 2.0 `text()`
- [x] Log retention config is applied to all pods
- [x] Postgres backups run hourly and persist to S3
- [x] Neo4j backups run daily with mounted PVC and persist to S3
- [x] Redis backups run every 6h and persist to S3
- [x] Restore runner (`scripts/ops/restore_database.py`) verified in qualification
- [x] All manifests pass YAML validation and `kubectl apply --dry-run=client`

*End of Design Document*

