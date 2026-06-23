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
          containers:
          - name: neo4j-backup
            image: neo4j:5.18-community
            command:
            - /bin/sh
            - -c
            - |
              neo4j-admin database dump --to-path=/backup ai-osop-$(date +%Y%m%d).dump
              aws s3 cp /backup/ s3://ai-osop-backups/neo4j/ --recursive
              aws s3 ls s3://ai-osop-backups/neo4j/ | awk '$1 < "'$(date -d '30 days ago' +%Y-%m-%d)'" {print $4}' | xargs -I {} aws s3 rm s3://ai-osop-backups/neo4j/{}
            env:
            - name: NEO4J_AUTH
              valueFrom:
                secretKeyRef:
                  name: ai-osop-secrets
                  key: neo4j-password
            volumeMounts:
            - name: backup-tmp
              mountPath: /backup
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
          containers:
          - name: redis-backup
            image: redis:7-alpine
            command:
            - /bin/sh
            - -c
            - |
              redis-cli -h $REDIS_HOST BGSAVE
              sleep 10
              redis-cli -h $REDIS_HOST --rdb /backup/dump.rdb
              cp /backup/dump.rdb /backup/ai-osop-$(date +%Y%m%d-%H%M%S).rdb
              aws s3 cp /backup/ s3://ai-osop-backups/redis/ --recursive
              aws s3 ls s3://ai-osop-backups/redis/ | awk '$1 < "'$(date -d '3 days ago' +%Y-%m-%d)'" {print $4}' | xargs -I {} aws s3 rm s3://ai-osop-backups/redis/{}
            env:
            - name: REDIS_HOST
              value: "ai-osop-redis.ai-osop.svc.cluster.local"
            volumeMounts:
            - name: backup-tmp
              mountPath: /backup
          restartPolicy: OnFailure
```

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

## 9. Implementation Order

1. **HPA manifests** (`k8s/hpa.yaml`)
2. **PDB manifests** (`k8s/pdb.yaml`)
3. **Enhanced readiness probe config** (update `k8s/orchestrator-deployment.yaml`)
4. **Log retention ConfigMap** (`k8s/log-retention.yaml`)
5. **Backup CronJobs** (`k8s/backup-cronjobs.yaml`)
6. **Resource Quota** (`k8s/resource-quota.yaml`)
7. **Tests** (`tests/test_production_ops_*.py`)

---

## 10. Success Criteria

- [ ] HPA scales orchestrator from 2 → 10 replicas under CPU load
- [ ] HPA scales agents from 3 → 20 replicas under queue depth load
- [ ] PDB prevents all orchestrator pods from being drained simultaneously
- [ ] Readiness probe tolerates 15s of dependency flapping
- [ ] Log retention config is applied to all pods
- [ ] Postgres backups run hourly and persist to S3
- [ ] Neo4j backups run daily and persist to S3
- [ ] Redis backups run every 6h and persist to S3
- [ ] All new manifests pass `kubectl apply --dry-run=client`

*End of Design Document*
