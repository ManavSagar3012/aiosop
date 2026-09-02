# Release evidence and rollback runbook

## Evidence classes

Local evidence is tied to the current Git SHA and dirty state. It proves only what was run on the local source tree. Staging rollout, registry signing, transparency-log inclusion, admission policy, and alert delivery remain external gates and must never be inferred from local PASS results.

## Local checks

```text
python scripts/release/validate_release.py --output validation-artifacts/release-validation.json
python scripts/release/generate_evidence.py
```

The validator needs only Python and Git; it checks source-level workload security, probes, resources, default-deny policy, mutable image references, and workflow action pinning. If Helm is available, also run `helm lint helm/ai-osop` and render with an immutable `image.digest`. If kubectl is available, perform client and server dry-runs against the intended Kubernetes version.

## Migration proof

Use a dedicated disposable PostgreSQL database only:

```text
python scripts/release/migration_proof.py --database-url <disposable-url> --from-revision 0006 --to-revision head --allow-destructive --output validation-artifacts/migration-proof.json
```

The URL is never written to the report. Back up production before migration. Roll application and schema in the compatibility order documented by the release. Do not downgrade when a migration declares irreversible data loss; restore the verified backup instead.

## Runtime and observability proof

Build the release image at the exact SHA, inspect `Config.User`, run with a read-only root filesystem, dropped capabilities, a writable bounded `/tmp`, and use Python/HTTP tooling rather than embedding credentials. Then run:

```text
python scripts/release/observability_smoke.py --base-url http://127.0.0.1:8200 --output validation-artifacts/observability-smoke.json
```

Staging must additionally prove request-ID propagation in the centralized log backend, Prometheus rule loading, a synthetic alert reaching the configured receiver, NetworkPolicy enforcement, and a successful rollout/rollback with workload availability. Retain command output and platform audit identifiers.

## Supply chain and CI gates

CI must generate CycloneDX and SPDX SBOMs, scan repository/IaC/secrets/image with blocking policy, publish digest-addressed images, generate build provenance, and keylessly sign/attest the digest. Verify signature identity and issuer before promotion. These require registry and CI identity and therefore cannot be claimed by local generation.

All third-party workflow actions are commit-SHA pinned. Automated dependency updates should propose reviewed pin changes. Base and service images must be promoted by digest in the production values overlay.

## Consolidation

`generate_evidence.py` hashes every retained artifact, records SHA and dirty paths, and explicitly marks external requirements `required-not-evaluated`. A dirty tree is allowed for development evidence but must block production promotion policy.
