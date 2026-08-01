"""Provision one KMS CMK per tenant and regenerate an env fragment.

Usage:
  python scripts/ops/bootstrap_kms.py --tenant org-blue --tenant org-red \
      [--alias-prefix alias/ai-osop-] [--region us-east-1] [--out .env.kms]

Idempotent: looks up an existing alias first; only creates a CMK when absent.
Writes shell-style exports the caller can source into .env.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, List


def _kms_client(region: str | None) -> Any:
    try:
        import boto3
    except ImportError:
        sys.stderr.write(
            "boto3 is required: pip install boto3  (or `poetry install --with dev`)\n"
        )
        raise SystemExit(2)
    return boto3.client("kms", region_name=region)


def _ensure_alias(kms: Any, alias: str, description: str) -> Dict[str, str]:
    """Return KeyId/TargetKeyId for alias if present, else create and tag."""
    alias_arn = alias.lstrip("alias/")
    full_alias = alias if alias.startswith("alias/") else f"alias/{alias}"
    try:
        resp = kms.describe_key(KeyId=full_alias)
        meta = resp.get("KeyMetadata", {})
        return {
            "key_id": meta.get("KeyId", ""),
            "arn": meta.get("Arn", ""),
            "alias": full_alias,
            "existing": True,
        }
    except kms.exceptions.NotFoundException:
        resp = kms.create_key(Description=description, KeyUsage="ENCRYPT_DECRYPT", Origin="AWS_KMS")
        key_id = resp["KeyMetadata"]["KeyId"]
        # Tag for tenant tracking (required for audit / lifecycle management).
        kms.create_alias(AliasName=full_alias, TargetKeyId=key_id)
        meta = kms.describe_key(KeyId=key_id).get("KeyMetadata", {})
        return {
            "key_id": key_id,
            "arn": meta.get("Arn", ""),
            "alias": full_alias,
            "existing": False,
        }


def main(argv: List[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--tenant", action="append", required=True, help="tenant id (repeatable)")
    p.add_argument("--alias-prefix", default="alias/ai-osop-")
    p.add_argument("--region", default=None)
    p.add_argument("--out", default=None, help="file to append exports to (default stdout)")
    args = p.parse_args(argv)

    kms = _kms_client(args.region)
    outputs: Dict[str, Dict[str, Any]] = {}
    lines: List[str] = []
    for tenant in args.tenant:
        alias = f"{args.alias_prefix}{tenant}"
        info = _ensure_alias(kms, alias, description=f"AI-OSOP tenant key: {tenant}")
        outputs[tenant] = info
        lines.append(f"export OSOP_KMS_ARN_{tenant.replace('-', '_').upper()}={info['arn']}")
    payload = json.dumps(outputs, indent=2)
    if args.out:
        with open(args.out, "a", encoding="utf-8") as fh:
            fh.write("\n# ai-osop bootstrap_kms " + "\n".join(lines) + "\n")
        sys.stdout.write(f"wrote {args.out}\n")
    sys.stdout.write(payload + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
