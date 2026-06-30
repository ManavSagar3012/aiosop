"""Subdomain-takeover fingerprint engine.

A subdomain is takeover-able when its DNS points at a third-party service (often via
CNAME) that no longer has the resource claimed — the service then serves a
characteristic "unclaimed" response. We match on those service-specific signatures
(NOT bare 404s), because a generic 404 is the #1 false-positive source and false
positives get bug-bounty reports rejected. Signatures track the community
"can-i-take-over-xyz" dataset.
"""
from typing import Any, Dict, List, Optional

# Each entry: service name, CNAME substrings that indicate the provider (evidence
# only — not required to match), and one or more provider-specific unclaimed-resource
# signature strings (the decisive signal).
TAKEOVER_FINGERPRINTS: List[Dict[str, Any]] = [
    {"service": "AWS S3", "cname": ["s3.amazonaws.com", "s3-website", "amazonaws.com"],
     "fingerprints": ["NoSuchBucket", "The specified bucket does not exist"]},
    {"service": "GitHub Pages", "cname": ["github.io"],
     "fingerprints": ["There isn't a GitHub Pages site here",
                      "For root URLs (like http://example.com/) you must provide an index.html file"]},
    {"service": "Heroku", "cname": ["herokuapp.com", "herokudns.com"],
     "fingerprints": ["No such app", "herokucdn.com/error-pages/no-such-app.html"]},
    {"service": "Shopify", "cname": ["myshopify.com"],
     "fingerprints": ["Sorry, this shop is currently unavailable"]},
    {"service": "Fastly", "cname": ["fastly.net"],
     "fingerprints": ["Fastly error: unknown domain"]},
    {"service": "Bitbucket", "cname": ["bitbucket.io"],
     "fingerprints": ["Repository not found"]},
    {"service": "Surge.sh", "cname": ["surge.sh"],
     "fingerprints": ["project not found"]},
    {"service": "Tumblr", "cname": ["domains.tumblr.com"],
     "fingerprints": ["Whatever you were looking for doesn't currently exist at this address"]},
    {"service": "Pantheon", "cname": ["pantheonsite.io"],
     "fingerprints": ["The gods are wise, but do not know of the site which you seek"]},
    {"service": "Ghost", "cname": ["ghost.io"],
     "fingerprints": ["The thing you were looking for is no longer here, or never was"]},
    {"service": "Cloudfront", "cname": ["cloudfront.net"],
     "fingerprints": ["ERROR: The request could not be satisfied"]},
    {"service": "Azure", "cname": ["azurewebsites.net", "cloudapp.net", "trafficmanager.net", "blob.core.windows.net"],
     "fingerprints": ["404 Web Site not found"]},
]


def match_takeover(host: str, cnames: List[str], body: str) -> Optional[Dict[str, Any]]:
    """Return the matched service entry (with evidence) if `body` carries a
    provider-specific unclaimed signature, else None. CNAME match strengthens
    confidence but is not required (some takeovers resolve via A records / aliases).
    """
    body_l = (body or "").lower()
    cnames_l = [c.lower() for c in (cnames or [])]
    for entry in TAKEOVER_FINGERPRINTS:
        for sig in entry["fingerprints"]:
            if sig.lower() in body_l:
                cname_match = any(p in c for c in cnames_l for p in entry["cname"])
                return {
                    "service": entry["service"],
                    "signature": sig,
                    "host": host,
                    "cname_match": cname_match,
                    "cnames": cnames,
                    "confidence": 0.97 if cname_match else 0.85,
                }
    return None
