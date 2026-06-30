"""Subdomain permutation engine (altdns-style).

Most bounty value starts with attack-surface breadth. Given the subdomains already
discovered (crt.sh, wayback, DNS), this expands them into likely-existing candidates
(dev-/staging-/api- prefixes, -test/-uat suffixes, numeric increments) to resolve and
feed into subdomain_takeover_scan and recon. Pure + deterministic so it's testable
and cheap; resolution is a separate step.
"""
import re
from typing import Iterable, List, Set

DEFAULT_WORDS: List[str] = [
    "dev", "staging", "stage", "test", "uat", "qa", "prod", "api", "admin", "internal",
    "vpn", "beta", "demo", "app", "portal", "gateway", "auth", "sso", "mail", "git",
    "jenkins", "jira", "confluence", "grafana", "kibana", "backup", "old", "new", "v2",
]


def _root_domain(domain: str) -> str:
    """Best-effort registrable root (last two labels). Good enough for permutation."""
    parts = domain.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def _label(sub: str, root: str) -> str:
    """Strip the root from a full subdomain to get the leftmost label group."""
    if sub.endswith("." + root):
        return sub[: -(len(root) + 1)]
    return sub


def generate_permutations(
    domain: str, known_subs: Iterable[str], words: Iterable[str] = None
) -> List[str]:
    """Return a deduplicated, in-scope list of candidate subdomains."""
    root = _root_domain(domain)
    words = list(words if words is not None else DEFAULT_WORDS)
    out: Set[str] = set()

    labels = []
    for s in known_subs:
        lbl = _label(s, root).strip(".")
        if lbl:
            labels.append(lbl)

    # Words against the bare root.
    for w in words:
        out.add(f"{w}.{root}")

    for lbl in labels:
        # prefix/suffix word permutations
        for w in words:
            out.add(f"{w}-{lbl}.{root}")
            out.add(f"{lbl}-{w}.{root}")
            out.add(f"{w}.{lbl}.{root}")
        # numeric increment: api1 -> api2, api3 ; api -> api1
        m = re.match(r"^(.*?)(\d+)$", lbl)
        if m:
            base, num = m.group(1), int(m.group(2))
            for d in (1, 2):
                out.add(f"{base}{num + d}.{root}")
        else:
            for d in (1, 2):
                out.add(f"{lbl}{d}.{root}")

    return sorted(out)
