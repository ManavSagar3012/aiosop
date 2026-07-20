"""Pure view/normalization layer for finding nodes read from graph_memory.

No DB I/O. Takes a raw dict as persisted on a vulnerability node (see
get_vulnerabilities_by_engagement) and resolves the fields that are not
directly on the node (url/method/param) via the evidence[0] fallback chain,
plus a couple of display-friendly derived fields (title, category,
cvss_score).
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, TypedDict


class FindingView(TypedDict, total=False):
    id: Any
    title: str
    vuln_type: Any
    category: Any
    severity: Any
    confidence: Any
    cwe: Any
    cvss_score: float
    description: Any
    evidence: List[Dict[str, Any]]
    validated: Any
    tool_source: Any
    engagement_id: Any
    entry_point: Any
    requires_auth: Any
    exploitability: Any
    impact: Any
    endpoint_id: Any
    url: Optional[str]
    method: str
    param: Optional[Any]


_URL_FALLBACK_KEYS = (
    "matched_at", "url", "verify_url", "store_url", "host",
    "render_url", "request_url", "target", "uri",
)
_PARAM_FALLBACK_KEYS = ("parameter", "injection", "store_field", "accepted_fields")

# Derived-only fallback (NOT a real CVSS score) used when the node has no
# cvss_score of its own — keep this table clearly separate from real data.
_SEVERITY_TO_CVSS = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.0,
    "low": 3.0,
    "info": 0.0,
}


def _coerce_dict(node: Any) -> Dict[str, Any]:
    """Accept a persisted-node dict, a pydantic model, or any attribute-bearing
    object and return a plain dict. The canonical view is the single entry point
    every consumer calls, so it must be robust to model-or-dict input rather than
    forcing each caller to normalize (which previously drifted per-consumer).
    """
    if isinstance(node, dict):
        return node
    # pydantic v2 model
    dump = getattr(node, "model_dump", None)
    if callable(dump):
        try:
            return dump()
        except Exception:  # noqa: BLE001 - fall through to generic paths
            pass
    # pydantic v1 model
    dump_v1 = getattr(node, "dict", None)
    if callable(dump_v1):
        try:
            return dump_v1()
        except Exception:  # noqa: BLE001
            pass
    # generic object with __dict__
    obj_dict = getattr(node, "__dict__", None)
    if isinstance(obj_dict, dict):
        return dict(obj_dict)
    return {}


def to_finding_view(node: Any) -> FindingView:
    # 0. coerce model / object input to a plain dict (canonical entry point)
    node = _coerce_dict(node)
    # 1. decode evidence defensively
    raw_evidence = node.get("evidence")
    if isinstance(raw_evidence, str):
        try:
            ev: List[Dict[str, Any]] = json.loads(raw_evidence)
        except json.JSONDecodeError:
            ev = []
    elif isinstance(raw_evidence, list):
        ev = raw_evidence
    else:
        ev = []
    ev0: Dict[str, Any] = ev[0] if ev and isinstance(ev[0], dict) else {}

    # 2. url
    url = node.get("url") or None
    if not url:
        for key in _URL_FALLBACK_KEYS:
            val = ev0.get(key)
            if val:
                url = val
                break

    # 3. method
    method = node.get("method") or ev0.get("method") or "GET"

    # 4. param
    param = None
    for key in _PARAM_FALLBACK_KEYS:
        val = ev0.get(key)
        if val:
            param = val
            break

    # 5. category
    category = node.get("vuln_type") or node.get("category")

    # 6. title
    title = node.get("title") or category or "Finding"

    # 7. cvss_score: real value passes through; only derive when missing
    cvss_score = node.get("cvss_score")
    if cvss_score is None:
        severity = str(node.get("severity") or "").lower()
        cvss_score = _SEVERITY_TO_CVSS.get(severity, 0.0)  # derived, not real

    # 8. pass through remaining persisted keys as-is
    view: FindingView = dict(node)  # type: ignore[assignment]
    view["evidence"] = ev
    view["url"] = url
    view["method"] = method
    view["param"] = param
    view["category"] = category
    view["title"] = title
    view["cvss_score"] = cvss_score
    return view


if __name__ == "__main__":
    orphaned_sqli_node = {
        "id": "v1",
        "vuln_type": "sqli",
        "severity": "high",
        "evidence": json.dumps([{
            "type": "sqli_oracle",
            "provenance": "http",
            "url": "http://localhost:3000/rest/user/login",
            "technique": "auth_bypass",
            "endpoint": "http://localhost:3000/rest/user/login",
            "payload": "' OR 1=1--",
            "http_status": 200,
            "proof": "...",
            "confidence": 1.0,
        }]),
    }
    view1 = to_finding_view(orphaned_sqli_node)
    assert view1["url"] == "http://localhost:3000/rest/user/login", view1["url"]
    assert view1["method"] == "GET", view1["method"]
    assert view1["category"] == "sqli", view1["category"]

    node_with_url = {
        "id": "v2",
        "vuln_type": "sqli",
        "url": "http://x/y",
        "evidence": json.dumps([{"url": "http://other/should-not-win"}]),
    }
    view2 = to_finding_view(node_with_url)
    assert view2["url"] == "http://x/y", view2["url"]

    node_no_cvss = {"id": "v3", "vuln_type": "xss", "severity": "high"}
    view3 = to_finding_view(node_no_cvss)
    assert view3["cvss_score"] == 7.5, view3["cvss_score"]

    # object input (attribute access, no .get) must coerce cleanly
    class _Obj:
        def __init__(self):
            self.id = "v4"
            self.vuln_type = "ssrf"
            self.severity = "high"
            self.evidence = [{"url": "http://obj/target"}]
    view4 = to_finding_view(_Obj())
    assert view4["url"] == "http://obj/target", view4["url"]
    assert view4["category"] == "ssrf", view4["category"]

    print("all asserts passed")
    print("view1:", view1)
    print("view2:", view2)
    print("view3:", view3)
