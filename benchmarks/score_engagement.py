"""Score real platform findings against a ground-truth manifest.

WHY THIS EXISTS
    ``benchmarks/juiceshop/bench.py`` proves the *deterministic engines*
    (JWTTester, DifferentialAuthEngine, HTTP oracles) can validate Juice Shop
    weaknesses in isolation. It does NOT drive the orchestrator, scheduler,
    phase_monitor, graph persistence, or dedup — the exact layers where the
    correctness bugs live. So a 1.0/1.0 engine score says nothing about whether
    the *platform* finds real vulnerabilities when run end-to-end.

    This module closes that gap. It takes the findings a real engagement
    actually persisted (as ``Vulnerability`` records, or a JSON export of them)
    and scores them against a ground-truth manifest, emitting the metrics that
    tell you detection quality:

        precision, recall, false positives, false negatives, coverage,
        evidence completeness, plus a triage list of extra findings that are
        not in the manifest (neither credited nor penalised).

HONEST-GROUND-TRUTH POLICY
    A hand-written manifest is necessarily incomplete: a capable scanner will
    find real bugs the manifest never listed. Counting those as false positives
    would punish the platform for doing its job. So:

      * RECALL is measured over the manifest — it defines what MUST be found.
        A manifest entry with no matching finding is a false negative.
      * PRECISION is measured only against explicit negative controls
        (manifest entries with ``expected: false``). A finding that matches a
        negative control is a false positive. Precision is ``None`` when no
        negative controls are defined, rather than a fake 1.0.
      * Everything else the platform reported that does not map to any manifest
        entry is surfaced as ``extras`` for human triage — real-but-unlisted
        findings and genuine noise both land here, and conflating them into a
        precision number would be dishonest.

    Simulated/mock findings (``Vulnerability.is_simulated()``) are dropped
    before scoring: they must never count as a true positive.

USAGE
    # score a JSON export of findings
    python benchmarks/score_engagement.py \
        --findings run_findings.json \
        --manifest benchmarks/ground_truth/juice_shop.yaml \
        --out scorecard.json

    # or, programmatically, from live graph memory:
    from benchmarks.score_engagement import score_findings, load_manifest
    vulns = await graph_memory.get_vulnerabilities_by_engagement(eid)
    card = score_findings(vulns, load_manifest("benchmarks/ground_truth/juice_shop.yaml"))
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

try:
    import yaml
except ImportError:  # pragma: no cover - PyYAML is a project dependency
    yaml = None


# --------------------------------------------------------------------------- #
# Ground-truth type -> platform VulnClass value.
#
# Manifest ``type`` strings are human-friendly (SQLi, IDOR, JWT); persisted
# findings use the ``VulnClass`` enum *value* (sqli, idor, jwt_abuse). We match
# on a normalised alias set so a JWT ground-truth entry matches a jwt_abuse
# finding, an IDOR entry matches idor OR bola OR broken_access_control, etc.
# Keep this permissive on the "same underlying weakness" axis but never so loose
# that unrelated classes collide.
# --------------------------------------------------------------------------- #
_TYPE_ALIASES: Dict[str, set] = {
    "sqli": {"sqli", "sql_injection", "sqlinjection"},
    "xss": {"xss", "cross_site_scripting"},
    "idor": {"idor", "bola", "broken_access_control"},
    "jwt": {"jwt", "jwt_abuse", "jwt_forgery", "cryptographic_failures"},
    "massassignment": {"massassignment", "mass_assignment"},
    "ssrf": {"ssrf"},
    "ssti": {"ssti"},
    "csrf": {"csrf"},
    "rce": {"rce"},
    "exposed_secret": {"exposed_secret", "secrets", "information_disclosure"},
}


def _norm_type(raw: str) -> str:
    """Collapse a type string to its canonical alias-group key."""
    key = (raw or "").strip().lower().replace("-", "_").replace(" ", "")
    for canon, aliases in _TYPE_ALIASES.items():
        if key == canon or key in aliases:
            return canon
    return key


def _type_matches(gt_type: str, finding_type: str) -> bool:
    a = _norm_type(gt_type)
    b = _norm_type(finding_type)
    if a == b:
        return True
    # Cross-check alias groups so gt "jwt" matches finding "jwt_abuse", or an
    # IDOR ground-truth entry matches a broken_access_control finding.
    ga = _TYPE_ALIASES.get(a, {a})
    gb = _TYPE_ALIASES.get(b, {b})
    return bool(ga & gb) or a in gb or b in ga


def _endpoint_path(value: str) -> str:
    """Reduce an endpoint id/url to a comparable path.

    Findings store endpoint_id which may be a full URL, a path, or an opaque id.
    We compare on the URL path when parseable, else the raw lowercased string.
    """
    if not value:
        return ""
    v = str(value).strip()
    if "://" in v:
        v = urlparse(v).path
    return v.rstrip("/").lower()


def _endpoint_matches(gt_endpoint: str, finding_endpoint: str) -> bool:
    gt = _endpoint_path(gt_endpoint)
    fe = _endpoint_path(finding_endpoint)
    if not gt or not fe:
        # Endpoint unknown on one side: fall back to type-only match (caller
        # already requires a type match), so don't veto here.
        return True
    return gt == fe or gt in fe or fe in gt


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class GroundTruthEntry:
    id: str
    type: str
    endpoint: str = ""
    parameter: str = ""
    severity: str = ""
    expected: bool = True  # False => negative control
    expected_evidence: List[str] = field(default_factory=list)
    expected_report: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MatchedFinding:
    gt_id: str
    finding_id: str
    finding_type: str
    endpoint: str
    confidence: float
    evidence_kinds: List[str]
    evidence_complete: bool
    missing_evidence: List[str]


def load_manifest(path: str | Path) -> List[GroundTruthEntry]:
    if yaml is None:
        raise RuntimeError("PyYAML is required to load the ground-truth manifest")
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or []
    if not isinstance(data, list):
        raise ValueError(f"manifest must be a YAML list, got {type(data).__name__}")
    entries: List[GroundTruthEntry] = []
    for row in data:
        entries.append(
            GroundTruthEntry(
                id=str(row.get("id", "")),
                type=str(row.get("type", "")),
                endpoint=str(row.get("endpoint", "")),
                parameter=str(row.get("parameter", "")),
                severity=str(row.get("severity", "")),
                # default True: a manifest entry is an expected finding unless it
                # explicitly declares itself a negative control.
                expected=bool(row.get("expected", True)),
                expected_evidence=list(row.get("expected_evidence", []) or []),
                expected_report=list(row.get("expected_report", []) or []),
                raw=row,
            )
        )
    return entries


# --------------------------------------------------------------------------- #
# Finding normalisation — accept either Vulnerability model instances or plain
# dicts (JSON export / graph_memory rows). We never import the model here so the
# scorer stays usable without the full platform installed; we duck-type instead.
# --------------------------------------------------------------------------- #
def _finding_field(f: Any, *names: str, default: Any = None) -> Any:
    for n in names:
        if isinstance(f, dict):
            if n in f and f[n] is not None:
                return f[n]
        else:
            v = getattr(f, n, None)
            if v is not None:
                return v
    return default


def _finding_type_str(f: Any) -> str:
    vt = _finding_field(f, "vuln_type", "type", "vuln_class", default="")
    # enum -> its .value; str stays as-is
    return getattr(vt, "value", vt) if vt is not None else ""


def _finding_is_simulated(f: Any) -> bool:
    # Prefer the model's own authoritative check.
    if hasattr(f, "is_simulated"):
        try:
            return bool(f.is_simulated())
        except Exception:
            pass
    src = str(_finding_field(f, "tool_source", "tool", default="")).lower()
    if "mock" in src or src.endswith("-sim") or "simulated" in src:
        return True
    title = str(_finding_field(f, "title", default="")).lower()
    if "(simulated)" in title:
        return True
    for ev in _finding_field(f, "evidence", default=[]) or []:
        if isinstance(ev, dict) and str(ev.get("provenance", "")).lower() == "simulated":
            return True
    return False


def _evidence_kinds(f: Any) -> List[str]:
    """Collect the evidence 'kinds' present on a finding.

    Manifest expects tokens like request/response/payload/token/diff. Evidence
    entries are dicts that may carry those either as a ``type`` value or as keys.
    We union both so a {"request": ...} dict and a {"type": "request"} dict both
    register the 'request' kind.
    """
    kinds: set = set()
    for ev in _finding_field(f, "evidence", default=[]) or []:
        if not isinstance(ev, dict):
            continue
        t = str(ev.get("type", "")).lower()
        if t:
            kinds.add(t)
        for k in ev.keys():
            kinds.add(str(k).lower())
    return sorted(kinds)


def _evidence_complete(expected: List[str], present: Iterable[str]) -> Tuple[bool, List[str]]:
    present_set = {p.lower() for p in present}
    missing = [e for e in expected if e.lower() not in present_set]
    return (len(missing) == 0, missing)


# --------------------------------------------------------------------------- #
# Core scoring
# --------------------------------------------------------------------------- #
def score_findings(
    findings: Iterable[Any],
    manifest: List[GroundTruthEntry],
) -> Dict[str, Any]:
    """Score a set of platform findings against a ground-truth manifest.

    Returns a JSON-serialisable scorecard dict.
    """
    all_findings = list(findings)
    simulated = [f for f in all_findings if _finding_is_simulated(f)]
    real = [f for f in all_findings if not _finding_is_simulated(f)]

    positives = [g for g in manifest if g.expected]
    negatives = [g for g in manifest if not g.expected]

    matched: List[MatchedFinding] = []
    matched_finding_ids: set = set()
    false_negatives: List[Dict[str, Any]] = []

    # Greedy match: each ground-truth positive claims the best real finding of a
    # matching type+endpoint that hasn't already been claimed. Highest-confidence
    # finding wins so a weak duplicate can't shadow a strong match.
    def _finding_id(f: Any, idx: int) -> str:
        return str(_finding_field(f, "id", default=f"finding-{idx}"))

    indexed = list(enumerate(real))

    for g in positives:
        candidates = []
        for idx, f in indexed:
            fid = _finding_id(f, idx)
            if fid in matched_finding_ids:
                continue
            ftype = _finding_type_str(f)
            if not _type_matches(g.type, ftype):
                continue
            fendpoint = str(
                _finding_field(f, "endpoint_id", "endpoint", "url", default="")
            )
            if not _endpoint_matches(g.endpoint, fendpoint):
                continue
            conf = float(_finding_field(f, "confidence", default=0.0) or 0.0)
            candidates.append((conf, idx, f, fid, fendpoint))
        if not candidates:
            false_negatives.append(
                {"gt_id": g.id, "type": g.type, "endpoint": g.endpoint, "severity": g.severity}
            )
            continue
        candidates.sort(key=lambda c: c[0], reverse=True)
        conf, idx, f, fid, fendpoint = candidates[0]
        matched_finding_ids.add(fid)
        kinds = _evidence_kinds(f)
        complete, missing = _evidence_complete(g.expected_evidence, kinds)
        matched.append(
            MatchedFinding(
                gt_id=g.id,
                finding_id=fid,
                finding_type=_finding_type_str(f),
                endpoint=fendpoint,
                confidence=conf,
                evidence_kinds=kinds,
                evidence_complete=complete,
                missing_evidence=missing,
            )
        )

    # Negative controls: a real finding matching one is a false positive.
    false_positives: List[Dict[str, Any]] = []
    for g in negatives:
        for idx, f in indexed:
            fid = _finding_id(f, idx)
            if fid in matched_finding_ids:
                continue
            if not _type_matches(g.type, _finding_type_str(f)):
                continue
            fendpoint = str(_finding_field(f, "endpoint_id", "endpoint", "url", default=""))
            if _endpoint_matches(g.endpoint, fendpoint):
                false_positives.append(
                    {"gt_id": g.id, "finding_id": fid, "type": g.type, "endpoint": fendpoint}
                )
                matched_finding_ids.add(fid)

    # Extras: real findings that mapped to no manifest entry. Neither credited
    # nor penalised — surfaced for human triage.
    extras: List[Dict[str, Any]] = []
    for idx, f in indexed:
        fid = _finding_id(f, idx)
        if fid in matched_finding_ids:
            continue
        extras.append(
            {
                "finding_id": fid,
                "type": _finding_type_str(f),
                "endpoint": str(_finding_field(f, "endpoint_id", "endpoint", "url", default="")),
                "confidence": float(_finding_field(f, "confidence", default=0.0) or 0.0),
                "severity": str(
                    getattr(_finding_field(f, "severity", default=""), "value", "")
                    or _finding_field(f, "severity", default="")
                ),
            }
        )

    tp = len(matched)
    fn = len(false_negatives)
    fp = len(false_positives)

    recall = tp / (tp + fn) if (tp + fn) else None
    # Precision only meaningful against negative controls.
    precision = (tp / (tp + fp)) if (fp or negatives) and (tp + fp) else None
    coverage = tp / len(positives) if positives else None
    evidence_complete_count = sum(1 for m in matched if m.evidence_complete)
    evidence_completeness = evidence_complete_count / tp if tp else None

    return {
        "summary": {
            "manifest_positives": len(positives),
            "manifest_negative_controls": len(negatives),
            "findings_total": len(all_findings),
            "findings_real": len(real),
            "findings_simulated_dropped": len(simulated),
            "true_positives": tp,
            "false_negatives": fn,
            "false_positives": fp,
            "extras_for_triage": len(extras),
            "precision": precision,
            "recall": recall,
            "coverage": coverage,
            "evidence_completeness": evidence_completeness,
        },
        "matched": [m.__dict__ for m in matched],
        "false_negatives": false_negatives,
        "false_positives": false_positives,
        "extras": extras,
        "notes": [
            "recall measured over manifest positives (what MUST be found).",
            "precision measured only against explicit negative controls; "
            "None means no negative controls were defined.",
            "extras are findings unmapped to any manifest entry — triage manually, "
            "not counted as false positives.",
            "simulated/mock findings dropped before scoring.",
        ],
    }


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _load_findings_json(path: str | Path) -> List[Any]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        # tolerate {"findings": [...]} or {"vulnerabilities": [...]}
        for key in ("findings", "vulnerabilities", "vulns", "data"):
            if isinstance(raw.get(key), list):
                return raw[key]
        raise ValueError("findings JSON object has no findings/vulnerabilities list")
    if isinstance(raw, list):
        return raw
    raise ValueError(f"findings JSON must be list or object, got {type(raw).__name__}")


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--findings", required=True, help="JSON file of persisted findings")
    ap.add_argument(
        "--manifest",
        default="benchmarks/ground_truth/juice_shop.yaml",
        help="ground-truth YAML manifest",
    )
    ap.add_argument("--out", default=None, help="write scorecard JSON here (else stdout)")
    ap.add_argument(
        "--min-recall", type=float, default=None, help="exit 1 if recall below this"
    )
    ap.add_argument(
        "--max-fp", type=int, default=None, help="exit 1 if false positives exceed this"
    )
    args = ap.parse_args(argv)

    manifest = load_manifest(args.manifest)
    findings = _load_findings_json(args.findings)
    card = score_findings(findings, manifest)

    out_text = json.dumps(card, indent=2, default=str)
    if args.out:
        Path(args.out).write_text(out_text, encoding="utf-8")
        s = card["summary"]
        print(
            f"scorecard -> {args.out}  "
            f"recall={s['recall']} precision={s['precision']} "
            f"TP={s['true_positives']} FN={s['false_negatives']} FP={s['false_positives']} "
            f"extras={s['extras_for_triage']}"
        )
    else:
        print(out_text)

    s = card["summary"]
    if args.min_recall is not None and (s["recall"] is None or s["recall"] < args.min_recall):
        print(f"GATE FAIL: recall {s['recall']} < {args.min_recall}", file=sys.stderr)
        return 1
    if args.max_fp is not None and s["false_positives"] > args.max_fp:
        print(f"GATE FAIL: FP {s['false_positives']} > {args.max_fp}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
