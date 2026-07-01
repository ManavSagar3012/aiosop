"""OAST blind-vulnerability correlation registry.

Ties every out-of-band correlation token to the probe that minted it
(engagement, vuln class, injection point, payload, triggering request) and
reconciles captured callbacks back into findings -- including callbacks that
land *after* the injecting scan's inline poll window has already closed.

The provenance travels *with* the interaction: the OAST server echoes each
token's stored context back on ``oast_drain``, so :func:`build_findings` can
reconstruct a :class:`Vulnerability` from a drained interaction alone, without
needing the in-process probe map. That is what lets the slow-path reconciler
promote a blind finding minutes or hours later -- or even after a restart of
the process that originally injected the payload.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

import structlog
from pydantic import BaseModel, Field

from ai_osop.core.config import Severity, VulnClass
from ai_osop.core.models import Observation, Vulnerability

logger = structlog.get_logger(__name__)


# CWE + default severity per blind class we can confirm out-of-band. Anything
# not listed still promotes (as SSRF-style HIGH) because a captured callback is
# ground truth regardless of how we classified the probe.
_CLASS_META = {
    VulnClass.SSRF: ("CWE-918", Severity.HIGH),
    VulnClass.XSS: ("CWE-79", Severity.MEDIUM),
    VulnClass.RCE: ("CWE-77", Severity.CRITICAL),
    VulnClass.XXE: ("CWE-611", Severity.HIGH),
    VulnClass.SQLI: ("CWE-89", Severity.HIGH),
    VulnClass.SSTI: ("CWE-1336", Severity.HIGH),
}
_DEFAULT_META = ("CWE-918", Severity.HIGH)


def _coerce_class(value: Any) -> VulnClass:
    try:
        return VulnClass(str(value).lower())
    except ValueError:
        return VulnClass.UNKNOWN


class OASTProbe(BaseModel):
    """A minted OAST token plus the provenance of the probe that used it."""

    token: str = ""
    callback_url: str = ""
    engagement_id: str
    vuln_class: VulnClass = VulnClass.UNKNOWN
    injection_point: str = ""     # param name or body field the callback went into
    payload: str = ""             # what we injected (usually the callback URL)
    request_summary: str = ""     # method + URL that triggered the sink
    source_agent_id: str = ""
    label: str = ""
    created_at: datetime = Field(default_factory=datetime.utcnow)

    def to_context(self) -> Dict[str, Any]:
        """The dict handed to the OAST server so it can echo provenance back."""
        return {
            "engagement_id": self.engagement_id,
            "vuln_class": self.vuln_class.value,
            "injection_point": self.injection_point,
            "payload": self.payload,
            "request_summary": self.request_summary,
            "source_agent_id": self.source_agent_id,
            "label": self.label,
        }


@dataclass
class ReconcileResult:
    """Outcome of a reconcile pass over drained OAST interactions."""

    cursor: int = 0
    findings: List[Vulnerability] = field(default_factory=list)
    observations: List[Observation] = field(default_factory=list)
    # Each entry: {"source_ip": str, "tokens": [str, ...], "probe_count": int}
    correlations: List[Dict[str, Any]] = field(default_factory=list)


def _finding_from_interaction(interaction: Dict[str, Any]) -> Optional[Vulnerability]:
    """Reconstruct a confirmed blind finding from one drained interaction.

    Returns None when the interaction lacks the provenance needed to attribute
    it to an engagement (e.g. a stray hit on an expired/unknown token).
    """
    ctx = interaction.get("context") or {}
    engagement_id = ctx.get("engagement_id")
    if not engagement_id:
        return None
    vclass = _coerce_class(ctx.get("vuln_class"))
    cwe, severity = _CLASS_META.get(vclass, _DEFAULT_META)
    injection = ctx.get("injection_point") or "parameter"
    source_ip = interaction.get("source_ip", "")
    return Vulnerability(
        cwe=cwe,
        vuln_type=vclass,
        severity=severity,
        title=f"Blind {vclass.value.upper()} via {injection} (out-of-band confirmed)",
        description=(
            f"An out-of-band callback was captured at the OAST server "
            f"(source {source_ip}, method {interaction.get('method')}, "
            f"path {interaction.get('path')}), proving a blind {vclass.value.upper()} "
            f"through injection point '{injection}'. "
            f"Triggering request: {ctx.get('request_summary') or 'n/a'}."
        ),
        evidence=[{
            "type": "oast_callback",
            "provenance": "oast",
            "token": interaction.get("token"),
            "interaction_id": interaction.get("interaction_id"),
            "injection": injection,
            "payload": ctx.get("payload"),
            "interaction": interaction,
        }],
        tool_source="oast_reconciler",
        confidence=0.97,
        validated=True,
        exploitability="high",
        impact=severity.value,
        engagement_id=engagement_id,
    )


def _observation_from_interaction(interaction: Dict[str, Any]) -> Optional[Observation]:
    """A coordination-bus observation for one callback (feeds correlation)."""
    ctx = interaction.get("context") or {}
    engagement_id = ctx.get("engagement_id")
    if not engagement_id:
        return None
    return Observation(
        type="oast_callback",
        source_agent_id=ctx.get("source_agent_id") or "oast-reconciler",
        target_id=ctx.get("injection_point") or interaction.get("token", ""),
        data={
            "token": interaction.get("token"),
            "source_ip": interaction.get("source_ip", ""),
            "vuln_class": ctx.get("vuln_class"),
            "interaction_id": interaction.get("interaction_id"),
        },
        confidence=0.97,
        provenance="oast",
        engagement_id=engagement_id,
    )


def build_findings(
    interactions: List[Dict[str, Any]],
    *,
    promoted_tokens: Optional[Set[str]] = None,
) -> ReconcileResult:
    """Pure: turn drained interactions into findings + correlations.

    - One finding per token -- the first captured callback confirms the vuln;
      further callbacks on the same token are correlation signal, not new bugs.
    - ``promoted_tokens`` suppresses tokens already turned into findings on an
      earlier pass, so reconciling repeatedly is idempotent.
    - Cross-probe correlation: a single ``source_ip`` hitting two or more
      distinct tokens indicates one vulnerable backend reached through several
      injection points -- worth surfacing as a correlated cluster.
    """
    promoted: Set[str] = set(promoted_tokens or set())
    result = ReconcileResult()
    by_source_ip: Dict[str, Set[str]] = {}
    max_seq = 0

    for it in interactions:
        max_seq = max(max_seq, int(it.get("seq", 0) or 0))
        token = it.get("token", "")
        src = it.get("source_ip", "")
        if src and token:
            by_source_ip.setdefault(src, set()).add(token)
        if not token or token in promoted:
            continue
        vuln = _finding_from_interaction(it)
        if vuln is None:
            continue
        promoted.add(token)
        result.findings.append(vuln)
        obs = _observation_from_interaction(it)
        if obs is not None:
            result.observations.append(obs)

    for src, tokens in by_source_ip.items():
        if len(tokens) >= 2:
            result.correlations.append(
                {"source_ip": src, "tokens": sorted(tokens), "probe_count": len(tokens)}
            )
    result.cursor = max_seq
    return result


class OASTCorrelationRegistry:
    """Mints provenance-carrying OAST probes and reconciles their callbacks.

    Scanners call :meth:`mint_probe` instead of ``oast.register`` directly, so
    the injection provenance is attached to the token at the source. A
    background reconciler (or a test) calls :meth:`reconcile` to drain callbacks
    and promote blind findings -- including late ones the inline scan poll
    missed. The registry is deliberately dependency-light: it needs only an
    object exposing ``register(label, context)`` and ``drain(since, ...)``
    (the :class:`~ai_osop.adapters.oast_mcp.OASTAdapter` contract).
    """

    def __init__(self, oast_adapter: Any):
        self.oast = oast_adapter
        self._probes: Dict[str, OASTProbe] = {}
        self._cursor: int = 0
        self._promoted_tokens: Set[str] = set()

    async def mint_probe(
        self,
        *,
        engagement_id: str,
        vuln_class: Any,
        injection_point: str = "",
        payload: str = "",
        request_summary: str = "",
        source_agent_id: str = "",
        label: str = "",
    ) -> OASTProbe:
        """Mint a token carrying full probe provenance; returns the probe."""
        vclass = vuln_class if isinstance(vuln_class, VulnClass) else _coerce_class(vuln_class)
        probe = OASTProbe(
            engagement_id=engagement_id,
            vuln_class=vclass,
            injection_point=injection_point,
            payload=payload,
            request_summary=request_summary,
            source_agent_id=source_agent_id,
            label=label or f"{vclass.value}:{injection_point}",
        )
        token, callback_url = await self.oast.register(
            label=probe.label, context=probe.to_context()
        )
        probe.token = token
        probe.callback_url = callback_url
        if token:
            self._probes[token] = probe
        logger.info(
            "oast_probe_minted", token=token, vuln_class=vclass.value,
            injection=injection_point, engagement_id=engagement_id,
        )
        return probe

    def get_probe(self, token: str) -> Optional[OASTProbe]:
        return self._probes.get(token)

    async def reconcile(self, engagement_id: Optional[str] = None) -> ReconcileResult:
        """Drain fresh callbacks and promote blind findings (slow path).

        Idempotent across calls: it pages from the last cursor and never
        re-promotes a token it has already turned into a finding.
        """
        cursor, interactions = await self.oast.drain(
            since=self._cursor, engagement_id=engagement_id
        )
        result = build_findings(interactions, promoted_tokens=self._promoted_tokens)
        for vuln in result.findings:
            if vuln.evidence and vuln.evidence[0].get("token"):
                self._promoted_tokens.add(vuln.evidence[0]["token"])
        self._cursor = max(self._cursor, int(cursor or 0), result.cursor)
        result.cursor = self._cursor
        if result.findings or result.correlations:
            logger.info(
                "oast_reconcile_promoted", count=len(result.findings),
                correlations=len(result.correlations), cursor=self._cursor,
            )
        return result
