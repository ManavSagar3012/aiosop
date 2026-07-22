"""Unit tests for the OAST blind-vulnerability correlation registry.

Covers the two things the inline scan poll can't do: promoting a callback that
lands *after* the scan returned (late/slow path), and correlating multiple
probes hit by a single backend.
"""

import asyncio

from ai_osop.core.enums import VulnClass
from ai_osop.core.oast_correlation import OASTCorrelationRegistry, OASTProbe, build_findings


class FakeOASTServer:
    """Mimics the real OAST server: stores probe context against a token and
    echoes it back on cursor-based drain (the provenance-travels-with-the-hit
    contract that lets late callbacks be attributed)."""

    def __init__(self):
        self._tokens = {}  # token -> context
        self._interactions = []  # list of interaction dicts
        self._seq = 0
        self._minted = 0

    async def register(self, label="", context=None):
        self._minted += 1
        token = f"tok{self._minted}"
        self._tokens[token] = context or {}
        return token, f"http://oast.example/{token}"

    def fire(self, token, source_ip="9.9.9.9", method="GET"):
        """Simulate a target making the out-of-band callback."""
        self._seq += 1
        self._interactions.append(
            {
                "seq": self._seq,
                "interaction_id": f"i{self._seq}",
                "kind": "http",
                "token": token,
                "source_ip": source_ip,
                "method": method,
                "path": f"/{token}",
                "context": self._tokens.get(token, {}),
            }
        )

    async def drain(self, since=0, engagement_id=None):
        out = [
            i
            for i in self._interactions
            if i["seq"] > since
            and (not engagement_id or i["context"].get("engagement_id") == engagement_id)
        ]
        cursor = max([since] + [i["seq"] for i in out])
        return cursor, out


# ----------------------------- build_findings (pure) -----------------------------


def _interaction(seq, token, engagement="eng1", vclass="ssrf", src="9.9.9.9", injection="url"):
    return {
        "seq": seq,
        "token": token,
        "interaction_id": f"i{seq}",
        "kind": "http",
        "source_ip": src,
        "method": "GET",
        "path": f"/{token}",
        "context": {
            "engagement_id": engagement,
            "vuln_class": vclass,
            "injection_point": injection,
        },
    }


def test_build_findings_promotes_one_finding_per_token():
    res = build_findings([_interaction(1, "a"), _interaction(2, "a")])  # same token twice
    assert len(res.findings) == 1
    v = res.findings[0]
    assert v.vuln_type == VulnClass.SSRF and v.cwe == "CWE-918"
    assert v.validated is True and v.evidence[0]["token"] == "a"
    assert res.cursor == 2


def test_build_findings_ignores_interactions_without_provenance():
    stray = {"seq": 1, "token": "x", "source_ip": "1.2.3.4", "context": {}}
    res = build_findings([stray])
    assert res.findings == []


def test_build_findings_idempotent_with_promoted_tokens():
    ints = [_interaction(1, "a")]
    assert len(build_findings(ints).findings) == 1
    assert build_findings(ints, promoted_tokens={"a"}).findings == []


def test_build_findings_cross_probe_source_ip_correlation():
    ints = [_interaction(1, "a", src="5.5.5.5"), _interaction(2, "b", src="5.5.5.5", vclass="xxe")]
    res = build_findings(ints)
    assert len(res.findings) == 2
    assert len(res.correlations) == 1
    c = res.correlations[0]
    assert c["source_ip"] == "5.5.5.5" and c["tokens"] == ["a", "b"] and c["probe_count"] == 2


def test_build_findings_unknown_class_still_promotes():
    res = build_findings([_interaction(1, "a", vclass="totally-made-up")])
    assert len(res.findings) == 1
    assert res.findings[0].vuln_type == VulnClass.UNKNOWN  # coerced, still confirmed


# ----------------------------- registry (async) -----------------------------


def test_mint_probe_attaches_context_and_reconcile_promotes():
    async def run():
        server = FakeOASTServer()
        reg = OASTCorrelationRegistry(server)
        probe = await reg.mint_probe(
            engagement_id="engX",
            vuln_class=VulnClass.SSRF,
            injection_point="imageUrl",
            request_summary="POST https://t/fetch",
        )
        assert probe.token and probe.callback_url.endswith(probe.token)
        server.fire(probe.token, source_ip="10.1.1.1")
        res = await reg.reconcile()
        assert len(res.findings) == 1
        v = res.findings[0]
        assert v.engagement_id == "engX" and v.vuln_type == VulnClass.SSRF
        assert v.evidence[0]["injection"] == "imageUrl"

    asyncio.run(run())


def test_late_callback_is_promoted_after_scan_would_have_given_up():
    async def run():
        server = FakeOASTServer()
        reg = OASTCorrelationRegistry(server)
        probe = await reg.mint_probe(engagement_id="engL", vuln_class=VulnClass.RCE)
        # First reconcile finds nothing (callback hasn't fired -- inline poll window closed).
        assert (await reg.reconcile()).findings == []
        # Minutes later the blind callback lands.
        server.fire(probe.token, source_ip="10.2.2.2")
        res = await reg.reconcile()
        assert len(res.findings) == 1
        assert res.findings[0].vuln_type == VulnClass.RCE
        assert res.findings[0].severity.value == "critical"

    asyncio.run(run())


def test_reconcile_is_idempotent_across_passes():
    async def run():
        server = FakeOASTServer()
        reg = OASTCorrelationRegistry(server)
        probe = await reg.mint_probe(engagement_id="engI", vuln_class=VulnClass.SSRF)
        server.fire(probe.token)
        assert len((await reg.reconcile()).findings) == 1
        # A second reconcile must not re-promote the same token.
        assert (await reg.reconcile()).findings == []

    asyncio.run(run())


def test_reconcile_engagement_filter_and_cross_probe_cluster():
    async def run():
        server = FakeOASTServer()
        reg = OASTCorrelationRegistry(server)
        p1 = await reg.mint_probe(
            engagement_id="engC", vuln_class=VulnClass.SSRF, injection_point="url"
        )
        p2 = await reg.mint_probe(
            engagement_id="engC", vuln_class=VulnClass.XXE, injection_point="xml"
        )
        # One vulnerable backend reaches both callbacks from the same IP.
        server.fire(p1.token, source_ip="172.16.0.5")
        server.fire(p2.token, source_ip="172.16.0.5")
        res = await reg.reconcile(engagement_id="engC")
        assert len(res.findings) == 2
        assert len(res.correlations) == 1
        assert res.correlations[0]["probe_count"] == 2

    asyncio.run(run())
