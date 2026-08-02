"""Tests for Sprint 2 — Escalation Engine + Chain Composer + Auto-PoC Generator."""

import pytest

from ai_osop.core.chain_composer import ChainComposer
from ai_osop.core.escalation_engine import EscalationEngine
from ai_osop.core.models import (
    AttackChain,
    ChainStatus,
    EvidencePackage,
    PrimitiveLedger,
    PrimitiveType,
)

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _prim(
    primitive_type=PrimitiveType.NUCLEI_SIGNAL,
    confidence=0.75,
    target="http://example.com/vuln",
    severity_hint="high",
    raw=None,
    tags=None,
    **kw,
):
    return PrimitiveLedger(
        primitive_type=primitive_type,
        engagement_id="eng-test",
        source="test",
        dedup_key=f"dk-{primitive_type.value}-test",
        target=target,
        confidence=confidence,
        severity_hint=severity_hint,
        raw=raw or {},
        tags=tags or [],
        **kw,
    )


# --------------------------------------------------------------------------
# Escalation Engine Tests
# --------------------------------------------------------------------------


class TestEscalationEngine:
    def test_nuclei_signal_produces_escalation(self):
        engine = EscalationEngine()
        prim = _prim(PrimitiveType.NUCLEI_SIGNAL)
        paths = engine.escalate(prim)
        assert len(paths) >= 1
        techniques = [p.suggested_technique for p in paths]
        assert any("nuclei" in t or "active" in t.lower() for t in techniques)

    def test_auth_signal_routes_to_diff_auth(self):
        engine = EscalationEngine()
        prim = _prim(PrimitiveType.AUTH_SIGNAL)
        paths = engine.escalate(prim)
        assert any(
            "diff" in p.suggested_technique.lower() or "auth" in p.suggested_technique.lower()
            for p in paths
        )

    def test_ssrf_hint_routes_to_oast(self):
        engine = EscalationEngine()
        prim = _prim(PrimitiveType.SSRF_HINT)
        paths = engine.escalate(prim)
        techniques = [p.suggested_technique for p in paths]
        assert any("oast" in t or "ssrf" in t for t in techniques)

    def test_idor_hint_routes_to_cross_account(self):
        engine = EscalationEngine()
        prim = _prim(PrimitiveType.IDOR_HINT)
        paths = engine.escalate(prim)
        assert any(
            "idor" in p.suggested_technique.lower() or "cross" in p.suggested_technique.lower()
            for p in paths
        )

    def test_js_secret_routes_to_liveness(self):
        engine = EscalationEngine()
        prim = _prim(PrimitiveType.JS_SECRET)
        paths = engine.escalate(prim)
        assert any(
            "secret" in p.suggested_technique.lower() or "liveness" in p.suggested_technique.lower()
            for p in paths
        )

    def test_never_returns_empty_paths(self):
        """Principle: never stop at a signal — always at least one path."""
        engine = EscalationEngine()
        for pt in PrimitiveType:
            prim = _prim(pt)
            paths = engine.escalate(prim)
            assert len(paths) >= 1, f"No escalation path for {pt.value}"

    def test_each_path_has_required_fields(self):
        engine = EscalationEngine()
        prim = _prim(PrimitiveType.NUCLEI_SIGNAL)
        paths = engine.escalate(prim)
        for path in paths:
            assert path.source_primitive_id == prim.id
            assert path.suggested_technique
            assert path.reason
            assert 0.0 <= path.confidence <= 1.0
            assert path.engagement_id == "eng-test"

    def test_high_severity_nuclei_gets_capture_path(self):
        engine = EscalationEngine()
        prim = _prim(PrimitiveType.NUCLEI_SIGNAL, severity_hint="critical")
        paths = engine.escalate(prim)
        # Should include HTTP capture path for critical signals
        assert len(paths) >= 2


# --------------------------------------------------------------------------
# Chain Composer Tests
# --------------------------------------------------------------------------


class TestChainComposer:
    def test_compose_basic_chain(self):
        composer = ChainComposer()
        primitives = [
            _prim(PrimitiveType.NUCLEI_SIGNAL, confidence=0.80),
            _prim(PrimitiveType.ENDPOINT_OBSERVED, confidence=0.70),
        ]
        chain = composer.compose(primitives)
        assert chain.id.startswith("chain-")
        assert chain.status == ChainStatus.BUILDING
        assert len(chain.primitive_ids) == 2

    def test_compose_derives_title_when_empty(self):
        composer = ChainComposer()
        primitives = [_prim(PrimitiveType.NUCLEI_SIGNAL, target="http://target.com")]
        chain = composer.compose(primitives)
        assert "nuclei_signal" in chain.title.lower() or "chain" in chain.title.lower()

    def test_compose_uses_max_severity(self):
        composer = ChainComposer()
        primitives = [
            _prim(PrimitiveType.NUCLEI_SIGNAL, severity_hint="info", confidence=0.70),
            _prim(PrimitiveType.AUTH_SIGNAL, severity_hint="critical", confidence=0.80),
        ]
        chain = composer.compose(primitives)
        assert chain.severity == "critical"

    def test_compose_confidence_weakest_link(self):
        """Chain confidence must not exceed the minimum member confidence."""
        composer = ChainComposer()
        primitives = [
            _prim(PrimitiveType.NUCLEI_SIGNAL, confidence=0.90),
            _prim(PrimitiveType.ENDPOINT_OBSERVED, confidence=0.40),
        ]
        chain = composer.compose(primitives)
        assert chain.confidence <= 0.40

    def test_compose_raises_on_empty_list(self):
        composer = ChainComposer()
        with pytest.raises(ValueError, match="zero primitives"):
            composer.compose([])

    def test_generate_poc_nuclei(self):
        composer = ChainComposer()
        prim = _prim(
            PrimitiveType.NUCLEI_SIGNAL,
            raw={"template_id": "cve-2024-1234"},
            target="http://vuln.example.com",
        )
        chain = composer.compose([prim])
        chain = composer.generate_poc(chain, [prim])
        assert "nuclei" in chain.poc_script[0]
        assert "cve-2024-1234" in " ".join(chain.poc_script)

    def test_generate_poc_diff_auth(self):
        composer = ChainComposer()
        prim = _prim(
            PrimitiveType.IDOR_HINT,
            raw={"victim_cookie": "abc", "attacker_cookie": "xyz"},
            target="http://api.example.com/resource/1",
        )
        chain = composer.compose([prim])
        chain = composer.generate_poc(chain, [prim])
        assert len(chain.poc_script) > 0
        poc_str = " ".join(chain.poc_script)
        assert "abc" in poc_str and "xyz" in poc_str

    def test_generate_poc_empty_target_leaves_poc_empty(self):
        composer = ChainComposer()
        prim = _prim(PrimitiveType.NUCLEI_SIGNAL, target="", raw={})
        chain = composer.compose([prim])
        chain = composer.generate_poc(chain, [prim])
        # Can't build a PoC without a target
        assert chain.poc_script == []
        assert chain.status == ChainStatus.PENDING_POC

    def test_generate_poc_sets_pending_poc_status(self):
        composer = ChainComposer()
        prim = _prim(PrimitiveType.NUCLEI_SIGNAL, raw={"template_id": "t-1"})
        chain = composer.compose([prim])
        chain = composer.generate_poc(chain, [prim])
        assert chain.status == ChainStatus.PENDING_POC

    def test_build_evidence_package_includes_replay_script(self):
        composer = ChainComposer()
        prim = _prim(
            PrimitiveType.NUCLEI_SIGNAL,
            raw={
                "template_id": "sqli-1",
                "request": {"method": "GET", "url": "http://x.com"},
                "response": {"status_code": 200},
            },
            target="http://x.com",
        )
        chain = composer.compose([prim])
        chain = composer.generate_poc(chain, [prim])
        pkg = composer.build_evidence_package(chain, [prim])
        assert isinstance(pkg, EvidencePackage)
        assert pkg.replay_script == chain.poc_script
        assert len(pkg.raw_requests) >= 1
        assert len(pkg.raw_responses) >= 1

    def test_build_evidence_package_no_data_gives_empty_lists(self):
        composer = ChainComposer()
        prim = _prim(PrimitiveType.GENERIC, raw={})
        chain = composer.compose([prim])
        chain = composer.generate_poc(chain, [prim])
        pkg = composer.build_evidence_package(chain, [prim])
        assert pkg.raw_requests == []
        assert pkg.raw_responses == []


# --------------------------------------------------------------------------
# Integration: Escalate → Compose → Gate
# --------------------------------------------------------------------------


class TestEndToEndChainPipeline:
    def test_nuclei_signal_full_pipeline(self):
        """Integration test: signal → escalate → compose → PoC → triage."""
        from ai_osop.core.models import TriageVerdict
        from ai_osop.core.triager_gate import TriagerGate

        engine = EscalationEngine()
        composer = ChainComposer()
        gate = TriagerGate()

        # Step 1: raw Primitive from Nuclei
        prim = _prim(
            PrimitiveType.NUCLEI_SIGNAL,
            confidence=0.85,
            severity_hint="high",
            raw={
                "template_id": "apache-log4j-rce",
                "request": {"method": "GET", "url": "http://vuln.example.com"},
                "response": {"status_code": 200, "body": "JNDI:ldap"},
            },
            target="http://vuln.example.com",
        )

        # Step 2: escalate (shows next steps; we skip actual execution here)
        paths = engine.escalate(prim)
        assert len(paths) >= 1

        # Step 3: compose chain from primitives
        chain = composer.compose([prim], title="Log4Shell RCE via nuclei signal")
        assert chain.id.startswith("chain-")

        # Step 4: generate PoC
        chain = composer.generate_poc(chain, [prim])
        assert "nuclei" in chain.poc_script[0]

        # Step 5: build evidence package
        pkg = composer.build_evidence_package(chain, [prim])
        assert pkg.replay_script == chain.poc_script

        # Step 6: run through triage gate
        report = gate.evaluate(prim, chain=chain, evidence=pkg)
        # High confidence + evidence + PoC → EMIT
        assert report.verdict == TriageVerdict.EMIT
