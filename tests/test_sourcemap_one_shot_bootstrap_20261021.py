"""SourceMap first-use bootstrap cycle regression, not a live bootstrap.

Current production wiring cannot bootstrap safely:

* OriginalSourceMapHostCoordinator.coordinate() demands a signed current
  supervisor-source + kernel-attested RO native mount BEFORE sole 0035 issue.
* SourceMapSupervisorSourceIssuer.issue() demands a fresh central signed STATUS.
* SourceMapStatusAuthorityStore requires a COMMITTED original 0035 preflight
  before it can sign current STATUS. A caller-signed placeholder is not valid.

A safe optional two-phase path needs a separately authenticated, independent
current original 0027/ROE read-only precheck plus a registered host-only
post-issue callback to obtain and verify 0035 STATUS, exact 0033 current DB
CAS, live PID process witness, supervisor source, and kernel mount. There is
no existing protected precheck/callback contract; these tests deliberately
do NOT mint it or relax the coordinator. No DB/Docker/targets/network used.
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import os
import sys
import types
from pathlib import Path
from typing import Any

import pytest


ROOT = Path(__file__).resolve().parent
PROJECT = ROOT.parent
FIXTURE = ROOT / "test_sourcemap_original_host_coordinator_20261021.py"


@pytest.fixture
def cycle(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, Any]:
    spec = importlib.util.spec_from_file_location("sourcemap_coordinator_cycle_fixture", FIXTURE)
    assert spec is not None and spec.loader is not None
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    scoped = fixture.modules.__wrapped__(monkeypatch)
    imports = next(scoped)
    context = fixture.context.__wrapped__(imports, tmp_path, monkeypatch)
    try:
        yield {"fixture": fixture, "context": context, "coordinator": imports[1]}
    finally:
        scoped.close()


@pytest.mark.skipif(os.name != "posix", reason="one-shot journal requires POSIX stage")
def test_no_first_0035_without_independent_supervisor_status_and_mount(
    cycle: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = cycle["context"]
    ft = cycle["fixture"]
    co = ft._setup_coordinator(ctx)
    calls = ft._http_stub(ctx, monkeypatch)

    class NeverStage:
        async def provision(self, **_kwargs: Any) -> None:
            raise AssertionError("No original bytes may be published")

    co._provisioner = NeverStage()
    for absent in ({}, {"read_only": True}, {"status_id": "caller-minted"}):
        with pytest.raises(ctx["mod"].SourceMapHostCoordinationDenied):
            asyncio.run(
                co.coordinate(
                    original_action_request=dict(ft.REQUEST),
                    signed_supervisor_source=absent,
                )
            )
    assert calls == []
    assert not list(ctx["root"].glob(".issuer-*.used"))
    assert not (ctx["root"] / (ft.DIGEST + ".map")).exists()


@pytest.mark.skipif(os.name != "posix", reason="one-shot journal requires POSIX stage")
def test_post_0035_kernel_attestation_failure_consumes_issuance_without_publish(
    cycle: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Even valid signed original 0035 receipt is no right to publish bytes."""
    ctx = cycle["context"]
    ft = cycle["fixture"]
    co = ft._setup_coordinator(ctx)
    issuer_posts = ft._http_stub(ctx, monkeypatch)
    observations: list[int] = []
    original_observe = co._observer.observe

    def abort_second(source: Any) -> dict[str, Any]:
        observations.append(len(observations) + 1)
        if len(observations) >= 2:
            raise RuntimeError("mount/lease/PID no longer current after 0035 receipt")
        return original_observe(source)

    monkeypatch.setattr(co._observer, "observe", abort_second)

    class NeverStage:
        async def provision(self, **_kwargs: Any) -> None:
            raise AssertionError("Must not stage after lost native source")

    co._provisioner = NeverStage()
    with pytest.raises(ctx["mod"].SourceMapHostCoordinationDenied):
        asyncio.run(
            co.coordinate(
                original_action_request=dict(ft.REQUEST),
                signed_supervisor_source=ctx["supervisor_source"],
            )
        )
    assert observations == [1, 2]
    assert issuer_posts == [ft.REQUEST]
    assert not (ctx["root"] / (ft.DIGEST + ".map")).exists()
    journal = ".issuer-" + hashlib.sha256(ft.REQUEST["request_id"].encode()).hexdigest() + ".used"
    assert (ctx["root"] / journal).is_file()

    # A restart cannot send another central request after the protected local
    # tombstone was durably committed, even if a fresh mount later reappears.
    restarted = ft._setup_coordinator(ctx)
    restarted._provisioner = NeverStage()
    with pytest.raises(ctx["mod"].SourceMapHostCoordinationDenied):
        asyncio.run(
            restarted.coordinate(
                original_action_request=dict(ft.REQUEST),
                signed_supervisor_source=ctx["supervisor_source"],
            )
        )
    assert issuer_posts == [ft.REQUEST]
    assert not (ctx["root"] / (ft.DIGEST + ".map")).exists()


def test_current_status_requires_committed_0035_preflight_without_app_database(
    cycle: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Invoke the REAL status store's non-consuming committed-row verifier.

    Stub only import-time dependencies; no SQL query is made. The verifier
    itself comes unmodified from sourcemap_status_authority.py.
    """
    ctx = cycle["context"]
    stage = ctx["stage"]
    memory = types.ModuleType("ai_osop.memory")
    memory.__path__ = [str(PROJECT / "src" / "ai_osop" / "memory")]
    monkeypatch.setitem(sys.modules, "ai_osop.memory", memory)
    sql = types.ModuleType("sqlalchemy")
    sql.text = lambda statement: statement
    monkeypatch.setitem(sys.modules, "sqlalchemy", sql)
    action = types.ModuleType("ai_osop.memory.flow_mcp_action_dispatch")
    action.FlowMCPActionStore = type("FlowMCPActionStore", (), {})
    action.MCPActionDenied = type("MCPActionDenied", (ValueError,), {})
    monkeypatch.setitem(sys.modules, action.__name__, action)
    source = types.ModuleType("ai_osop.memory.sourcemap_source_authority")
    source.CLAIM_FIELDS = stage._SOURCE_FIELDS

    class Denied(ValueError):
        pass

    def deny(*_args: Any) -> None:
        raise Denied("Current original status preflight unavailable")

    source.SourceMapSourceAuthorityStore = type("SourceMapSourceAuthorityStore", (), {})
    source.SourceMapSourceDenied = Denied
    source._deny = deny
    source.canonical = stage._canonical
    source.signer = lambda: (_ for _ in ()).throw(Denied("No issuer"))
    source.validate_request = lambda _: deny()
    monkeypatch.setitem(sys.modules, source.__name__, source)
    module_name = "ai_osop.memory.sourcemap_status_authority"
    spec = importlib.util.spec_from_file_location(
        module_name,
        PROJECT / "src" / "ai_osop" / "memory" / "sourcemap_status_authority.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, module_name, module)
    spec.loader.exec_module(module)
    actual = ctx["claims"]
    original = dict(actual)
    kwargs = {
        "manifest_sha256": actual["manifest_sha256"],
        "requested_sha256": actual["artifact_sha256"],
        "current_kid": "central-source",
        "now": actual["issued_at"],
    }
    for record in (
        None,  # No issuance ever committed.
        {**actual, "committed_at": None},  # Prepared but not committed.
    ):
        with pytest.raises(Denied):
            module.SourceMapStatusAuthorityStore._verify_issued(record, original, **kwargs)

    # Artificially complete row is sufficient for this *helper's* format
    # check only, NOT proof of a live PostgreSQL commit or current reviewer.
    # This demonstrates the required dependency on committed 0035 state.
    complete = {
        **actual,
        "kid": "central-source",
        "committed_at": "test-only-simulated-commit",
        "claims_sha256": hashlib.sha256(stage._canonical(actual)).hexdigest(),
        "signature_sha256": "a" * 64,
    }
    assert (
        module.SourceMapStatusAuthorityStore._verify_issued(complete, original, **kwargs) == actual
    )


def test_bootstrap_needs_distinct_trusted_precheck_and_postproof_source(
    cycle: dict[str, Any]
) -> None:
    """Regression contract: a false caller 'ready' token cannot break cycle."""
    mod = cycle["coordinator"]
    assert (
        "signed_supervisor_source"
        in mod.OriginalSourceMapHostCoordinator.coordinate.__code__.co_varnames
    )
    assert not hasattr(mod.OriginalSourceMapHostCoordinator, "coordinate_bootstrap")
    assert (
        "_reserve_issuer_once" in mod.OriginalSourceMapHostCoordinator.coordinate.__code__.co_names
    )
    assert (
        "_native_mount_ready" in mod.OriginalSourceMapHostCoordinator.coordinate.__code__.co_names
    )
