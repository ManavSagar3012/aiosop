"""Genuine production source branch defaults to DENY absent host enrollment.

No credential, ledger write, provider, network or app DB is touched.
"""

from __future__ import annotations

import pytest

from ai_osop.core import provider_host_runtime_slot_20261022 as slot
from ai_osop.core.provider_vault_runtime_join import (
    ProviderVaultRuntimeDenied,
    ProviderVaultRuntimeJoin,
)


def test_unconfigured_host_slot_defaults_to_absent_and_cannot_install_pending() -> None:
    assert slot.host_enrolled_provider_runtime() is None
    with pytest.raises(ProviderVaultRuntimeDenied):
        slot.install_independent_host_provider_runtime(ProviderVaultRuntimeJoin())
    assert slot.host_enrolled_provider_runtime() is None


@pytest.mark.parametrize("untrusted", [None, True, False, {}, "APPROVED", object()])
def test_untrusted_external_status_is_never_host_enrollment(untrusted: object) -> None:
    with pytest.raises(ProviderVaultRuntimeDenied):
        slot.install_independent_host_provider_runtime(untrusted)  # type: ignore[arg-type]
    assert slot.host_enrolled_provider_runtime() is None


def test_production_source_exposes_explicit_host_signed_join_and_default_pending() -> None:
    from pathlib import Path

    source = (Path(__file__).resolve().parents[1] / "src/ai_osop/api/main.py").read_text(
        encoding="utf-8"
    )
    assert "host_enrolled_provider_runtime()" in source
    assert "host_vault.construct_client(usage_store=ModelUsageLedger(session_memory))" in source
    assert "pending_guarded_client(usage_store=ModelUsageLedger(session_memory))" in source
    assert "install_independent_host_provider_runtime" not in source


def test_actual_main_production_constructor_branch_consumes_host_join_without_direct_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AST invokes original main branch with a deliberately synthetic host.

    Tests the conditional wiring only. The fake is NOT an enrolled signer and
    cannot be installed through the real host slot or trigger paid I/O.
    """
    import ast
    import copy
    from pathlib import Path
    from types import SimpleNamespace

    from tests.test_api_production_host_vault_pending_20261021 import _bootstrap_branch

    seen = []
    fake_client = object()

    class FixtureHostJoin:
        def construct_client(self, *, usage_store: object) -> object:
            seen.append(usage_store)
            return fake_client

    simulated = FixtureHostJoin()
    monkeypatch.setattr(slot, "host_enrolled_provider_runtime", lambda: simulated)
    main = Path(__file__).resolve().parents[1] / "src/ai_osop/api/main.py"
    scoped = ast.fix_missing_locations(
        ast.Module(body=[copy.deepcopy(_bootstrap_branch())], type_ignores=[])
    )
    safe_ledger = object()
    symbols = {
        "settings": SimpleNamespace(environment="production"),
        "session_memory": object(),
        "ModelUsageLedger": lambda *_: safe_ledger,
    }
    exec(compile(scoped, str(main), "exec"), symbols)
    assert symbols["llm_client"] is fake_client
    assert seen == [safe_ledger]
