"""Fast-fail per-action timeout in browser-mcp.

Guards the ACTION_TIMEOUT_MS parse so click/fill never silently fall back to
Playwright's 30s default (which stacks across register's 4 fills and blows the
180s agent ceiling).
"""

import importlib.util
import os
from pathlib import Path

_MOD = Path(__file__).resolve().parents[1] / "mcp-servers" / "python" / "browser_mcp.py"


def _load(env_value=None):
    if env_value is None:
        os.environ.pop("OSOP_BROWSER_ACTION_TIMEOUT_MS", None)
    else:
        os.environ["OSOP_BROWSER_ACTION_TIMEOUT_MS"] = env_value
    spec = importlib.util.spec_from_file_location("_browser_mcp_probe", _MOD)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_default_is_bounded_well_under_agent_ceiling():
    mod = _load()
    assert mod.ACTION_TIMEOUT_MS == 10000
    # 4 fills worst-case must stay under the 180s (180000ms) agent hard timeout.
    assert mod.ACTION_TIMEOUT_MS * 4 < 180000


def test_env_override_respected():
    mod = _load("5000")
    assert mod.ACTION_TIMEOUT_MS == 5000


if __name__ == "__main__":
    test_default_is_bounded_well_under_agent_ceiling()
    test_env_override_respected()
    print("ok")
