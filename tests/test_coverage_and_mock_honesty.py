"""Coverage floor and mock-LLM honesty gates.

- The pytest config must enforce a floor >= the repo's stated bar so regressions
  can't silently ship under a lower number.
- mock_llm will never silently produce empty completions without logging a one-time
  warning per process.
"""

from pathlib import Path
from unittest.mock import patch

import pytest


def test_coverage_floor_is_at_least_70():
    import re

    cfg = (Path(__file__).parent.parent / "pyproject.toml").read_text(
        encoding="utf-8", errors="ignore"
    )
    m = re.search(r"--cov-fail-under=(\d+)", cfg)
    assert m, "pyproject must pin --cov-fail-under"
    assert int(m.group(1)) >= 70, f"coverage floor {m.group(1)} is below the repo minimum of 70"


@pytest.mark.asyncio
async def test_mock_llm_logs_once_per_process():
    from ai_osop.core import llm_client

    llm_client._MOCK_WARNING_EMITTED = False
    with (
        patch.object(llm_client, "settings") as fake,
        patch.object(llm_client, "llm_logger") as fake_logger,
    ):
        fake.mock_llm = True
        fake.llm_primary_model = "m"
        fake.llm_fallback_model = "f"
        fake.llm_temperature = 0.2
        fake.llm_max_tokens = 256
        fake.llm_completion_timeout = 10
        fake.llm_max_concurrency = 2
        fake.llm_embedding_dim = 8
        fake.llm_keep_alive = 0

        client = llm_client.LiteLLMClient()
        await client.complete([{"role": "user", "content": "hi"}])
        await client.complete([{"role": "user", "content": "hi2"}])

        warnings = [c.args[0] for c in fake_logger.warning.call_args_list]
        assert warnings == ["mock_llm_active_empty_completions"], warnings
