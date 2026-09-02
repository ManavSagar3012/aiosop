import os
import sys
import pytest

# Ensure no environment overrides from bash
keys_to_pop = [
    "OSOP_LLM_PRIMARY",
    "OSOP_LLM_PRIMARY_MODEL",
    "OSOP_LLM_FALLBACK_MODEL",
    "OSOP_LLM_EMBEDDING_MODEL",
    "OSOP_LLM_MAX_CONCURRENCY",
    "OSOP_LLM_EMBEDDING_DIM",
    "OSOP_MOCK_LLM"
]

# Increase timeout for cold starts
os.environ["OSOP_LLM_COMPLETION_TIMEOUT"] = "180"

for k in keys_to_pop:
    if k in os.environ:
        os.environ.pop(k)

if __name__ == "__main__":
    args = sys.argv[1:] if len(sys.argv) > 1 else ["tests/test_e2e_recon_reporting.py"]
    sys.exit(pytest.main(args))
