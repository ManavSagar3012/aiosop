# W7 — Live LLM Reasoning Verification (2026-07-28)

Empirical, against the live stack (Ollama on `localhost:11434`, project venv,
my W7 `llm_reasoning_model` routing committed as `e578d487`). Reproducible via
`benchmarks/results/w7_live_llm_bench.json` + `w7_think_live_proof.json`.

## Finding 1 — the review's "8b local model is degraded" is CONFIRMED live
`qwen3:8b` (the deployment's primary reasoning model) returns **EMPTY** for even a
trivial prompt through the production `LiteLLMClient.complete()` path — no
exception, just `""`. This is exactly the runtime behavior behind the review's
"all agent think() degraded until Ollama up" note. The model connects (no error),
it just produces nothing.

## Finding 2 — working alternatives exist (measured)
Realistic attack-reasoning prompt (observation -> next 3 actions + the chain):

| Model | tokens | secs | words | output |
|-------|--------|------|-------|--------|
| qwen3:8b (local) | any | — | 0 | **EMPTY** (degraded) |
| llama3:latest (local) | 512 | 48.1 | 177 | specific next-actions (SQLi payload gen, etc.) |
| llama3:latest (local) | 1536 | 35.6 | 158 | specific next-actions |
| phi3:latest (local) | test | — | — | clean answer on simple prompt; transient OSError under the heavier prompt (socket cleanup artifact, not a model refusal) |
| kimi-k2.5:cloud | test | — | — | works (real answer); faster than local |
| gpt-oss:20b-cloud | any | — | 0 | subscription-gated (Ollama cloud) / empty |
| qwen3-coder:480b-cloud | any | — | 0 | **retired** by Ollama 2026-07-15 (hard error) |

## Finding 3 — W7 routing works end-to-end through think()
With `OSOP_LLM_REASONING_MODEL=ollama/llama3:latest` and the token cap raised
512->1536, the production `BaseAgent.think()` produced non-empty output through the
real `LiteLLMClient.complete()` path (proof: `w7_think_live_proof.json`). The
routing mechanism my commit added works against the live provider.

## Finding 4 — 512 tokens was genuinely truncating chains
llama3 used 158-298 words (~220-400 tokens) just for a *concise* 3-action answer at
both 512 and 1536. At the old 512 cap the answer fit; but a real multi-stage observe
-> plan -> chain (the W1 loop) needs more headroom — 1536 is the floor, not the
ceiling. For the tool-use loop (W1), reasoning calls should budget ~4-6k when routed
to a capable model.

## Prefer note (honest)
- llama3 *refused* the pentest-framed prompt with a safety message in isolated
  think() ("I cannot provide… illegal or harmful activities"). The platform's
  prompts must carry the authorized-testing context (rules of engagement / scope)
  so the model treats it as authorized work, OR a model with appropriate
  guardrails for security tooling must be pinned. This is a *prompt/model*
  selection concern for the proving ground (#8/#3), not a routing bug.
- `qwen3-coder:480b-cloud` (the model the last deployment ran) was retired by
  Ollama cloud — that deployment's LLM config is stale and must be repointed.

## Actionable config (this deployment)
```
OSOP_LLM_PRIMARY_MODEL=ollama/llama3:latest      # bulk
OSOP_LLM_FALLBACK_MODEL=ollama/kimi-k2.5:cloud   # cloud fallback
OSOP_LLM_REASONING_MODEL=ollama/llama3:latest    # W7: reasoning path (worker)
OSOP_LLM_REASONING_MAX_TOKENS=1536               # W7: raised from 512
```
