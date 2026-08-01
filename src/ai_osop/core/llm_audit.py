"""LLM-call audit ledger — every completion call gets a WORM-audit entry with
SHA-256 hashes of prompt and response (content never written, only digests).

Step F: "Financial audit trail for every LLM call". Wired as a callback on
LiteLLMClient; writes are best-effort (audit must never crash inference).
"""

from __future__ import annotations

import hashlib
from typing import Any, Callable, Dict, List, Optional

import structlog

logger = structlog.get_logger(__name__)


def _sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", "ignore")).hexdigest()


def make_llm_audit_callback(worm_log: Any) -> Callable[..., None]:
    """Build a LiteLLM-compatible callback.

    The callback receives (messages, model, response_text, usage_dict) after each
    successful completion. Writes a WORM entry containing hashed prompt/response,
    model, token counts. Never raises.
    """

    async def _on_completion(
        *,
        model: str,
        messages: List[Dict[str, str]],
        response_text: str,
        usage: Optional[Dict[str, Any]] = None,
        tenant_id: str = "default",
    ) -> None:
        try:
            payload = {
                "event": "llm_call",
                "model": model,
                "prompt_hash": _sha256_text(
                    "\n".join(f"{m.get('role','')}|{m.get('content','')}" for m in messages)
                ),
                "response_hash": _sha256_text(response_text or ""),
                "prompt_messages": len(messages),
                "total_tokens": (usage or {}).get("total_tokens"),
            }
            await worm_log.append(payload, tenant_id=tenant_id)
        except Exception as e:  # noqa: BLE001
            logger.warning("llm_audit_write_failed", error=str(e))

    return _on_completion
