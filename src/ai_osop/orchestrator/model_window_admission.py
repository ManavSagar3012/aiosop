"""Optional, deterministic model-context admission before provider I/O.

PentAGI's providers/window_compaction.go checks a model's context window and
preserves the last message while trying to summarize older history. This
security-sensitive Flow boundary deliberately **does not** summarize, splice,
truncate or otherwise rewrite *any* model text: unverified summaries could
change an approval, target, scope, signed task or operator instruction.

Opt in with OSOP_MODEL_WINDOW_ADMISSION_ENABLED=true and an explicitly
configured JSON dictionary OSOP_MODEL_CONTEXT_WINDOWS_JSON mapping *each*
primary and fallback model identifier to an integer context window. This
is only an approximate conservative byte-cost preflight, not a provider
tokenizer, exact token count, a context-fit guarantee, or a substitute for
the provider's limits. Unknown configuration, unsupported message shapes or
over-budget prompts fail closed *before* provider submission. No prompts or
model secrets are logged or retained.
"""

import json
import os
from typing import Any, Dict, List, Mapping, Optional


class ModelWindowAdmissionDenied(RuntimeError):
    """No safe, configured admission was established for this model input."""


_ENABLED = frozenset({"true", "1", "yes"})
_DISABLED = frozenset({"", "false", "0", "no"})
_KNOWN_ROLES = frozenset({"system", "developer", "user", "assistant", "tool"})
_FIXED_OVERHEAD_BYTES = 256
_MESSAGE_OVERHEAD_BYTES = 128
_CONSERVATIVE_BYTE_FACTOR = 2


def _no_duplicate_entries(pairs: List[tuple]) -> Dict[str, Any]:
    collected: Dict[str, Any] = {}
    for key, value in pairs:
        if key in collected:
            raise ValueError("Duplicate model context window key")
        collected[key] = value
    return collected


def _window_config(environment: Mapping[str, str]) -> Optional[Dict[str, int]]:
    flag = environment.get("OSOP_MODEL_WINDOW_ADMISSION_ENABLED", "").strip().lower()
    if flag in _DISABLED:
        return None
    if flag not in _ENABLED:
        raise ModelWindowAdmissionDenied("Invalid model window admission configuration")
    raw = environment.get("OSOP_MODEL_CONTEXT_WINDOWS_JSON", "")
    if not isinstance(raw, str) or not 2 <= len(raw) <= 16384:
        raise ModelWindowAdmissionDenied("Model context windows are not configured")
    try:
        parsed = json.loads(raw, object_pairs_hook=_no_duplicate_entries)
        if (
            not isinstance(parsed, dict)
            or not 1 <= len(parsed) <= 64
            or any(
                not isinstance(name, str)
                or not 0 < len(name) <= 256
                or name.strip() != name
                or any(ord(char) < 32 for char in name)
                or type(window) is not int
                or not 512 <= window <= 4_000_000
                for name, window in parsed.items()
            )
        ):
            raise ValueError("Invalid window model configuration")
    except (TypeError, ValueError) as exc:
        raise ModelWindowAdmissionDenied("Model context windows are invalid") from exc
    return parsed


def admit_model_messages(
    messages: List[Dict[str, Any]],
    client: Any,
    *,
    environment: Optional[Mapping[str, str]] = None,
) -> List[Dict[str, Any]]:
    """Return the SAME input only when the conservative window gate admits it.

    Byte-bound proxy deliberately overweights serialized UTF-8 size relative
    to a typical 4-byte/token heuristic; tokenizer-specific counts remain
    unknown. Provider route selection may use either primary or fallback, so
    the most restrictive configured window is applied to both. Actual
    generation maximum (client.max_tokens) is reserved up front. No text is
    removed, even if it appears to be a historical summary or an old tool
    response; only the verified context producer may create a new snapshot.
    """
    config = _window_config(os.environ if environment is None else environment)
    if config is None:
        return messages

    primary = getattr(client, "primary_model", None)
    fallback = getattr(client, "fallback_model", None)
    configured_models = [primary]
    if fallback is not None and fallback != primary:
        configured_models.append(fallback)
    if (
        not hasattr(client, "fallback_model")
        or not all(
            isinstance(name, str) and name and name in config
            for name in configured_models
        )
        or type(getattr(client, "max_tokens", None)) is not int
        or not 1 <= client.max_tokens <= 1_000_000
    ):
        raise ModelWindowAdmissionDenied("Configured model window or output reserve missing")

    # Only text-only messages have a defensible conservative serialized-byte
    # proxy here. JSON/tool/image/opaque message bodies require a separate
    # model-specific estimator; never guess, stringify or drop them.
    if (
        not isinstance(messages, list) or not messages
        or len(messages) > 2048
        or any(
            not isinstance(message, dict)
            or message.get("role") not in _KNOWN_ROLES
            or not isinstance(message.get("content"), str)
            for message in messages
        )
    ):
        raise ModelWindowAdmissionDenied("Unsupported model message shape")
    try:
        # This serialization is used ONLY for the capacity proxy. The
        # original message array, Unicode content and operator input are
        # returned unmodified, never re-serialized for provider submission.
        serialized = json.dumps(
            messages, ensure_ascii=True, allow_nan=False,
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, OverflowError) as exc:
        raise ModelWindowAdmissionDenied("Unsupported model message metadata") from exc

    byte_proxy = (
        len(serialized) * _CONSERVATIVE_BYTE_FACTOR
        + _MESSAGE_OVERHEAD_BYTES * len(messages)
        + _FIXED_OVERHEAD_BYTES
    )
    # This is NOT an exact token estimate and does not claim one. It merely
    # denies content that exceeds a deliberately pessimistic configured
    # byte-based capacity and reserves output space before provider I/O.
    required = byte_proxy + client.max_tokens
    if any(required > config[name] for name in configured_models):
        raise ModelWindowAdmissionDenied("Model context window conservative bound exceeded")
    return messages
