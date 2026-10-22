"""Bound every embedding provider request before durable precharge.

PentAGI's EMBEDDING_MAX_TEXT_BYTES is a useful guard against oversized and
unbounded model calls. This implementation counts UTF-8 bytes (not characters)
and handles direct _provider_call as well as the high-level embedding API.
"""

import os
import re
from typing import Any

from ai_osop.memory.model_usage import ModelBudgetExceeded

_SETTING = "OSOP_EMBEDDING_MAX_TEXT_BYTES"
_DEFAULT = 65536
_MAX = 262144
_MIN = 1024


def embedding_max_text_bytes() -> int:
    raw = os.environ.get(_SETTING)
    if raw is None:
        return _DEFAULT
    if not isinstance(raw, str) or not re.fullmatch(r"[0-9]{1,6}", raw):
        raise ModelBudgetExceeded("Embedding input limit configuration is invalid")
    amount = int(raw)
    if not _MIN <= amount <= _MAX:
        raise ModelBudgetExceeded("Embedding input limit configuration is invalid")
    return amount


def verify_embedding_request(input_value: Any) -> None:
    """Reject malformed/overlimit payloads WITHOUT inference or quota debit."""
    limit = embedding_max_text_bytes()
    if (
        not isinstance(input_value, list)
        or not 1 <= len(input_value) <= 16
        or any(type(item) is not str or not item for item in input_value)
    ):
        raise ModelBudgetExceeded("Embedding input must be a bounded text batch")
    total = 0
    for item in input_value:
        try:
            encoded = item.encode("utf-8")
        except UnicodeError as exc:
            raise ModelBudgetExceeded("Embedding text is not valid UTF-8") from exc
        if len(encoded) > limit:
            raise ModelBudgetExceeded("Embedding text exceeds configured byte limit")
        total += len(encoded)
        if total > limit:
            raise ModelBudgetExceeded("Embedding batch exceeds configured byte limit")
