from datetime import datetime
from typing import Any, Dict

from pydantic import BaseModel, ConfigDict, Field

from ai_osop.core.config import EngagementPhase


class EngagementState(BaseModel):
    # MINOR / Pydantic V2 migration (2026-07-21): replaced the deprecated
    # class-based ``Config`` with ``model_config = ConfigDict(...)``. The
    # class-based form was removed in Pydantic V2 and only emitted a
    # deprecation warning; on a future Pydantic bump it would have hard-failed.
    # ``frozen=False`` is the Pydantic default, so the explicit flag is kept
    # only for documentation parity with the prior comment.
    model_config = ConfigDict(frozen=False)

    id: str
    phase: EngagementPhase
    version: int = Field(default=0, description="Optimistic locking version")
    data: Dict[str, Any] = Field(default_factory=dict)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
