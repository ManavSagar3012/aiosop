from datetime import datetime
from typing import Any, Dict

from pydantic import BaseModel, ConfigDict, Field

from ai_osop.core.config import EngagementPhase


class EngagementState(BaseModel):
    # FIX (pydantic-v2-config-2026-08-24): class-based `Config` is deprecated in
    # Pydantic v2 (removal planned for v3) and emitted a deprecation warning on
    # every test run. Migrated to the ConfigDict form; semantics unchanged.
    model_config = ConfigDict(frozen=False)  # Allow mutation, but update version manually

    id: str
    phase: EngagementPhase
    version: int = Field(default=0, description="Optimistic locking version")
    data: Dict[str, Any] = Field(default_factory=dict)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
