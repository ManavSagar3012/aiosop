from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field

from ai_osop.core.config import EngagementPhase


class EngagementState(BaseModel):
    id: str
    phase: EngagementPhase
    version: int = Field(default=0, description="Optimistic locking version")
    data: Dict[str, Any] = Field(default_factory=dict)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        frozen = False  # Allow mutation, but update version manually
