
from pydantic import BaseModel, Field
from datetime import datetime
from ai_osop.core.config import EngagementPhase
from typing import Dict, Any, Optional

class EngagementState(BaseModel):
    id: str
    phase: EngagementPhase
    version: int = Field(default=0, description="Optimistic locking version")
    data: Dict[str, Any] = Field(default_factory=dict)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        frozen = False # Allow mutation, but update version manually
