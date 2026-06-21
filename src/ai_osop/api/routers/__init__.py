# AI-OSOP API Routers
#
# NOTE: Each router module registers its own APIRouter instance.
# They are imported in api/main.py and mounted with app.include_router().

from ai_osop.api.routers import (
    agents,
    approvals,
    engagements,
    findings,
    intelligence,
    sessions,
    system,
    tasks,
)

__all__ = [
    "engagements",
    "tasks",
    "agents",
    "approvals",
    "sessions",
    "findings",
    "intelligence",
    "system",
]
