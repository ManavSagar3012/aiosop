"""
Authenticated-session subsystem.

Phase 1 of the Bug Bounty Capability Upgrade.

Modules:
    session_store: Durable (Postgres) + hot-cache (Redis) credential storage.
    session_client: Auth-aware httpx wrapper. Every agent uses this so we
        never sprinkle cookie/bearer-injection logic across the codebase.
    api_inventory: HAR parser → APIEndpoint Neo4j nodes (foundation for
        BOLA / IDOR / authz testing).
"""

from ai_osop.auth.session_store import SessionStore, UserSession, UserSessionNotFound

__all__ = ["SessionStore", "UserSession", "UserSessionNotFound"]
