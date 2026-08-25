"""
Mutual TLS (mTLS) Configuration for AI-OSOP Services

Provides TLS context factories for Redis, Neo4j, and inter-service
communication. When OSOP_MTLS_ENABLED=true, all connections require
mutual authentication via client certificates.

Phase 2: Adversarial Validation — proves the platform can enforce
encrypted, authenticated connections between all components.
"""

import ssl
from typing import Optional

import structlog

from ai_osop.core.config import settings

logger = structlog.get_logger("ai_osop.mtls")


def create_redis_tls_context() -> Optional[ssl.SSLContext]:
    """Create a TLS context for Redis connections.

    Returns None if mTLS is not enabled, allowing plaintext fallback
    for development environments.

    The context enforces:
    - TLS 1.2+ (no older protocols)
    - Server certificate verification against the CA
    - Client certificate presentation (mutual auth)
    - Strong cipher suites only
    """
    if not settings.redis_tls_enabled:
        return None

    cert_path = settings.mtls_cert_path
    key_path = settings.mtls_key_path
    ca_path = settings.mtls_ca_cert_path

    if not all([cert_path, key_path, ca_path]):
        logger.warning(
            "redis_tls_incomplete_config",
            cert_set=bool(cert_path),
            key_set=bool(key_path),
            ca_set=bool(ca_path),
        )
        return None

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    # Load client certificate and key (for mutual auth)
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)

    # Load CA certificate for server verification
    ctx.load_verify_locations(cafile=ca_path)
    ctx.verify_mode = ssl.CERT_REQUIRED

    # Enforce strong ciphers
    ctx.set_ciphers(
        "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS"
    )

    logger.info("redis_tls_context_created")
    return ctx


def create_neo4j_tls_context() -> Optional[ssl.SSLContext]:
    """Create a TLS context for Neo4j Bolt connections.

    Returns None if Neo4j TLS is not enabled.

    The context enforces:
    - TLS 1.2+
    - Server certificate verification
    - Client certificate presentation
    """
    if not settings.neo4j_tls_enabled:
        return None

    cert_path = settings.mtls_cert_path
    key_path = settings.mtls_key_path
    ca_path = settings.mtls_ca_cert_path

    if not all([cert_path, key_path, ca_path]):
        logger.warning(
            "neo4j_tls_incomplete_config",
            cert_set=bool(cert_path),
            key_set=bool(key_path),
            ca_set=bool(ca_path),
        )
        return None

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    ctx.load_verify_locations(cafile=ca_path)
    ctx.verify_mode = ssl.CERT_REQUIRED

    logger.info("neo4j_tls_context_created")
    return ctx


def create_service_tls_context() -> Optional[ssl.SSLContext]:
    """Create a TLS context for inter-service HTTP communication.

    Used by the API gateway and agent-to-orchestrator channels.
    Returns None if mTLS is not enabled.
    """
    if not settings.mtls_enabled:
        return None

    cert_path = settings.mtls_cert_path
    key_path = settings.mtls_key_path
    ca_path = settings.mtls_ca_cert_path

    if not all([cert_path, key_path, ca_path]):
        return None

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    ctx.load_verify_locations(cafile=ca_path)
    ctx.verify_mode = ssl.CERT_REQUIRED

    logger.info("service_tls_context_created")
    return ctx


def get_tls_status() -> dict:
    """Return the current mTLS configuration status for observability."""
    return {
        "mtls_enabled": settings.mtls_enabled,
        "redis_tls_enabled": settings.redis_tls_enabled,
        "neo4j_tls_enabled": settings.neo4j_tls_enabled,
        "cert_configured": bool(settings.mtls_cert_path),
        "key_configured": bool(settings.mtls_key_path),
        "ca_configured": bool(settings.mtls_ca_cert_path),
        "redis_tls_context": create_redis_tls_context() is not None,
        "neo4j_tls_context": create_neo4j_tls_context() is not None,
        "service_tls_context": create_service_tls_context() is not None,
    }
