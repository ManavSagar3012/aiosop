import structlog
import logging
import pytest


def test_structlog_accepts_error_kwarg():
    """Verify structlog logger.error() accepts error= as a keyword argument.

    The stdlib logging.Logger._log() raises TypeError on unexpected kwargs
    like error= and target_count=. structlog wraps _log() and passes kwargs
    as structured event context, so this call must never crash.
    This is the exact pattern that was crashing in _execute_service_probe.
    """
    logger = structlog.get_logger("test_recon")
    # These are the exact call patterns that were crashing with stdlib logging
    logger.error("service_probe_failed", error="test error", target_count=5, exc_info=True)
    logger.warning("service_probe_failed", error="test error", target_count=5)
    logger.error("full_recon_failure", error="test error", exc_info=True)


def test_recon_agent_imports():
    """Verify the recon agent module can import without error."""
    from ai_osop.agents.recon_agent import ReconAgent, logger
    assert logger is not None
    # Verify it’s NOT a stdlib Logger (which would crash on error= kwarg)
    assert not isinstance(logger, logging.Logger)


def test_recon_logger_does_not_raise_typeerror():
    """Verify calling logger.error() with unexpected kwargs does NOT raise TypeError.

    The stdlib logging.Logger._log() raises "Logger._log() got unexpected keyword
    argument 'error'". structlog must never exhibit this crash.
    """
    from ai_osop.agents.recon_agent import logger
    # Trigger the lazy proxy resolution first
    try:
        logger.info("probe")
    except Exception:
        pass
    # Now test the actual fix patterns
    logger.error("service_probe_failed", error="test error", target_count=5, exc_info=True)
    logger.warning("service_probe_failed", error="test error", target_count=5)
    logger.error("full_recon_failure", error="test error", exc_info=True)
