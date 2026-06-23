"""Retry utilities with exponential backoff for AI-OSOP.

Provides a shared `retry_with_backoff` decorator and helper for
connection initialization (Redis, Neo4j, Postgres) so the platform
survives transient dependency outages during startup.
"""

from __future__ import annotations

import asyncio
import functools
import logging
from typing import Any, Callable, Optional, Type, Union

logger = logging.getLogger(__name__)


async def retry_with_backoff(
    fn: Callable,
    max_retries: int = 5,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    backoff_multiplier: float = 2.0,
    exceptions: Union[Type[Exception], tuple] = Exception,
    retry_name: str = "operation",
) -> Any:
    """Retry an async callable with exponential backoff.

    Args:
        fn: Async callable to retry.
        max_retries: Maximum number of retry attempts (0 = no retries).
        base_delay: Initial delay between retries in seconds.
        max_delay: Maximum delay cap in seconds.
        backoff_multiplier: Multiplier for exponential backoff.
        exceptions: Exception type(s) to catch and retry on.
        retry_name: Human-readable name for logging.

    Returns:
        The result of the successful call.

    Raises:
        The last exception raised if all retries are exhausted.
    """
    last_exception: Optional[Exception] = None
    for attempt in range(max_retries + 1):
        try:
            return await fn()
        except exceptions as e:
            last_exception = e
            if attempt >= max_retries:
                break
            delay = min(base_delay * (backoff_multiplier**attempt), max_delay)
            logger.warning(
                "%s failed (attempt %d/%d): %s. Retrying in %.1fs...",
                retry_name,
                attempt + 1,
                max_retries + 1,
                e,
                delay,
            )
            await asyncio.sleep(delay)

    logger.error(
        "%s exhausted all %d retries. Last error: %s",
        retry_name,
        max_retries + 1,
        last_exception,
    )
    raise last_exception  # type: ignore[misc]


def with_retry(
    max_retries: int = 5,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    backoff_multiplier: float = 2.0,
    exceptions: Union[Type[Exception], tuple] = Exception,
    retry_name: Optional[str] = None,
) -> Callable:
    """Decorator that applies retry_with_backoff to an async function.

    Usage:
        @with_retry(max_retries=5, exceptions=(ConnectionError,))
        async def connect_neo4j():
            ...
    """

    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            name = retry_name or fn.__qualname__
            return await retry_with_backoff(
                lambda: fn(*args, **kwargs),
                max_retries=max_retries,
                base_delay=base_delay,
                max_delay=max_delay,
                backoff_multiplier=backoff_multiplier,
                exceptions=exceptions,
                retry_name=name,
            )

        return wrapper

    return decorator
