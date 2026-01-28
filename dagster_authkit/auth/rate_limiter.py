"""
Rate Limiter - Brute Force Protection

Supports both in-memory (single-pod) and Redis (distributed) backends.
"""

import logging
import threading
import time
from abc import ABC, abstractmethod
from collections import defaultdict
from typing import Dict, Tuple, Optional

logger = logging.getLogger(__name__)


# ========================================
# Abstract Backend
# ========================================


class RateLimiterBackend(ABC):
    """Abstract rate limiter backend."""

    @abstractmethod
    def is_rate_limited(
        self, identifier: str, max_attempts: int, window_seconds: int
    ) -> Tuple[bool, int]:
        """
        Check if identifier is rate limited.

        Args:
            identifier: Username or IP address
            max_attempts: Maximum attempts allowed
            window_seconds: Time window in seconds

        Returns:
            Tuple[bool, int]: (is_limited, attempts_count)
        """
        pass

    @abstractmethod
    def record_attempt(self, identifier: str, window_seconds: int) -> int:
        """
        Record a failed attempt.

        Args:
            identifier: Username or IP address
            window_seconds: Time window in seconds

        Returns:
            int: Current attempt count
        """
        pass

    @abstractmethod
    def reset(self, identifier: str) -> None:
        """
        Reset attempts for identifier (after successful login).

        Args:
            identifier: Username or IP address
        """
        pass


# ========================================
# In-Memory Backend (Single-Pod Only)
# ========================================


class InMemoryRateLimiter(RateLimiterBackend):
    """
    In-memory rate limiter (single-pod only).

    ⚠️ WARNING: Does NOT work across multiple pods/instances!
    Each pod has its own memory, so rate limits are not shared.

    Use RedisRateLimiter for distributed deployments.
    """

    def __init__(self):
        # Dict: identifier -> [(timestamp1, timestamp2, ...)]
        self._attempts: Dict[str, list] = defaultdict(list)
        self._lock = threading.Lock()

        logger.warning(
            "⚠️  InMemoryRateLimiter initialized - NOT DISTRIBUTED!\n"
            "   This will NOT work correctly in multi-pod Kubernetes deployments.\n"
            "   Set DAGSTER_AUTH_REDIS_URL to enable distributed rate limiting."
        )

    def is_rate_limited(
        self, identifier: str, max_attempts: int, window_seconds: int
    ) -> Tuple[bool, int]:
        """Check if identifier is rate limited."""
        now = time.time()
        cutoff = now - window_seconds

        with self._lock:
            # Filter attempts within window
            recent_attempts = [ts for ts in self._attempts.get(identifier, []) if ts > cutoff]

            attempts_count = len(recent_attempts)
            is_limited = attempts_count >= max_attempts

            return is_limited, attempts_count

    def record_attempt(self, identifier: str, window_seconds: int) -> int:
        """Record failed attempt."""
        now = time.time()
        cutoff = now - window_seconds

        with self._lock:
            # Add current attempt
            self._attempts[identifier].append(now)

            # Clean old attempts
            self._attempts[identifier] = [ts for ts in self._attempts[identifier] if ts > cutoff]

            return len(self._attempts[identifier])

    def reset(self, identifier: str) -> None:
        """Reset counter after successful login."""
        with self._lock:
            if identifier in self._attempts:
                del self._attempts[identifier]
                logger.debug(f"Rate limit reset for '{identifier}'")


# ========================================
# Redis Backend (Distributed)
# ========================================


class RedisRateLimiter(RateLimiterBackend):
    """
    Redis-backed rate limiter (distributed, multi-pod safe).

    Uses Redis INCR + EXPIRE for atomic operations.
    Works correctly across multiple pods/instances.
    """

    def __init__(self, redis_url: str):
        try:
            import redis

            self.redis = redis.from_url(redis_url, decode_responses=True)

            # Test connection
            self.redis.ping()
            logger.info(f"✅ RedisRateLimiter initialized (distributed, url={redis_url})")
        except ImportError:
            raise RuntimeError(
                "Redis rate limiting requires 'redis' package.\n" "Install with: pip install redis"
            )
        except Exception as e:
            raise RuntimeError(f"Failed to connect to Redis: {e}")

    def is_rate_limited(
        self, identifier: str, max_attempts: int, window_seconds: int
    ) -> Tuple[bool, int]:
        """Check if identifier is rate limited."""
        key = f"ratelimit:{identifier}"

        try:
            count = self.redis.get(key)
            attempts = int(count) if count else 0

            is_limited = attempts >= max_attempts

            if is_limited:
                logger.warning(
                    f"Rate limit triggered for '{identifier}': "
                    f"{attempts}/{max_attempts} attempts"
                )

            return is_limited, attempts
        except Exception as e:
            logger.error(f"Redis rate limit check failed: {e}")
            # Fail open (don't block on Redis errors)
            return False, 0

    def record_attempt(self, identifier: str, window_seconds: int) -> int:
        """Record failed attempt with auto-expiration."""
        key = f"ratelimit:{identifier}"

        try:
            # Atomic increment
            count = self.redis.incr(key)
            self.redis.expire(key, window_seconds)

            logger.debug(f"Rate limit attempt recorded: {identifier} ({count})")
            return count
        except Exception as e:
            logger.error(f"Redis rate limit record failed: {e}")
            return 0

    def reset(self, identifier: str) -> None:
        """Reset attempts after successful login."""
        key = f"ratelimit:{identifier}"

        try:
            deleted = self.redis.delete(key)
            if deleted:
                logger.debug(f"Rate limit reset: {identifier}")
        except Exception as e:
            logger.error(f"Redis rate limit reset failed: {e}")


# ========================================
# Rate Limiter (Orchestrator)
# ========================================


class RateLimiter:
    """
    Main rate limiter class (facade pattern).

    Automatically selects backend based on configuration:
    - Redis if DAGSTER_AUTH_REDIS_URL is set
    - In-memory otherwise (with warning for multi-pod)
    """

    def __init__(
        self,
        max_attempts: int = 5,
        window_seconds: int = 300,
        enabled: bool = True,
        redis_url: Optional[str] = None,
    ):
        """
        Initialize rate limiter.

        Args:
            max_attempts: Maximum allowed attempts within window
            window_seconds: Time window in seconds
            enabled: If False, rate limiting is disabled
            redis_url: Redis connection URL (optional, auto-detected)
        """
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.enabled = enabled

        # Auto-detect Redis URL if not provided
        if redis_url is None:
            import os

            redis_url = os.getenv("DAGSTER_AUTH_REDIS_URL")

        # Select backend
        if redis_url:
            self.backend = RedisRateLimiter(redis_url)
            logger.info(f"Rate limiting: DISTRIBUTED (Redis)")
        else:
            self.backend = InMemoryRateLimiter()
            logger.info(f"Rate limiting: IN-MEMORY (single-pod only)")

        logger.info(
            f"Rate limiter configured: {max_attempts} attempts / {window_seconds}s "
            f"({'enabled' if enabled else 'disabled'})"
        )

    def record_attempt(self, identifier: str) -> int:
        """
        Record a failed login attempt.

        Args:
            identifier: Username or IP address

        Returns:
            int: Current attempt count
        """
        if not self.enabled:
            return 0

        return self.backend.record_attempt(identifier, self.window_seconds)

    def is_rate_limited(self, identifier: str) -> Tuple[bool, int]:
        """
        Check if identifier is rate limited.

        Args:
            identifier: Username or IP address

        Returns:
            Tuple[bool, int]: (is_limited, attempts_count)
        """
        if not self.enabled:
            return False, 0

        return self.backend.is_rate_limited(identifier, self.max_attempts, self.window_seconds)

    def reset(self, identifier: str) -> None:
        """
        Reset attempts for identifier (after successful login).

        Args:
            identifier: Username or IP address
        """
        if not self.enabled:
            return

        self.backend.reset(identifier)


# ========================================
# Global Singleton Instance
# ========================================

_rate_limiter: Optional[RateLimiter] = None


def get_rate_limiter() -> RateLimiter:
    """
    Get rate limiter singleton.

    Returns:
        Global RateLimiter instance
    """
    global _rate_limiter

    if _rate_limiter is None:
        from dagster_authkit.utils.config import config

        _rate_limiter = RateLimiter(
            max_attempts=config.RATE_LIMIT_MAX_ATTEMPTS,
            window_seconds=config.RATE_LIMIT_WINDOW_SECONDS,
            enabled=config.RATE_LIMIT_ENABLED,
            redis_url=getattr(config, "REDIS_URL", None),
        )

    return _rate_limiter


# ========================================
# Convenience Functions (Backward Compatible)
# ========================================


def record_login_attempt(username: str) -> int:
    """
    Record failed login attempt.

    Args:
        username: Username

    Returns:
        int: Current attempt count
    """
    return get_rate_limiter().record_attempt(username)


def is_rate_limited(username: str) -> Tuple[bool, int]:
    """
    Check if username is rate limited.

    Args:
        username: Username

    Returns:
        Tuple[bool, int]: (is_limited, attempts_count)
    """
    return get_rate_limiter().is_rate_limited(username)


def reset_rate_limit(username: str) -> None:
    """
    Reset rate limit after successful login.

    Args:
        username: Username
    """
    get_rate_limiter().reset(username)
