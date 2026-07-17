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
    def check_and_record(
        self, identifier: str, max_attempts: int, window_seconds: int
    ) -> Tuple[bool, int]:
        """
        Atomically check if rate limited and record an attempt.

        Eliminates the TOCTOU race between is_rate_limited() and
        record_attempt() when called separately.

        Args:
            identifier: Username or IP address
            max_attempts: Maximum attempts allowed
            window_seconds: Time window in seconds

        Returns:
            Tuple[bool, int]: (is_limited, attempts_count)
            Unlike check_and_record on the facade, this does NOT skip
            recording when already limited — the atomic operation records
            and checks in one step, returning the post-recording state.
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

    WARNING: Does NOT work across multiple pods/instances!
    Each pod has its own memory, so rate limits are not shared.

    Use RedisRateLimiter for distributed deployments.
    """

    # Maximum tracked identifiers before forced cleanup.
    # Prevents OOM from adversarial key stuffing (random usernames/IPs).
    _MAX_TRACKED = 10_000

    def __init__(self):
        """Initialise thread-safe in-memory attempt store with OOM protection."""
        self._attempts: Dict[str, list] = defaultdict(list)
        self._lock = threading.Lock()
        self._last_cleanup = time.time()

        logger.warning(
            "InMemoryRateLimiter initialized - NOT DISTRIBUTED!\n"
            "   This will NOT work correctly in multi-pod Kubernetes deployments.\n"
            "   Set DAGSTER_AUTH_REDIS_URL to enable distributed rate limiting."
        )

    def _maybe_prune(self, window_seconds: int) -> None:
        """Prune expired entries across the entire dict to prevent OOM from
        adversarial key stuffing (random identifiers that are never checked again)."""
        now = time.time()
        if now - self._last_cleanup < 60:
            return
        self._last_cleanup = now

        cutoff = now - window_seconds
        expired = []
        for ident, timestamps in self._attempts.items():
            active = [ts for ts in timestamps if ts > cutoff]
            if active:
                self._attempts[ident] = active
            else:
                expired.append(ident)

        for ident in expired:
            del self._attempts[ident]

        if expired:
            logger.debug(f"Pruned {len(expired)} expired rate-limit entries")

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

    def check_and_record(
        self, identifier: str, max_attempts: int, window_seconds: int
    ) -> Tuple[bool, int]:
        """Atomically check and record an attempt. Holds the lock once."""
        now = time.time()
        cutoff = now - window_seconds

        with self._lock:
            recent = [ts for ts in self._attempts.get(identifier, []) if ts > cutoff]
            attempts_count = len(recent)

            if attempts_count >= max_attempts:
                return True, attempts_count

            # OOM prevention
            if len(self._attempts) >= self._MAX_TRACKED and identifier not in self._attempts:
                self._maybe_prune(window_seconds)
                if len(self._attempts) >= self._MAX_TRACKED:
                    logger.warning(
                        f"Rate limiter at capacity ({self._MAX_TRACKED} tracked). "
                        "Rejecting new identifier to prevent OOM."
                    )
                    return True, self._MAX_TRACKED

            self._attempts[identifier].append(now)
            new_recent = [ts for ts in self._attempts[identifier] if ts > cutoff]
            if not new_recent:
                del self._attempts[identifier]
                return False, 0
            self._attempts[identifier] = new_recent
            new_count = len(new_recent)
            return new_count >= max_attempts, new_count

    def record_attempt(self, identifier: str, window_seconds: int) -> int:
        """Record failed attempt."""
        now = time.time()
        cutoff = now - window_seconds

        with self._lock:
            # Guard against adversarial key flooding (OOM prevention)
            if len(self._attempts) >= self._MAX_TRACKED and identifier not in self._attempts:
                self._maybe_prune(window_seconds)
                if len(self._attempts) >= self._MAX_TRACKED:
                    # Still at capacity after pruning — reject new identifiers.
                    # This is a legitimate rate-limit defense: the attacker
                    # can't create infinite new buckets.
                    logger.warning(
                        f"Rate limiter at capacity ({self._MAX_TRACKED} tracked). "
                        "Rejecting new identifier to prevent OOM."
                    )
                    return self._MAX_TRACKED  # effectively rate-limited

            # Add current attempt
            self._attempts[identifier].append(now)

            # Clean old attempts for this identifier
            self._attempts[identifier] = [ts for ts in self._attempts[identifier] if ts > cutoff]

            # Prune empty entries to prevent memory leak
            if not self._attempts[identifier]:
                del self._attempts[identifier]
                return 0

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
        """
        Initialise Redis connection.

        Args:
            redis_url: Redis connection URL (``redis://`` or ``rediss://``).

        Raises:
            RuntimeError: If the ``redis`` package is not installed or
                          the connection fails.
        """
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
            # Fail-closed: block logins if Redis is unreachable.
            # Legitimate users with an existing session continue unaffected.
            return True, max_attempts

    def check_and_record(
        self, identifier: str, max_attempts: int, window_seconds: int
    ) -> Tuple[bool, int]:
        """Atomically check and record via Lua script."""
        key = f"ratelimit:{identifier}"
        script = """
        local key = KEYS[1]
        local max_attempts = tonumber(ARGV[1])
        local window = tonumber(ARGV[2])
        local count = redis.call('GET', key)
        if count and tonumber(count) >= max_attempts then
            return {1, count}
        end
        local new_count = redis.call('INCR', key)
        redis.call('EXPIRE', key, window, 'NX')
        if tonumber(new_count) >= max_attempts then
            return {1, new_count}
        end
        return {0, new_count}
        """

        try:
            limited, count = self.redis.eval(script, 1, key, str(max_attempts), str(window_seconds))
            limited = bool(limited)
            count = int(count)

            if limited:
                logger.warning(
                    f"Rate limit triggered for '{identifier}': "
                    f"{count}/{max_attempts} attempts"
                )

            return limited, count
        except Exception as e:
            logger.error(f"Redis rate limit check_and_record failed: {e}")
            return True, max_attempts

    def record_attempt(self, identifier: str, window_seconds: int) -> int:
        key = f"ratelimit:{identifier}"

        try:
            count = self.redis.incr(key)
            self.redis.expire(key, window_seconds, nx=True)

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
        Initialise the rate limiter, auto-selecting the backend.

        Args:
            max_attempts:  Maximum allowed attempts within the window.
            window_seconds: Time window in seconds.
            enabled:       If ``False``, rate limiting is disabled entirely.
            redis_url:     Redis connection URL. Auto-detected from
                           ``DAGSTER_AUTH_REDIS_URL`` if not provided.
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

    def check_and_record(self, identifier: str) -> Tuple[bool, int]:
        """
        Atomically check if rate limited and record an attempt.

        Delegates to the backend's atomic check_and_record, which
        eliminates the TOCTOU race between is_rate_limited() and
        record_attempt() when called separately.

        Returns:
            Tuple[bool, int]: (is_limited, attempts_count)
            If is_limited is True, the attempt was recorded but
            the user exceeded the limit.
        """
        if not self.enabled:
            return False, 0

        return self.backend.check_and_record(
            identifier, self.max_attempts, self.window_seconds
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
