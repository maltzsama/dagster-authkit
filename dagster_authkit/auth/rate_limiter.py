"""
Rate Limiter - Brute Force Protection

In-memory rate limiting for protection against brute force attacks.
"""

import logging
import threading
import time
from collections import defaultdict
from typing import Dict, Tuple

logger = logging.getLogger(__name__)


class RateLimiter:
    """
    Simple in-memory rate limiter.

    Tracks login attempts by username and blocks after N failures.

    ⚠️ LIMITATION: In-memory only - does not work in multi-instance!
    For distributed deployments, use Redis-based rate limiting.
    """

    def __init__(
        self, max_attempts: int = 5, window_seconds: int = 300, enabled: bool = True  # 5 minutes
    ):
        """
        Args:
            max_attempts: Maximum allowed attempts within the window
            window_seconds: Time window in seconds
            enabled: If False, rate limiting disabled
        """
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.enabled = enabled

        # Dict: username -> [(timestamp1, timestamp2, ...)]
        self._attempts: Dict[str, list] = defaultdict(list)
        self._lock = threading.Lock()

        logger.info(
            f"RateLimiter initialized: {max_attempts} attempts / {window_seconds}s "
            f"({'enabled' if enabled else 'disabled'})"
        )

    def record_attempt(self, username: str) -> None:
        """
        Records a login attempt.

        Args:
            username: Username
        """
        if not self.enabled:
            return

        now = time.time()

        with self._lock:
            # Adds current attempt
            self._attempts[username].append(now)

            # Cleans old attempts (outside the window)
            cutoff = now - self.window_seconds
            self._attempts[username] = [ts for ts in self._attempts[username] if ts > cutoff]

    def is_rate_limited(self, username: str) -> Tuple[bool, int]:
        """
        Checks if username is blocked by rate limit.

        Args:
            username: Username

        Returns:
            Tuple[bool, int]: (is_limited, attempts_count)

        Example:
            >>> limiter = RateLimiter(max_attempts=3, window_seconds=60)
            >>> limiter.record_attempt('hacker')
            >>> limiter.record_attempt('hacker')
            >>> limiter.record_attempt('hacker')
            >>> is_limited, count = limiter.is_rate_limited('hacker')
            >>> print(f"Limited: {is_limited}, Attempts: {count}")
            Limited: True, Attempts: 3
        """
        if not self.enabled:
            return False, 0

        now = time.time()
        cutoff = now - self.window_seconds

        with self._lock:
            # Filters attempts within the window
            recent_attempts = [ts for ts in self._attempts.get(username, []) if ts > cutoff]

            attempts_count = len(recent_attempts)
            is_limited = attempts_count >= self.max_attempts

            if is_limited:
                logger.warning(
                    f"Rate limit triggered for '{username}': "
                    f"{attempts_count} attempts in {self.window_seconds}s"
                )

            return is_limited, attempts_count

    def reset(self, username: str) -> None:
        """
        Resets counter for a user (after successful login).

        Args:
            username: Username
        """
        if not self.enabled:
            return

        with self._lock:
            if username in self._attempts:
                del self._attempts[username]
                logger.debug(f"Rate limit counter reset for '{username}'")

    def clear_all(self) -> None:
        """Clears all counters (useful for testing)."""
        with self._lock:
            self._attempts.clear()
            logger.debug("All rate limit counters cleared")


# ========================================
# Global Singleton Instance
# ========================================

_rate_limiter: RateLimiter = None


def get_rate_limiter() -> RateLimiter:
    """
    Returns rate limiter singleton.

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
        )

    return _rate_limiter


# ========================================
# Convenience Functions
# ========================================


def record_login_attempt(username: str):
    """Convenience function to record attempt."""
    get_rate_limiter().record_attempt(username)


def is_rate_limited(username: str) -> Tuple[bool, int]:
    """Convenience function to check rate limit."""
    return get_rate_limiter().is_rate_limited(username)


def reset_rate_limit(username: str):
    """Convenience function to reset counter."""
    get_rate_limiter().reset(username)
