"""
Unit tests for auth/rate_limiter.py

Covers:
- InMemoryRateLimiter: record, check, reset, thread safety
- RateLimiter (orchestrator): disabled mode, enabled mode
- Convenience functions (is_rate_limited, record_login_attempt, reset_rate_limit)
"""

import threading
import time

import pytest

from dagster_authkit.auth.rate_limiter import (
    InMemoryRateLimiter,
    RateLimiter,
    get_rate_limiter,
    is_rate_limited,
    record_login_attempt,
    reset_rate_limit,
)


class TestInMemoryRateLimiter:
    """Verifies the in-memory rate limiter backend."""

    @pytest.fixture
    def limiter(self):
        """Returns a fresh InMemoryRateLimiter for each test."""
        return InMemoryRateLimiter()

    def test_not_limited_initially(self, limiter):
        """A new identifier should not be rate limited."""
        is_limited, count = limiter.is_rate_limited("user1", max_attempts=5, window_seconds=300)
        assert is_limited is False
        assert count == 0

    def test_record_attempt_increases_count(self, limiter):
        """Each record_attempt call should increase the attempt count."""
        limiter.record_attempt("user1", window_seconds=300)
        is_limited, count = limiter.is_rate_limited("user1", max_attempts=5, window_seconds=300)
        assert count == 1
        assert is_limited is False

    def test_rate_limited_after_max_attempts(self, limiter):
        """After reaching max_attempts, the identifier should be rate limited."""
        for _ in range(5):
            limiter.record_attempt("user2", window_seconds=300)
        is_limited, count = limiter.is_rate_limited("user2", max_attempts=5, window_seconds=300)
        assert is_limited is True
        assert count >= 5

    def test_reset_clears_counter(self, limiter):
        """Reset should clear the attempt counter."""
        limiter.record_attempt("user3", window_seconds=300)
        limiter.reset("user3")
        is_limited, count = limiter.is_rate_limited("user3", max_attempts=5, window_seconds=300)
        assert count == 0
        assert is_limited is False

    def test_reset_nonexistent_no_error(self, limiter):
        """Resetting a nonexistent identifier should not raise an error."""
        limiter.reset("ghost")  # should not raise

    def test_identifiers_are_independent(self, limiter):
        """Rate limiting for one user should not affect another."""
        for _ in range(5):
            limiter.record_attempt("user_a", window_seconds=300)
        is_limited_b, _ = limiter.is_rate_limited("user_b", max_attempts=5, window_seconds=300)
        assert is_limited_b is False

    def test_old_attempts_cleaned(self, limiter):
        """Attempts older than the window should be cleaned automatically."""
        limiter.record_attempt("user4", window_seconds=1)
        time.sleep(1.1)  # wait for window to expire
        # Old attempts should have fallen out of the window
        is_limited, count = limiter.is_rate_limited("user4", max_attempts=1, window_seconds=1)
        assert count == 0
        assert is_limited is False

    def test_thread_safety(self, limiter):
        """Concurrent record_attempt calls should not cause data races."""
        threads = []
        errors = []

        def record():
            try:
                for _ in range(10):
                    limiter.record_attempt("threaded_user", window_seconds=300)
            except Exception as e:
                errors.append(e)

        for _ in range(5):
            t = threading.Thread(target=record)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        assert len(errors) == 0
        is_limited, count = limiter.is_rate_limited(
            "threaded_user", max_attempts=1000, window_seconds=300
        )
        assert count == 50  # 5 threads * 10 records each


class TestRateLimiterOrchestrator:
    """Verifies the RateLimiter facade with enabled/disabled modes."""

    def test_disabled_mode(self):
        """When disabled, rate limiter should never block."""
        rl = RateLimiter(max_attempts=3, window_seconds=300, enabled=False)
        for _ in range(10):
            rl.record_attempt("user")
        is_limited, count = rl.is_rate_limited("user")
        assert is_limited is False
        assert count == 0

    def test_enabled_mode_blocks(self):
        """When enabled, rate limiter should block after max_attempts."""
        rl = RateLimiter(max_attempts=3, window_seconds=300, enabled=True)
        for _ in range(3):
            rl.record_attempt("user")
        is_limited, _ = rl.is_rate_limited("user")
        assert is_limited is True

    def test_reset_when_disabled_no_error(self):
        """Reset should not raise when disabled."""
        rl = RateLimiter(enabled=False)
        rl.reset("user")  # should not raise

    def test_record_returns_zero_when_disabled(self):
        """Record should return 0 when disabled."""
        rl = RateLimiter(enabled=False)
        assert rl.record_attempt("user") == 0
