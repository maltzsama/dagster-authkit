"""
Unit tests for auth/rate_limiter.py

Covers:
- InMemoryRateLimiter: record, check, reset, thread safety
- RateLimiter (orchestrator): disabled mode, enabled mode
- Convenience functions (is_rate_limited, record_login_attempt, reset_rate_limit)
"""

import threading
import time
from unittest.mock import patch

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


class TestInMemoryRateLimiterOOM:
    """Verifies OOM prevention (adversarial key flooding)."""

    @pytest.fixture
    def limiter(self):
        return InMemoryRateLimiter()

    def test_max_tracked_rejects_new_identifiers(self, limiter):
        """When at capacity, new identifiers are rate-limited immediately."""
        # Set a very low max for testability
        limiter._MAX_TRACKED = 5
        window = 300

        # Fill up with 5 distinct identifiers
        for i in range(5):
            limiter.record_attempt(f"user_{i}", window)

        # 6th identifier should be rejected (returns MAX_TRACKED, which > any max_attempts)
        count = limiter.record_attempt("user_new", window)
        assert count == limiter._MAX_TRACKED

    def test_prune_frees_slots(self, limiter):
        """After pruning expired entries, new identifiers are accepted again."""
        limiter._MAX_TRACKED = 5
        window = 1  # 1 second window

        # Fill up
        for i in range(5):
            limiter.record_attempt(f"user_{i}", window)

        # Wait for entries to expire
        import time

        time.sleep(1.1)

        # Force prune check (bypasses the 60s interval by setting last_cleanup back)
        limiter._last_cleanup = 0
        limiter._maybe_prune(window)

        # Should be accepted now
        count = limiter.record_attempt("user_new", window)
        assert count < limiter._MAX_TRACKED

    def test_existing_identifiers_not_rejected_at_capacity(self, limiter):
        """Identifiers already being tracked should still record at capacity."""
        limiter._MAX_TRACKED = 5
        window = 300

        for i in range(5):
            limiter.record_attempt(f"user_{i}", window)

        # user_0 already exists — should accept
        count = limiter.record_attempt("user_0", window)
        assert count == 2  # second attempt

    def test_reset_removes_from_tracking(self, limiter):
        """reset() should remove the identifier, freeing a slot."""
        limiter._MAX_TRACKED = 3
        window = 300

        limiter.record_attempt("user_a", window)
        limiter.record_attempt("user_b", window)
        limiter.record_attempt("user_c", window)

        limiter.reset("user_a")
        # Now user_a should count as 0 again
        _, count = limiter.is_rate_limited("user_a", max_attempts=5, window_seconds=window)
        assert count == 0

    def test_is_rate_limited_cleans_window(self, limiter):
        """Calling is_rate_limited should clean entries outside the window."""
        limiter._MAX_TRACKED = 10
        window = 1
        limiter.record_attempt("user", window)
        import time
        time.sleep(1.1)
        # Force cleanup check
        limiter._last_cleanup = 0
        _, count = limiter.is_rate_limited("user", max_attempts=5, window_seconds=window)
        assert count == 0


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

    def test_check_and_record_disabled(self):
        """check_and_record should never block when disabled."""
        rl = RateLimiter(max_attempts=1, window_seconds=300, enabled=False)
        for _ in range(20):
            limited, count = rl.check_and_record("user")
            assert limited is False
            assert count == 0

    def test_check_and_record_blocks(self):
        """check_and_record should block after max_attempts."""
        rl = RateLimiter(max_attempts=3, window_seconds=300, enabled=True)
        for i in range(2):  # 2 attempts: not limited yet
            limited, _ = rl.check_and_record("user")
            assert limited is False
        # 3rd attempt: check finds 2, records -> 3, returns 3 >= 3 = True
        limited, _ = rl.check_and_record("user")
        assert limited is True

    def test_check_and_record_only_checks_when_disabled(self):
        """When disabled, check_and_record should not record, just return not limited."""
        rl = RateLimiter(max_attempts=1, window_seconds=300, enabled=False)
        limited, count = rl.check_and_record("user")
        assert limited is False
        assert count == 0

    def test_get_rate_limiter_singleton(self):
        """get_rate_limiter should always return the same instance."""
        rl1 = get_rate_limiter()
        rl2 = get_rate_limiter()
        assert rl1 is rl2

    def test_record_login_attempt_disabled(self, monkeypatch):
        """record_login_attempt should return 0 when rate limiter is disabled."""
        monkeypatch.setattr(
            "dagster_authkit.auth.rate_limiter._rate_limiter.enabled", False
        )
        assert record_login_attempt("user") == 0

    def test_is_rate_limited_disabled(self, monkeypatch):
        """is_rate_limited should return False when disabled."""
        monkeypatch.setattr(
            "dagster_authkit.auth.rate_limiter._rate_limiter.enabled", False
        )
        limited, count = is_rate_limited("user")
        assert limited is False

    def test_reset_rate_limit_disabled(self, monkeypatch):
        """reset_rate_limit should not raise when disabled."""
        monkeypatch.setattr(
            "dagster_authkit.auth.rate_limiter._rate_limiter.enabled", False
        )
        reset_rate_limit("user")  # should not raise


class TestRedisRateLimiter:
    """Verifies the Redis-based rate limiter with mocked Redis."""

    @pytest.fixture
    def mock_redis_instance(self):
        """Provide a clean MagicMock for each test."""
        from unittest.mock import MagicMock
        return MagicMock()

    @pytest.fixture
    def limiter(self, monkeypatch, mock_redis_instance):
        """Returns a RedisRateLimiter with mocked Redis."""
        import sys
        from unittest.mock import MagicMock

        mock_redis_module = MagicMock()
        mock_redis_module.from_url = MagicMock(return_value=mock_redis_instance)
        monkeypatch.setitem(sys.modules, "redis", mock_redis_module)
        from dagster_authkit.auth.rate_limiter import RedisRateLimiter
        return RedisRateLimiter(redis_url="redis://localhost:6379/0")

    def test_is_rate_limited_under_limit(self, limiter, mock_redis_instance):
        """Should not be limited when under the limit."""
        mock_redis_instance.get.return_value = "2"
        limited, count = limiter.is_rate_limited("user1", 5, 300)
        assert limited is False
        assert count == 2

    def test_is_rate_limited_at_limit(self, limiter, mock_redis_instance):
        """Should be limited when at the limit."""
        mock_redis_instance.get.return_value = "5"
        limited, count = limiter.is_rate_limited("user1", 5, 300)
        assert limited is True

    def test_is_rate_limited_no_key(self, limiter, mock_redis_instance):
        """Should not be limited when no key exists."""
        mock_redis_instance.get.return_value = None
        limited, count = limiter.is_rate_limited("new_user", 5, 300)
        assert limited is False
        assert count == 0

    def test_is_rate_limited_redis_error(self, limiter, mock_redis_instance):
        """Should fail-closed (block) on Redis error."""
        mock_redis_instance.get.side_effect = Exception("Connection lost")
        limited, count = limiter.is_rate_limited("user1", 5, 300)
        assert limited is True

    def test_record_attempt(self, limiter, mock_redis_instance):
        """record_attempt should return incremented count."""
        mock_redis_instance.incr.return_value = 3
        count = limiter.record_attempt("user1", 300)
        assert count == 3
        assert mock_redis_instance.expire.called

    def test_record_attempt_redis_error(self, limiter, mock_redis_instance):
        """Should return 0 on Redis error."""
        mock_redis_instance.incr.side_effect = Exception("Connection lost")
        count = limiter.record_attempt("user1", 300)
        assert count == 0

    def test_reset(self, limiter, mock_redis_instance):
        """reset should delete the key."""
        limiter.reset("user1")
        assert mock_redis_instance.delete.called

    def test_reset_redis_error(self, limiter, mock_redis_instance):
        """reset should not raise on Redis error."""
        mock_redis_instance.delete.side_effect = Exception("Connection lost")
        limiter.reset("user1")  # should not raise

    def test_check_and_record_first_attempt(self, limiter, mock_redis_instance):
        """First attempt should not be limited and return count 1."""
        mock_redis_instance.eval.return_value = [0, 1]
        limited, count = limiter.check_and_record("user1", 5, 300)
        assert limited is False
        assert count == 1

    def test_check_and_record_under_limit(self, limiter, mock_redis_instance):
        """Under the limit should not be limited."""
        mock_redis_instance.eval.return_value = [0, 3]
        limited, count = limiter.check_and_record("user1", 5, 300)
        assert limited is False
        assert count == 3

    def test_check_and_record_at_limit(self, limiter, mock_redis_instance):
        """At the limit should be limited."""
        mock_redis_instance.eval.return_value = [1, 5]
        limited, count = limiter.check_and_record("user1", 5, 300)
        assert limited is True
        assert count == 5

    def test_check_and_record_already_limited(self, limiter, mock_redis_instance):
        """Already over the limit should be limited."""
        mock_redis_instance.eval.return_value = [1, 7]
        limited, count = limiter.check_and_record("user1", 5, 300)
        assert limited is True
        assert count == 7

    def test_check_and_record_logs_warning_when_limited(self, limiter, mock_redis_instance):
        """Should log warning when rate limited."""
        import dagster_authkit.auth.rate_limiter as rl_mod
        mock_redis_instance.eval.return_value = [1, 5]
        with patch.object(rl_mod.logger, "warning") as mock_warn:
            limited, count = limiter.check_and_record("user1", 5, 300)
            assert limited is True
            mock_warn.assert_called_once()
            msg = mock_warn.call_args[0][0]
            assert "Rate limit triggered" in msg
            assert "user1" in msg

    def test_check_and_record_redis_error_fail_closed(self, limiter, mock_redis_instance):
        """Redis error should fail-closed (block)."""
        mock_redis_instance.eval.side_effect = Exception("Redis down")
        limited, count = limiter.check_and_record("user1", 5, 300)
        assert limited is True
        assert count == 5
