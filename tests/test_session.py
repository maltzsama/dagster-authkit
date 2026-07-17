"""
Unit tests for auth/session.py

Covers:
- CookieBackend (stateless): create, validate, revoke, revoke_all, expiration
- SessionManager: create, validate, revoke via singleton
"""

import os
import time
from unittest.mock import patch

import pytest

from dagster_authkit.auth.session import CookieBackend, SessionManager, sessions


class TestCookieBackend:
    """Verifies the stateless cookie-based session backend."""

    @pytest.fixture
    def backend(self):
        """Returns a fresh CookieBackend with a short max_age for testing."""
        return CookieBackend(secret_key="test-secret-key-for-tests", max_age=5)

    @pytest.fixture
    def user_data(self):
        """Returns typical session user data."""
        return {
            "username": "admin",
            "role": "ADMIN",
            "email": "admin@test.com",
            "full_name": "Admin",
        }

    def test_create_returns_token(self, backend, user_data):
        """create should return a non-empty token string."""
        token = backend.create(user_data)
        assert isinstance(token, str)
        assert len(token) > 0

    def test_validate_valid_token(self, backend, user_data):
        """validate should return user data for a valid token."""
        token = backend.create(user_data)
        result = backend.validate(token)
        assert result is not None
        assert result["username"] == "admin"
        assert result["role"] == "ADMIN"

    def test_validate_invalid_token(self, backend):
        """validate should return None for an invalid token."""
        result = backend.validate("invalid-token-here")
        assert result is None

    def test_validate_expired_token(self, backend, user_data):
        """validate should return None for an expired token."""
        backend.max_age = -1  # negative max_age rejects all tokens as expired
        token = backend.create(user_data)
        result = backend.validate(token)
        assert result is None

    def test_validate_logs_warning_on_failure(self, backend):
        """validate should log a warning with exc_info=True on failure."""
        import dagster_authkit.auth.session as sess_mod
        with patch.object(sess_mod.logger, "warning") as mock_warn:
            result = backend.validate("garbage-token")
            assert result is None
            mock_warn.assert_called_once()
            assert mock_warn.call_args[0][0] == "Session validation failed"
            assert mock_warn.call_args[1].get("exc_info") is True

    def test_tokens_are_unique(self, backend, user_data):
        """Tokens with different data or versions should be unique.
        (itsdangerous TimedSerializer uses second-granularity timestamps,
        so same data in same second produces identical tokens.)"""
        token1 = backend.create({**user_data, "username": "user1"})
        token2 = backend.create({**user_data, "username": "user2"})
        assert token1 != token2

    def test_revoke_returns_true(self, backend):
        """revoke should return True (stateless, nothing to do server-side)."""
        assert backend.revoke("any-token") is True

    def test_revoke_all_increments_version(self, backend, user_data):
        """revoke_all should invalidate all existing tokens for a user."""
        token = backend.create(user_data)
        backend.revoke_all("admin")
        result = backend.validate(token)
        assert result is None  # old token should be invalid

    def test_revoke_all_only_affects_specified_user(self, backend, user_data):
        """revoke_all should not affect tokens of other users."""
        token_admin = backend.create({"username": "admin", "role": "ADMIN"})
        token_editor = backend.create({"username": "editor", "role": "EDITOR"})
        backend.revoke_all("admin")
        assert backend.validate(token_admin) is None
        assert backend.validate(token_editor) is not None

    def test_revoke_all_returns_int(self, backend):
        """revoke_all should return an integer."""
        result = backend.revoke_all("admin")
        assert isinstance(result, int)


class TestSessionManager:
    """Verifies the SessionManager singleton."""

    def test_sessions_singleton_exists(self):
        """The global 'sessions' instance should be a SessionManager."""
        assert isinstance(sessions, SessionManager)

    def test_create_and_validate(self):
        """SessionManager should create and validate tokens."""
        user_data = {"username": "testuser", "role": "VIEWER"}
        token = sessions.create(user_data)
        assert token is not None
        result = sessions.validate(token)
        assert result["username"] == "testuser"

    def test_validate_bogus_token(self):
        """SessionManager should return None for an invalid token."""
        assert sessions.validate("not-a-real-token") is None

    def test_revoke_individual_token(self):
        """Revoking a single token should invalidate it via the blocklist."""
        token = sessions.create({"username": "revoketest", "role": "VIEWER"})
        assert sessions.revoke(token) is True
        assert sessions.validate(token) is None


class TestCookieBackendVersioning:
    """Verifies DB-backed session versioning behavior."""

    def test_resolve_version_getter_sql_backend(self, monkeypatch):
        """When AUTH_BACKEND is sql, version getter should be resolved."""
        monkeypatch.setattr(
            "dagster_authkit.utils.config.config.AUTH_BACKEND", "sql"
        )
        backend = CookieBackend(secret_key="test-key", max_age=3600)
        backend._resolve_version_getter()
        assert backend._version_getter is not None
        assert backend._version_getter_resolved is True

    def test_resolve_version_getter_non_sql_backend(self, monkeypatch):
        """When AUTH_BACKEND is not sql/sqlite, no version getter."""
        monkeypatch.setattr(
            "dagster_authkit.utils.config.config.AUTH_BACKEND", "dummy"
        )
        backend = CookieBackend(secret_key="test-key", max_age=3600)
        backend._resolve_version_getter()
        assert backend._version_getter is None

    def test_resolve_idempotent(self, monkeypatch):
        """Calling _resolve_version_getter twice should be idempotent."""
        monkeypatch.setattr(
            "dagster_authkit.utils.config.config.AUTH_BACKEND", "dummy"
        )
        backend = CookieBackend(secret_key="test-key", max_age=3600)
        backend._resolve_version_getter()
        backend._resolve_version_getter()  # should not raise

    def test_current_version_in_memory(self):
        """Without a version getter, should use in-memory versions."""
        backend = CookieBackend(secret_key="test-key", max_age=3600)
        backend._version_getter_resolved = True  # skip resolution
        v = backend._current_version("testuser")
        assert v == 1  # default in-memory version

    def test_current_version_cached(self, monkeypatch):
        """Version should be cached within TTL."""
        mock_getter = __import__("unittest.mock", fromlist=["MagicMock"]).MagicMock
        call_count = 0
        version_values = [3, 4]  # different values to verify caching

        def fake_getter(username):
            nonlocal call_count
            result = version_values[min(call_count, len(version_values) - 1)]
            call_count += 1
            return result

        monkeypatch.setattr(
            "dagster_authkit.utils.config.config.AUTH_BACKEND", "sql"
        )
        backend = CookieBackend(secret_key="test-key", max_age=3600)
        backend._version_getter = fake_getter
        backend._version_getter_resolved = True

        v1 = backend._current_version("user")
        v2 = backend._current_version("user")
        assert v1 == v2  # second call should use cache
        assert call_count == 1  # getter only called once

    def test_revoke_all_db_backed_raises(self, monkeypatch):
        """In DB-backed mode, revoke_all should raise NotImplementedError."""
        monkeypatch.setattr(
            "dagster_authkit.utils.config.config.AUTH_BACKEND", "sql"
        )
        backend = CookieBackend(secret_key="test-key", max_age=3600)
        backend._version_getter = lambda u: 1
        backend._version_getter_resolved = True
        with pytest.raises(NotImplementedError):
            backend.revoke_all("admin")

    def test_prune_expired_revocations(self, monkeypatch):
        """Expired revocations should be removed from memory."""
        backend = CookieBackend(secret_key="test-key", max_age=5)
        backend._revoked = {
            "old-token": time.time() - 100,  # long expired
            "new-token": time.time() + 100,  # still active
        }
        backend._prune_expired_revocations()
        assert "old-token" not in backend._revoked
        assert "new-token" in backend._revoked

    def test_validate_checks_revoked(self):
        """A revoked token should be rejected by validate."""
        backend = CookieBackend(secret_key="test-key", max_age=3600)
        user_data = {"username": "test", "role": "VIEWER"}
        token = backend.create(user_data)
        backend.revoke(token)
        result = backend.validate(token)
        assert result is None

    def test_validate_token_without_username(self):
        """Token without username key should return None."""
        backend = CookieBackend(secret_key="test-key", max_age=3600)
        token = backend.serializer.dumps({"_v": 1})
        result = backend.validate(token)
        assert result is None


class TestRedisBackend:
    """Verifies the Redis-based session backend with mocked Redis."""

    @pytest.fixture
    def mock_redis(self, monkeypatch):
        """Mock redis.Redis for test isolation."""
        import sys
        from unittest.mock import MagicMock

        mock_instance = MagicMock()
        mock_redis_module = MagicMock()
        mock_redis_module.from_url = MagicMock(return_value=mock_instance)
        monkeypatch.setitem(sys.modules, "redis", mock_redis_module)
        return mock_instance

    @pytest.fixture
    def backend(self, mock_redis):
        from dagster_authkit.auth.session import RedisBackend
        return RedisBackend(redis_url="redis://localhost:6379/0", max_age=3600)

    @pytest.fixture
    def user_data(self):
        return {"username": "admin", "role": "ADMIN"}

    def test_create_returns_token(self, backend, user_data, mock_redis):
        mock_redis.setex.return_value = True
        mock_redis.sadd.return_value = 1
        token = backend.create(user_data)
        assert isinstance(token, str)
        assert len(token) == 43  # token_urlsafe(32) base64 length
        assert mock_redis.setex.called
        assert mock_redis.sadd.called

    def test_validate_valid(self, backend, user_data, mock_redis):
        import json
        mock_redis.get.return_value = json.dumps(user_data)
        result = backend.validate("some-token")
        assert result == user_data

    def test_validate_not_found(self, backend, mock_redis):
        mock_redis.get.return_value = None
        result = backend.validate("bogus-token")
        assert result is None

    def test_revoke_existing(self, backend, user_data, mock_redis):
        import json
        mock_redis.get.return_value = json.dumps(user_data)
        mock_redis.delete.return_value = 1
        result = backend.revoke("some-token")
        assert result is True
        assert mock_redis.srem.called

    def test_revoke_non_existing(self, backend, mock_redis):
        mock_redis.get.return_value = None
        mock_redis.delete.return_value = 0
        result = backend.revoke("bogus-token")
        assert result is False

    def test_revoke_all(self, backend, mock_redis):
        mock_redis.smembers.return_value = {"t1", "t2", "t3"}
        mock_redis.delete.return_value = 3
        result = backend.revoke_all("admin")
        assert result == 3
