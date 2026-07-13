"""
Unit tests for auth/session.py

Covers:
- CookieBackend (stateless): create, validate, revoke, revoke_all, expiration
- SessionManager: create, validate, revoke via singleton
"""

import os
import time

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
        """Stateless cookie backend: revoke returns True but does not invalidate the token."""
        token = sessions.create({"username": "revoketest", "role": "VIEWER"})
        assert sessions.revoke(token) is True
        # With stateless CookieBackend, the token remains valid after revoke.
        # Server-side invalidation requires revoke_all() which bumps the version.
        assert sessions.validate(token) is not None
