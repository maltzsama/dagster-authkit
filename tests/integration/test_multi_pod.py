"""
Multi-pod integration tests for dagster-authkit.

Validates that auth works correctly across pod boundaries without Docker:
- CSRF tokens signed on one "pod" validate on another (same SECRET_KEY)
- Session tokens created on one instance persist on another
- Session revocation with CookieBackend (process-local limitation documented)
"""

from itsdangerous import URLSafeTimedSerializer

from dagster_authkit.auth.backends.base import AuthUser, Role
from dagster_authkit.auth.session import CookieBackend


class TestCrossPodSessions:
    """
    Simulates two pods with the same SECRET_KEY and config.
    Validates that signed tokens produced by one pod validate on the other.
    """

    @staticmethod
    def _make_pods():
        """Create two CookieBackend instances with identical config (same SECRET_KEY)."""
        key = "test-cross-pod-secret-key"
        return CookieBackend(key, max_age=3600), CookieBackend(key, max_age=3600)

    def test_session_created_on_pod_a_validates_on_pod_b(self):
        """A session token from pod A should validate on pod B with same key."""
        pod_a, pod_b = self._make_pods()
        user_data = {"username": "admin", "role": Role.ADMIN.value, "email": "", "full_name": ""}

        token = pod_a.create(user_data)
        result = pod_b.validate(token)

        assert result is not None
        assert result["username"] == "admin"

    def test_tokens_invalid_with_different_key(self):
        """Tokens signed with a different key should not validate (security)."""
        pod_a = CookieBackend("key-alpha", max_age=3600)
        pod_b = CookieBackend("key-beta", max_age=3600)

        token = pod_a.create({"username": "admin", "role": Role.ADMIN.value})
        result = pod_b.validate(token)

        assert result is None

    def test_revoke_all_across_pods_is_process_local(self):
        """
        revoke_all() on pod A bumps the version on pod A only.
        Pod B does NOT see the bump — this is a known limitation of
        the stateless CookieBackend. Production multi-pod deployments
        should use RedisBackend or the DB-backed session version column.
        """
        pod_a, pod_b = self._make_pods()
        user_data = {"username": "admin", "role": Role.ADMIN.value}

        token = pod_a.create(user_data)
        assert pod_a.validate(token) is not None
        assert pod_b.validate(token) is not None

        # Revoke all on pod A only
        pod_a.revoke_all("admin")
        assert pod_a.validate(token) is None

        # Known limitation: pod B still validates the old token
        assert pod_b.validate(token) is not None


class TestCrossPodCSRF:
    """Validates that CSRF tokens work across pods with the same SECRET_KEY."""

    def test_csrf_token_from_one_serializer_validates_on_another(self):
        """CSRF tokens signed with the same key validate across instances."""
        key = "test-cross-pod-csrf-key"
        s1 = URLSafeTimedSerializer(key)
        s2 = URLSafeTimedSerializer(key)

        raw_token = s1.dumps({"token": "abc123"})
        # Validation on pod B
        data = s2.loads(raw_token, max_age=3600)
        assert data["token"] == "abc123"

    def test_csrf_token_invalid_with_different_key(self):
        """CSRF tokens from a different key should not validate."""
        s1 = URLSafeTimedSerializer("key-alpha")
        s2 = URLSafeTimedSerializer("key-beta")

        raw_token = s1.dumps({"token": "abc"})

        import pytest

        with pytest.raises(Exception):
            s2.loads(raw_token, max_age=3600)
