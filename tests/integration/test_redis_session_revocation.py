"""
Integration tests: Redis sessions are revoked by account changes.

Redis sessions are not tied to the ``session_version`` column, so the SQL
backend has to clear them explicitly whenever it bumps the version
(password change, role change, user deactivation).

Requires a live Redis; skipped unless ``AUTHKIT_TEST_REDIS_URL`` is set
(e.g. ``redis://127.0.0.1:6379/15``). The Redis database is flushed.
"""

import os

import pytest

from dagster_authkit.auth.backends.base import Role
from dagster_authkit.auth.backends.sql import PeeweeAuthBackend, UserTable
from dagster_authkit.auth.session import RedisBackend, sessions

REDIS_URL = os.getenv("AUTHKIT_TEST_REDIS_URL")

pytestmark = pytest.mark.skipif(not REDIS_URL, reason="AUTHKIT_TEST_REDIS_URL not set")


@pytest.fixture
def redis_sessions(monkeypatch):
    """Global SessionManager backed by the live Redis."""
    backend = RedisBackend(REDIS_URL, max_age=3600)
    backend.client.flushdb()
    monkeypatch.setattr(sessions, "backend", backend)
    yield sessions
    backend.client.flushdb()
    backend.client.close()


@pytest.fixture
def backend(tmp_path):
    be = PeeweeAuthBackend({"DAGSTER_AUTH_DATABASE_URL": f"sqlite:///{tmp_path / 'auth.db'}"})
    be.add_user("alice", "pass", Role.VIEWER)
    be.add_user("bob", "pass", Role.VIEWER)
    yield be
    UserTable.drop_table(safe=True)
    be.db.close()


OPERATIONS = {
    "change_password": lambda be: be.change_password("alice", "newpass"),
    "change_role": lambda be: be.change_role("alice", Role.ADMIN),
    "delete_user": lambda be: be.delete_user("alice"),
}


@pytest.mark.parametrize("operation", OPERATIONS.values(), ids=OPERATIONS.keys())
class TestRedisSessionRevocation:
    def test_all_sessions_of_the_user_are_revoked(self, backend, redis_sessions, operation):
        tokens = [redis_sessions.create({"username": "alice", "role": "VIEWER"}) for _ in range(3)]
        assert all(redis_sessions.validate(t) for t in tokens)

        assert operation(backend) is True

        assert [redis_sessions.validate(t) for t in tokens] == [None, None, None]
        assert redis_sessions.backend.client.exists("user_sess:alice") == 0

    def test_other_users_keep_their_sessions(self, backend, redis_sessions, operation):
        redis_sessions.create({"username": "alice", "role": "VIEWER"})
        bob = redis_sessions.create({"username": "bob", "role": "VIEWER"})

        operation(backend)

        assert redis_sessions.validate(bob)["username"] == "bob"

    def test_session_created_during_revocation_stays_tracked(
        self, backend, redis_sessions, operation, monkeypatch
    ):
        """A login racing with the revocation must not end up outside the
        user's session index, where no later revocation could reach it."""
        redis_sessions.create({"username": "alice", "role": "VIEWER"})
        client = redis_sessions.backend.client
        real_smembers = client.smembers
        racing = []

        def smembers_then_concurrent_login(key):
            snapshot = real_smembers(key)
            if not racing:
                racing.append(redis_sessions.create({"username": "alice", "role": "VIEWER"}))
            return snapshot

        with monkeypatch.context() as m:
            m.setattr(client, "smembers", smembers_then_concurrent_login)
            operation(backend)

        assert client.sismember("user_sess:alice", racing[0])
        redis_sessions.revoke_all("alice")
        assert redis_sessions.validate(racing[0]) is None

    def test_user_can_sign_in_again_afterwards(self, backend, redis_sessions, operation):
        """Revocation only affects sessions that existed at that moment."""
        redis_sessions.create({"username": "alice", "role": "VIEWER"})
        operation(backend)

        fresh = redis_sessions.create({"username": "alice", "role": "VIEWER"})
        assert redis_sessions.validate(fresh)["username"] == "alice"
