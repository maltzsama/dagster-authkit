"""
Unit tests for auth/backends/sql.py (PeeweeAuthBackend)

Covers:
- Backend initialization with in-memory SQLite
- User CRUD: add_user, get_user, list_users, delete_user
- Password authentication and verification
- Change password and role
- Admin bootstrap via ADMIN_PASSWORD config
- Soft delete (is_active = False)
"""

import pytest

from dagster_authkit.auth.backends.base import Role
from dagster_authkit.auth.backends.sql import PeeweeAuthBackend, UserTable


@pytest.fixture
def sql_config():
    """Returns config pointing to an in-memory SQLite database."""
    return {
        "DAGSTER_AUTH_DATABASE_URL": "sqlite:///:memory:",
    }


@pytest.fixture
def backend(sql_config):
    """Returns a fresh PeeweeAuthBackend backed by in-memory SQLite."""
    be = PeeweeAuthBackend(sql_config)
    yield be
    # Clean up tables after test
    UserTable.drop_table(safe=True)


class TestPeeweeAuthBackendInitialization:
    """Verifies backend initialization and table creation."""

    def test_get_name(self, backend):
        """get_name should return 'sql'."""
        assert backend.get_name() == "sql"

    def test_table_created(self, backend):
        """The 'users' table should exist after initialization."""
        tables = backend.db.get_tables()
        assert "users" in tables

    def test_admin_bootstrap(self, sql_config):
        """When ADMIN_PASSWORD is set, an admin user should be auto-created."""
        sql_config["ADMIN_PASSWORD"] = "bootpass"
        be = PeeweeAuthBackend(sql_config)
        admin = be.get_user("admin")
        assert admin is not None
        assert admin.role == Role.ADMIN
        UserTable.drop_table(safe=True)

    def test_admin_bootstrap_idempotent(self, sql_config):
        """Bootstrapping twice should not create a duplicate admin."""
        sql_config["ADMIN_PASSWORD"] = "bootpass"
        PeeweeAuthBackend(sql_config)
        be2 = PeeweeAuthBackend(sql_config)
        users = be2.list_users()
        assert len(users) == 1
        UserTable.drop_table(safe=True)

    def test_admin_bootstrap_custom_username(self, sql_config):
        """When ADMIN_USER is set, the admin should use that username."""
        sql_config["ADMIN_USER"] = "root"
        sql_config["ADMIN_PASSWORD"] = "bootpass"
        be = PeeweeAuthBackend(sql_config)
        admin = be.get_user("root")
        assert admin is not None
        assert admin.role == Role.ADMIN
        UserTable.drop_table(safe=True)


class TestPeeweeAuthBackendUserManagement:
    """Verifies user CRUD operations."""

    def test_add_user(self, backend):
        """add_user should create a user that can be retrieved."""
        result = backend.add_user(
            username="testuser",
            password="password123",
            role=Role.EDITOR,
            email="test@test.com",
            full_name="Test User",
        )
        assert result is True
        user = backend.get_user("testuser")
        assert user is not None
        assert user.username == "testuser"
        assert user.role == Role.EDITOR
        assert user.email == "test@test.com"
        assert user.full_name == "Test User"

    def test_add_user_duplicate_fails(self, backend):
        """Adding a duplicate username should return False."""
        backend.add_user("dup", "pass1", Role.VIEWER)
        result = backend.add_user("dup", "pass2", Role.EDITOR)
        assert result is False

    def test_get_user_nonexistent(self, backend):
        """get_user should return None for nonexistent users."""
        assert backend.get_user("nobody") is None

    def test_list_users(self, backend):
        """list_users should return all users."""
        backend.add_user("user1", "pass1", Role.VIEWER)
        backend.add_user("user2", "pass2", Role.EDITOR)
        users = backend.list_users()
        assert len(users) == 2
        usernames = {u.username for u in users}
        assert usernames == {"user1", "user2"}

    def test_list_users_empty(self, backend):
        """list_users should return an empty list when no users exist."""
        users = backend.list_users()
        assert len(users) == 0

    def test_delete_user_soft_delete(self, backend):
        """delete_user should set is_active to False (soft delete)."""
        backend.add_user("todelete", "pass", Role.VIEWER)
        result = backend.delete_user("todelete")
        assert result is True
        # get_user returns None for inactive users (implicitly)
        # authenticate should fail for inactive users
        auth_result = backend.authenticate("todelete", "pass")
        assert auth_result is None

    def test_delete_user_nonexistent(self, backend):
        """delete_user should return False for nonexistent users."""
        result = backend.delete_user("nobody")
        assert result is False

    def test_change_password(self, backend):
        """After changing password, old password should fail and new should work."""
        backend.add_user("pwuser", "oldpass", Role.VIEWER)
        result = backend.change_password("pwuser", "newpass")
        assert result is True
        assert backend.authenticate("pwuser", "oldpass") is None
        assert backend.authenticate("pwuser", "newpass") is not None

    def test_change_password_nonexistent(self, backend):
        """Changing password for nonexistent user should return False."""
        result = backend.change_password("ghost", "pass")
        assert result is False

    def test_change_role(self, backend):
        """change_role should update the user's role."""
        backend.add_user("roleuser", "pass", Role.VIEWER)
        result = backend.change_role("roleuser", Role.ADMIN)
        assert result is True
        user = backend.get_user("roleuser")
        assert user.role == Role.ADMIN

    def test_change_role_nonexistent(self, backend):
        """Changing role for nonexistent user should return False."""
        result = backend.change_role("ghost", Role.ADMIN)
        assert result is False


class TestPeeweeAuthBackendAuthentication:
    """Verifies password-based authentication."""

    def test_authenticate_valid(self, backend):
        """Valid credentials should return an AuthUser."""
        backend.add_user("authuser", "secret", Role.LAUNCHER)
        user = backend.authenticate("authuser", "secret")
        assert user is not None
        assert user.username == "authuser"
        assert user.role == Role.LAUNCHER

    def test_authenticate_wrong_password(self, backend):
        """Wrong password should return None."""
        backend.add_user("authuser", "secret", Role.VIEWER)
        assert backend.authenticate("authuser", "wrong") is None

    def test_authenticate_empty_password(self, backend):
        """Empty password should always fail (prevents unauthenticated bind attacks)."""
        backend.add_user("emptyuser", "pass", Role.VIEWER)
        assert backend.authenticate("emptyuser", "") is None

    def test_authenticate_nonexistent_user(self, backend):
        """Nonexistent user should return None."""
        assert backend.authenticate("ghost", "pass") is None

    def test_authenticate_updates_last_login(self, backend):
        """Successful authentication should update last_login timestamp."""
        backend.add_user("loginuser", "pass", Role.VIEWER)
        user_before = UserTable.get(UserTable.username == "loginuser")
        assert user_before.last_login is None
        backend.authenticate("loginuser", "pass")
        user_after = UserTable.get(UserTable.username == "loginuser")
        assert user_after.last_login is not None


class TestStoredSessionRevocation:
    """Verifies that session-invalidating operations also clear stateful
    session stores (Redis), which are not tied to session_version."""

    @pytest.fixture
    def store(self, monkeypatch):
        """Stand-in for the global SessionManager."""
        from unittest.mock import MagicMock

        mock = MagicMock()
        monkeypatch.setattr("dagster_authkit.auth.session.sessions", mock)
        return mock

    @pytest.mark.parametrize(
        "operation",
        [
            lambda be: be.change_password("suser", "newpass"),
            lambda be: be.change_role("suser", Role.ADMIN),
            lambda be: be.delete_user("suser"),
        ],
        ids=["change_password", "change_role", "delete_user"],
    )
    def test_operation_revokes_stored_sessions(self, backend, store, operation):
        backend.add_user("suser", "pass", Role.VIEWER)
        store.revoke_all.assert_not_called()

        assert operation(backend) is True

        store.revoke_all.assert_called_once_with("suser")

    @pytest.mark.parametrize(
        "operation",
        [
            lambda be: be.change_password("ghost", "newpass"),
            lambda be: be.change_role("ghost", Role.ADMIN),
            lambda be: be.delete_user("ghost"),
        ],
        ids=["change_password", "change_role", "delete_user"],
    )
    def test_unknown_user_revokes_nothing(self, backend, store, operation):
        assert operation(backend) is False
        store.revoke_all.assert_not_called()

    def test_only_target_user_is_revoked(self, backend, store):
        backend.add_user("suser", "pass", Role.VIEWER)
        backend.add_user("other", "pass", Role.VIEWER)
        backend.change_password("suser", "newpass")
        assert [c.args for c in store.revoke_all.call_args_list] == [("suser",)]

    def test_db_backed_cookie_sessions_need_no_store_revocation(self, backend, store):
        """CookieBackend raises NotImplementedError in DB-backed mode; the
        version bump alone invalidates those sessions."""
        store.revoke_all.side_effect = NotImplementedError
        backend.add_user("suser", "pass", Role.VIEWER)

        assert backend.change_password("suser", "newpass") is True
        assert PeeweeAuthBackend.get_session_version("suser") == 2

    def test_session_module_import_failure_does_not_fail_the_operation(
        self, backend, monkeypatch, caplog
    ):
        """E.g. Redis configured but the redis package missing in a CLI image:
        building the session manager on first import raises."""
        import builtins

        real_import = builtins.__import__

        def failing_import(name, *args, **kwargs):
            if name == "dagster_authkit.auth.session":
                raise ModuleNotFoundError("No module named 'redis'")
            return real_import(name, *args, **kwargs)

        backend.add_user("suser", "pass", Role.VIEWER)
        monkeypatch.setattr(builtins, "__import__", failing_import)

        with caplog.at_level("ERROR"):
            assert backend.change_password("suser", "newpass") is True
            assert backend.change_role("suser", Role.ADMIN) is True
            assert backend.delete_user("suser") is True

        assert PeeweeAuthBackend.get_session_version("suser") == 4
        assert "Failed to revoke stored sessions for 'suser'" in caplog.text

    def test_store_failure_does_not_fail_the_operation(self, backend, store, caplog):
        """The change is already committed; a store outage is logged only."""
        store.revoke_all.side_effect = ConnectionError("redis down")
        backend.add_user("suser", "pass", Role.VIEWER)

        with caplog.at_level("ERROR"):
            assert backend.change_password("suser", "newpass") is True

        assert backend.authenticate("suser", "newpass") is not None
        assert PeeweeAuthBackend.get_session_version("suser") == 2
        assert "Failed to revoke stored sessions for 'suser'" in caplog.text

    def test_version_is_bumped_before_store_revocation(self, backend, store):
        """A session created between the two steps must not survive."""
        seen = []
        store.revoke_all.side_effect = lambda u: seen.append(
            PeeweeAuthBackend.get_session_version(u)
        )
        backend.add_user("suser", "pass", Role.VIEWER)
        backend.change_password("suser", "newpass")
        assert seen == [2]
