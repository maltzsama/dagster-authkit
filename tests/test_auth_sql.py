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

from dagster_authkit.auth.backends.base import AuthUser, Role
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
        be1 = PeeweeAuthBackend(sql_config)
        be2 = PeeweeAuthBackend(sql_config)
        users = be2.list_users()
        assert len(users) == 1
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
