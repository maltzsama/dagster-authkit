"""
Unit tests for auth/backends/dummy.py

Covers:
- DummyAuthBackend authentication with hardcoded users
- get_user lookups
- list_users enumeration
- Unsupported operations (add, delete, change password, change role)
"""

import pytest

from dagster_authkit.auth.backends.base import AuthUser, Role
from dagster_authkit.auth.backends.dummy import DummyAuthBackend


class TestDummyAuthBackend:
    """Verifies the Dummy backend with hardcoded users."""

    @pytest.fixture
    def backend(self):
        """Returns a fresh DummyAuthBackend instance."""
        return DummyAuthBackend(config={})

    # ----------------------------------------------------------
    # get_name
    # ----------------------------------------------------------

    def test_get_name(self, backend):
        """get_name should return 'dummy'."""
        assert backend.get_name() == "dummy"

    # ----------------------------------------------------------
    # authenticate
    # ----------------------------------------------------------

    @pytest.mark.parametrize(
        "username,password,expected_role,expected_email",
        [
            ("admin", "admin", Role.ADMIN, "admin@localhost"),
            ("editor", "editor", Role.EDITOR, "editor@localhost"),
            ("launcher", "launcher", Role.LAUNCHER, "launcher@localhost"),
            ("viewer", "viewer", Role.VIEWER, "viewer@localhost"),
        ],
    )
    def test_authenticate_valid_users(self, backend, username, password, expected_role, expected_email):
        """All four hardcoded users should authenticate with correct credentials."""
        user = backend.authenticate(username, password)
        assert user is not None
        assert user.username == username
        assert user.role == expected_role
        assert user.email == expected_email

    def test_authenticate_wrong_password(self, backend):
        """Authentication should fail with an incorrect password."""
        user = backend.authenticate("admin", "wrongpassword")
        assert user is None

    def test_authenticate_nonexistent_user(self, backend):
        """Authentication should fail for a user that does not exist."""
        user = backend.authenticate("ghost", "password")
        assert user is None

    def test_authenticate_case_sensitive(self, backend):
        """Usernames and passwords should be case-sensitive."""
        user = backend.authenticate("Admin", "admin")
        assert user is None

    # ----------------------------------------------------------
    # get_user
    # ----------------------------------------------------------

    def test_get_user_existing(self, backend):
        """get_user should return user data without checking password."""
        user = backend.get_user("admin")
        assert user is not None
        assert user.username == "admin"
        assert user.role == Role.ADMIN

    def test_get_user_nonexistent(self, backend):
        """get_user should return None for nonexistent users."""
        user = backend.get_user("nobody")
        assert user is None

    # ----------------------------------------------------------
    # list_users
    # ----------------------------------------------------------

    def test_list_users(self, backend):
        """list_users should return all four hardcoded users."""
        users = backend.list_users()
        assert len(users) == 4
        usernames = {u.username for u in users}
        assert usernames == {"admin", "editor", "launcher", "viewer"}

    def test_list_users_all_have_roles(self, backend):
        """All listed users should have valid Role instances."""
        users = backend.list_users()
        for user in users:
            assert isinstance(user.role, Role)

    # ----------------------------------------------------------
    # Unsupported Operations
    # ----------------------------------------------------------

    def test_add_user_returns_false(self, backend):
        """Dummy backend returns False for add_user."""
        assert backend.add_user("new", "pass", Role.VIEWER) is False

    def test_delete_user_returns_false(self, backend):
        """Dummy backend returns False for delete_user."""
        assert backend.delete_user("admin") is False

    def test_change_password_returns_false(self, backend):
        """Dummy backend returns False for change_password."""
        assert backend.change_password("admin", "newpass") is False

    def test_change_role_returns_false(self, backend):
        """Dummy backend returns False for change_role."""
        assert backend.change_role("admin", Role.EDITOR) is False
