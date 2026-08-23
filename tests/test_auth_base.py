"""
Unit tests for auth/backends/base.py

Covers:
- Role enum hierarchy and comparisons
- RolePermissions mutation resolution and role inheritance
- AuthUser dataclass creation, serialization, and permission checks
- AuthBackend ABC contract
"""

import pytest

from dagster_authkit.auth.backends.base import (
    AuthBackend,
    AuthUser,
    Role,
    RolePermissions,
)

# ============================================================
# Role Enum Tests
# ============================================================


class TestRoleEnum:
    """Verifies the Role IntEnum hierarchy and comparison behavior."""

    def test_role_values(self):
        """Roles should have the correct numeric values for hierarchical comparison."""
        assert Role.VIEWER.value == 10
        assert Role.LAUNCHER.value == 20
        assert Role.EDITOR.value == 30
        assert Role.ADMIN.value == 40

    def test_role_comparison_gt(self):
        """ADMIN > EDITOR > LAUNCHER > VIEWER using greater-than."""
        assert Role.ADMIN > Role.EDITOR
        assert Role.EDITOR > Role.LAUNCHER
        assert Role.LAUNCHER > Role.VIEWER

    def test_role_comparison_gte(self):
        """Roles should be >= themselves."""
        assert Role.ADMIN >= Role.ADMIN
        assert Role.EDITOR >= Role.EDITOR
        assert Role.VIEWER >= Role.VIEWER

    def test_role_comparison_lt(self):
        """VIEWER < LAUNCHER < EDITOR < ADMIN using less-than."""
        assert Role.VIEWER < Role.LAUNCHER
        assert Role.LAUNCHER < Role.EDITOR
        assert Role.EDITOR < Role.ADMIN

    def test_role_string_name(self):
        """Role.name should return the string representation."""
        assert Role.ADMIN.name == "ADMIN"
        assert Role.VIEWER.name == "VIEWER"

    def test_role_from_string(self):
        """Role can be looked up by name string."""
        assert Role["ADMIN"] == Role.ADMIN
        assert Role["VIEWER"] == Role.VIEWER

    def test_role_from_invalid_string(self):
        """Looking up a nonexistent role should raise KeyError."""
        with pytest.raises(KeyError):
            Role["SUPERADMIN"]


# ============================================================
# RolePermissions Tests
# ============================================================


class TestRolePermissions:
    """Verifies mutation-to-role resolution and hierarchical permission checks."""

    def test_get_required_role_launcher_mutation(self):
        """launchRun should require LAUNCHER role."""
        assert RolePermissions.get_required_role("launchRun") == Role.LAUNCHER
        assert RolePermissions.get_required_role("terminateRun") == Role.LAUNCHER

    def test_get_required_role_editor_mutation(self):
        """startSchedule should require EDITOR role."""
        assert RolePermissions.get_required_role("startSchedule") == Role.EDITOR
        assert RolePermissions.get_required_role("wipeAssets") == Role.EDITOR

    def test_get_required_role_admin_mutation(self):
        """reloadWorkspace should require ADMIN role."""
        assert RolePermissions.get_required_role("reloadWorkspace") == Role.ADMIN

    def test_get_required_role_unrestricted(self):
        """A mutation not in any set should return None (no restriction)."""
        assert RolePermissions.get_required_role("logTelemetry") is None

    def test_can_execute_viewer_cannot_launch(self):
        """VIEWER should not be able to execute launchRun."""
        assert RolePermissions.can_execute(Role.VIEWER, "launchRun") is False

    def test_can_execute_launcher_can_launch(self):
        """LAUNCHER should be able to execute launchRun."""
        assert RolePermissions.can_execute(Role.LAUNCHER, "launchRun") is True

    def test_can_execute_admin_can_do_anything(self):
        """ADMIN should be able to execute any mutation (hierarchy)."""
        assert RolePermissions.can_execute(Role.ADMIN, "launchRun") is True
        assert RolePermissions.can_execute(Role.ADMIN, "startSchedule") is True
        assert RolePermissions.can_execute(Role.ADMIN, "reloadWorkspace") is True

    def test_can_execute_editor_can_launch(self):
        """EDITOR inherits LAUNCHER permissions."""
        assert RolePermissions.can_execute(Role.EDITOR, "launchRun") is True

    def test_can_execute_unrestricted_mutation(self):
        """Any role can execute unrestricted mutations."""
        assert RolePermissions.can_execute(Role.VIEWER, "logTelemetry") is True

    def test_get_required_role_unknown_with_default(self):
        """Unknown mutations should return the configured default_role (deny-by-default)."""
        assert RolePermissions.get_required_role("newDagsterMutation", Role.ADMIN) == Role.ADMIN

    def test_get_required_role_unknown_without_default(self):
        """Unknown mutations without default_role should return None (backward compat)."""
        assert RolePermissions.get_required_role("newDagsterMutation") is None

    def test_can_execute_unknown_with_default_admin(self):
        """VIEWER should be blocked from unknown mutations when default is ADMIN."""
        assert (
            RolePermissions.can_execute(Role.VIEWER, "newDagsterMutation") is True
        )  # no default set on can_execute
        # But get_required_role with default blocks:
        assert RolePermissions.get_required_role("newDagsterMutation", Role.ADMIN) == Role.ADMIN

    def test_can_execute_deny_by_default_with_admin(self):
        """Passing default_role=ADMIN to can_execute blocks unknown mutations."""
        assert (
            RolePermissions.can_execute(Role.VIEWER, "newDagsterMutation", default_role=Role.ADMIN)
            is False
        )
        assert (
            RolePermissions.can_execute(Role.ADMIN, "newDagsterMutation", default_role=Role.ADMIN)
            is True
        )

    def test_list_permissions_viewer(self):
        """VIEWER should have no mutation permissions."""
        perms = RolePermissions.list_permissions(Role.VIEWER)
        assert len(perms) == 0

    def test_list_permissions_launcher(self):
        """LAUNCHER should have only launcher mutations."""
        perms = RolePermissions.list_permissions(Role.LAUNCHER)
        assert "launchRun" in perms
        assert "startSchedule" not in perms

    def test_list_permissions_editor(self):
        """EDITOR should have editor + launcher mutations."""
        perms = RolePermissions.list_permissions(Role.EDITOR)
        assert "launchRun" in perms  # inherited
        assert "startSchedule" in perms
        assert "reloadWorkspace" not in perms

    def test_list_permissions_admin(self):
        """ADMIN should have all mutations."""
        perms = RolePermissions.list_permissions(Role.ADMIN)
        assert "launchRun" in perms
        assert "startSchedule" in perms
        assert "reloadWorkspace" in perms


# ============================================================
# AuthUser Tests
# ============================================================


class TestAuthUser:
    """Verifies AuthUser dataclass creation, serialization, and permission checks."""

    def test_create_minimal_user(self):
        """AuthUser can be created with only required fields."""
        user = AuthUser(username="test", role=Role.VIEWER)
        assert user.username == "test"
        assert user.role == Role.VIEWER
        assert user.email == ""
        assert user.full_name == ""

    def test_create_full_user(self):
        """AuthUser holds all optional fields correctly."""
        user = AuthUser(
            username="jane",
            role=Role.ADMIN,
            email="jane@example.com",
            full_name="Jane Doe",
        )
        assert user.email == "jane@example.com"
        assert user.full_name == "Jane Doe"

    def test_can_method(self):
        """AuthUser.can() uses hierarchical comparison."""
        user = AuthUser(username="editor", role=Role.EDITOR)
        assert user.can(Role.LAUNCHER) is True  # 30 >= 20
        assert user.can(Role.EDITOR) is True  # 30 >= 30
        assert user.can(Role.ADMIN) is False  # 30 < 40

    def test_display_name_with_full_name(self):
        """display_name should return full_name when available."""
        user = AuthUser(username="john", role=Role.VIEWER, full_name="John Smith")
        assert user.display_name == "John Smith"

    def test_display_name_fallback_to_username(self):
        """display_name should fall back to username when full_name is empty."""
        user = AuthUser(username="john", role=Role.VIEWER)
        assert user.display_name == "john"

    def test_to_dict(self):
        """to_dict should serialize role as int for cross-backend consistency."""
        user = AuthUser(
            username="admin",
            role=Role.ADMIN,
            email="admin@test.com",
            full_name="Admin",
        )
        result = user.to_dict()
        assert result == {
            "username": "admin",
            "role": 40,
            "email": "admin@test.com",
            "full_name": "Admin",
        }

    def test_from_dict_with_string_role(self):
        """from_dict should handle role as string name."""
        data = {
            "username": "editor",
            "role": "EDITOR",
            "email": "e@test.com",
            "full_name": "Ed",
        }
        user = AuthUser.from_dict(data)
        assert user.username == "editor"
        assert user.role == Role.EDITOR

    def test_from_dict_with_int_role(self):
        """from_dict should handle role as integer value."""
        data = {"username": "admin", "role": 40}
        user = AuthUser.from_dict(data)
        assert user.role == Role.ADMIN

    def test_from_dict_without_optional_fields(self):
        """from_dict should default missing optional fields to empty strings."""
        data = {"username": "viewer", "role": "VIEWER"}
        user = AuthUser.from_dict(data)
        assert user.email == ""
        assert user.full_name == ""

    def test_to_dict_from_dict_roundtrip(self):
        """Serializing and deserializing should produce an equivalent user."""
        original = AuthUser(
            username="roundtrip",
            role=Role.LAUNCHER,
            email="rt@test.com",
            full_name="Round Trip",
        )
        recreated = AuthUser.from_dict(original.to_dict())
        assert recreated.username == original.username
        assert recreated.role == original.role
        assert recreated.email == original.email
        assert recreated.full_name == original.full_name


# ============================================================
# AuthBackend ABC Tests
# ============================================================


class TestAuthBackendABC:
    """Verifies that the abstract AuthBackend enforces its contract."""

    def test_cannot_instantiate_abstract_backend(self):
        """Instantiating the ABC directly should raise TypeError."""
        with pytest.raises(TypeError):
            AuthBackend(config={})

    def test_abstract_methods_defined(self):
        """The ABC should define the three required abstract methods."""
        assert hasattr(AuthBackend, "authenticate")
        assert hasattr(AuthBackend, "get_user")
        assert hasattr(AuthBackend, "get_name")

    def test_optional_methods_raise_not_implemented(self):
        """Optional methods should raise NotImplementedError by default."""

        # We need a concrete subclass to test the default implementation
        class MinimalBackend(AuthBackend):
            def authenticate(self, username, password):
                return None

            def get_user(self, username):
                return None

            def get_name(self):
                return "minimal"

        backend = MinimalBackend(config={})
        with pytest.raises(NotImplementedError):
            backend.add_user("test", "pass", Role.VIEWER)
        with pytest.raises(NotImplementedError):
            backend.delete_user("test")
        with pytest.raises(NotImplementedError):
            backend.change_password("test", "newpass")
        with pytest.raises(NotImplementedError):
            backend.list_users()
        with pytest.raises(NotImplementedError):
            backend.change_role("test", Role.ADMIN)
