"""
Unit tests for auth/backends/proxy.py

Covers:
- ProxyAuthBackend initialization with group patterns
- _parse_groups_header: JSON, LDAP DN, comma/semicolon/pipe, whitespace
- _determine_role_from_groups: priority-based role mapping
- get_user_from_headers: full header extraction flow
- ensure authenticate and get_user raise NotImplementedError
"""

import pytest

from dagster_authkit.auth.backends.base import Role
from dagster_authkit.auth.backends.proxy import ProxyAuthBackend


class TestProxyAuthBackend:
    """Verifies the ProxyAuthBackend for Authelia forward-auth."""

    @pytest.fixture
    def config(self):
        """Provides a minimal valid config for ProxyAuthBackend."""
        return {
            "DAGSTER_AUTH_PROXY_USER_HEADER": "Remote-User",
            "DAGSTER_AUTH_PROXY_GROUPS_HEADER": "Remote-Groups",
            "DAGSTER_AUTH_PROXY_EMAIL_HEADER": "Remote-Email",
            "DAGSTER_AUTH_PROXY_NAME_HEADER": "Remote-Name",
        }

    @pytest.fixture
    def backend(self, config):
        """Returns a fresh ProxyAuthBackend with default config."""
        return ProxyAuthBackend(config)

    # ----------------------------------------------------------
    # get_name
    # ----------------------------------------------------------

    def test_get_name(self, backend):
        """get_name should return 'proxy'."""
        assert backend.get_name() == "proxy"

    # ----------------------------------------------------------
    # authenticate and get_user raise NotImplementedError
    # ----------------------------------------------------------

    def test_authenticate_raises_not_implemented(self, backend):
        """Password auth is not supported in proxy mode."""
        with pytest.raises(NotImplementedError):
            backend.authenticate("user", "pass")

    def test_get_user_raises_not_implemented(self, backend):
        """Direct user lookup is not supported in proxy mode."""
        with pytest.raises(NotImplementedError):
            backend.get_user("user")

    # ----------------------------------------------------------
    # _parse_groups_header
    # ----------------------------------------------------------

    def test_parse_empty_string(self, backend):
        """Empty or None groups should return empty list."""
        assert backend._parse_groups_header("") == []
        assert backend._parse_groups_header(None) == []

    def test_parse_json_array(self, backend):
        """JSON array format should be parsed correctly."""
        groups = backend._parse_groups_header('["admin", "editor"]')
        assert groups == ["admin", "editor"]

    def test_parse_json_array_single(self, backend):
        """Single-element JSON array should be parsed."""
        groups = backend._parse_groups_header('["admin"]')
        assert groups == ["admin"]

    def test_parse_comma_separated(self, backend):
        """Comma-separated simple group names should be split."""
        groups = backend._parse_groups_header("admin,editor,viewer")
        assert groups == ["admin", "editor", "viewer"]

    def test_parse_semicolon_separated(self, backend):
        """Semicolon-separated groups should be split."""
        groups = backend._parse_groups_header("admin;editor")
        assert groups == ["admin", "editor"]

    def test_parse_pipe_separated(self, backend):
        """Pipe-separated groups should be split."""
        groups = backend._parse_groups_header("admin|editor")
        assert groups == ["admin", "editor"]

    def test_parse_ldap_dn_single(self, backend):
        """A single LDAP DN should be returned as one group."""
        groups = backend._parse_groups_header("cn=admins,ou=groups,dc=company,dc=com")
        assert groups == ["cn=admins,ou=groups,dc=company,dc=com"]

    def test_parse_ldap_dn_multiple_semicolon(self, backend):
        """Multiple LDAP DNs separated by semicolons should be split."""
        groups = backend._parse_groups_header(
            "cn=admins,ou=groups,dc=com;cn=editors,ou=groups,dc=com"
        )
        assert len(groups) == 2
        assert "cn=admins,ou=groups,dc=com" in groups

    def test_parse_whitespace_split_fallback(self, backend):
        """Whitespace should be used as a fallback delimiter."""
        groups = backend._parse_groups_header("admin editor viewer")
        assert groups == ["admin", "editor", "viewer"]

    def test_parse_deduplication(self, backend):
        """Duplicate groups should be removed."""
        groups = backend._parse_groups_header("admin,admin,editor,admin")
        assert groups == ["admin", "editor"]

    # ----------------------------------------------------------
    # _determine_role_from_groups
    # ----------------------------------------------------------

    def test_determine_role_admin(self, backend):
        """Groups containing 'admins' should map to ADMIN."""
        role = backend._determine_role_from_groups(["admins", "editors"])
        assert role == Role.ADMIN

    def test_determine_role_editor(self, backend):
        """Groups containing 'editors' should map to EDITOR."""
        role = backend._determine_role_from_groups(["editors", "launchers"])
        assert role == Role.EDITOR

    def test_determine_role_launcher(self, backend):
        """Groups containing 'launchers' should map to LAUNCHER."""
        role = backend._determine_role_from_groups(["launchers"])
        assert role == Role.LAUNCHER

    def test_determine_role_viewer(self, backend):
        """Groups containing 'viewers' should map to VIEWER."""
        role = backend._determine_role_from_groups(["viewers"])
        assert role == Role.VIEWER

    def test_determine_role_defaults_to_viewer(self, backend):
        """Unknown groups should default to VIEWER."""
        role = backend._determine_role_from_groups(["developers"])
        assert role == Role.VIEWER

    def test_determine_role_empty_groups(self, backend):
        """Empty group list should default to VIEWER."""
        role = backend._determine_role_from_groups([])
        assert role == Role.VIEWER

    # ----------------------------------------------------------
    # get_user_from_headers
    # ----------------------------------------------------------

    def test_get_user_from_headers_full(self, backend):
        """Full set of headers should produce a complete AuthUser."""
        headers = {
            "Remote-User": "john",
            "Remote-Groups": "admins",
            "Remote-Email": "john@company.com",
            "Remote-Name": "John Doe",
        }
        user = backend.get_user_from_headers(headers)
        assert user is not None
        assert user.username == "john"
        assert user.role == Role.ADMIN
        assert user.email == "john@company.com"
        assert user.full_name == "John Doe"

    def test_get_user_from_headers_missing_user(self, backend):
        """Missing Remote-User header should return None."""
        user = backend.get_user_from_headers({"Remote-Groups": "admins"})
        assert user is None

    def test_get_user_from_headers_case_insensitive(self, backend):
        """Header keys should be case-insensitive."""
        headers = {
            "remote-user": "jane",
            "remote-groups": "editors",
            "remote-email": "jane@test.com",
        }
        user = backend.get_user_from_headers(headers)
        assert user is not None
        assert user.username == "jane"
        assert user.role == Role.EDITOR

    def test_get_user_from_headers_no_name_fallback(self, backend):
        """Missing name header should fall back to capitalized username."""
        headers = {
            "Remote-User": "bob",
            "Remote-Groups": "viewers",
        }
        user = backend.get_user_from_headers(headers)
        assert user.full_name == "Bob"

    # ----------------------------------------------------------
    # Pattern-based group mapping
    # ----------------------------------------------------------

    def test_ldap_dn_pattern_mapping(self):
        """LDAP DN group pattern should produce the correct role."""
        config = {
            "DAGSTER_AUTH_PROXY_USER_HEADER": "Remote-User",
            "DAGSTER_AUTH_PROXY_GROUPS_HEADER": "Remote-Groups",
            "DAGSTER_AUTH_PROXY_EMAIL_HEADER": "Remote-Email",
            "DAGSTER_AUTH_PROXY_NAME_HEADER": "Remote-Name",
            "DAGSTER_AUTH_PROXY_GROUP_PATTERN": "cn={role},ou=groups,dc=company,dc=com",
        }
        backend = ProxyAuthBackend(config)
        headers = {
            "Remote-User": "alice",
            "Remote-Groups": "cn=editors,ou=groups,dc=company,dc=com",
        }
        user = backend.get_user_from_headers(headers)
        assert user.role == Role.EDITOR

    # ----------------------------------------------------------
    # User management raises NotImplementedError
    # ----------------------------------------------------------

    def test_add_user_raises_not_implemented(self, backend):
        """User management is not supported in proxy mode."""
        with pytest.raises(NotImplementedError):
            backend.add_user("user", "pass", Role.VIEWER)

    def test_delete_user_raises_not_implemented(self, backend):
        with pytest.raises(NotImplementedError):
            backend.delete_user("user")

    def test_change_password_raises_not_implemented(self, backend):
        with pytest.raises(NotImplementedError):
            backend.change_password("user", "newpass")

    def test_list_users_raises_not_implemented(self, backend):
        with pytest.raises(NotImplementedError):
            backend.list_users()

    def test_change_role_raises_not_implemented(self, backend):
        with pytest.raises(NotImplementedError):
            backend.change_role("user", Role.ADMIN)
