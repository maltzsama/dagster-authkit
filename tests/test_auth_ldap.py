"""
Unit tests for dagster_authkit/auth/backends/ldap.py

Covers:
- Initialisation (config validation, TLS, server init, group patterns)
- authenticate (empty password, user not found, bind failure, success, exception)
- get_user (not found, success, exception)
- _find_user_dn (found, not found, exception, connection cleanup)
- _get_user_attributes (success, empty, exception, connection ownership)
- _determine_role (group match, priority, case insensitive, attribute fallback, manual search)
- _get_user_groups_manually (found, not found, exception)
- list_users (success, empty, exception)
- Write operations (add/delete/change_password/change_role all return False)
- Static/helper methods
"""

import sys
from unittest.mock import MagicMock, patch

import pytest

from dagster_authkit.auth.backends.base import AuthUser, Role
from dagster_authkit.auth.backends.ldap import LDAPAuthBackend


# ---------------------------------------------------------------------------
# Fake ldap3 module fixture
# ---------------------------------------------------------------------------

MINIMAL_CONFIG = {
    "DAGSTER_AUTH_LDAP_SERVER": "ldap://localhost:389",
    "DAGSTER_AUTH_LDAP_BASE_DN": "dc=example,dc=com",
}


@pytest.fixture(autouse=True)
def fake_ldap3():
    """Inject a fake ldap3 module into sys.modules so tests don't need ldap3 installed."""
    fake = MagicMock()
    fake.SAFE_SYNC = "SAFE_SYNC"
    fake.SUBTREE = "SUBTREE"
    fake.BASE = "BASE"

    mock_conn = MagicMock()
    fake.Connection = MagicMock(return_value=mock_conn)
    fake.Server = MagicMock(return_value=MagicMock())
    fake.Tls = MagicMock(return_value=MagicMock())

    fake_conv = MagicMock()
    fake_conv.escape_filter_chars = lambda s: s

    saved = {}
    for mod_name in ["ldap3", "ldap3.utils", "ldap3.utils.conv"]:
        saved[mod_name] = sys.modules.get(mod_name)

    sys.modules["ldap3"] = fake
    sys.modules["ldap3.utils"] = MagicMock()
    sys.modules["ldap3.utils"].conv = fake_conv
    sys.modules["ldap3.utils.conv"] = fake_conv

    yield {"ldap3": fake, "connection": mock_conn, "server_cls": fake.Server, "tls_cls": fake.Tls}

    for mod_name, mod_val in saved.items():
        if mod_val is not None:
            sys.modules[mod_name] = mod_val
        else:
            sys.modules.pop(mod_name, None)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def make_backend(config=None, **overrides):
    """Create an LDAPAuthBackend with optional config overrides."""
    cfg = dict(MINIMAL_CONFIG)
    if config:
        cfg.update(config)
    cfg.update(overrides)
    return LDAPAuthBackend(cfg)


# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------


class TestInit:
    def test_minimal_config_creates_server(self):
        backend = make_backend()
        assert backend.server_uri == "ldap://localhost:389"
        assert backend.base_dn == "dc=example,dc=com"
        assert backend.bind_dn is None
        assert backend.bind_password is None
        assert backend.user_filter == "(uid={username})"
        assert backend.use_tls is False
        assert backend.ca_cert is None
        assert backend.role_attribute is None
        assert backend.group_mappings == {}

    def test_missing_server_raises(self):
        with pytest.raises(ValueError, match="Missing LDAP config"):
            make_backend({"DAGSTER_AUTH_LDAP_SERVER": ""})

    def test_missing_base_dn_raises(self):
        with pytest.raises(ValueError, match="Missing LDAP config"):
            make_backend({"DAGSTER_AUTH_LDAP_BASE_DN": ""})

    def test_tls_with_ca_cert(self):
        backend = make_backend(
            DAGSTER_AUTH_LDAP_USE_TLS="true",
            DAGSTER_AUTH_LDAP_CA_CERT="/etc/ldap/ca.pem",
        )
        assert backend.use_tls is True
        assert backend.ca_cert == "/etc/ldap/ca.pem"

    def test_tls_without_ca_cert(self, caplog):
        import logging
        caplog.set_level(logging.WARNING)
        backend = make_backend(DAGSTER_AUTH_LDAP_USE_TLS="true")
        assert backend.use_tls is True
        assert backend.ca_cert is None
        assert any("MITM" in msg for msg in caplog.messages)

    def test_group_pattern_creates_mappings(self):
        backend = make_backend(DAGSTER_AUTH_LDAP_GROUP_PATTERN="cn={role},ou=groups,dc=example,dc=com")
        assert backend.group_mappings == {
            Role.ADMIN: "cn=admins,ou=groups,dc=example,dc=com",
            Role.EDITOR: "cn=editors,ou=groups,dc=example,dc=com",
            Role.LAUNCHER: "cn=launchers,ou=groups,dc=example,dc=com",
            Role.VIEWER: "cn=viewers,ou=groups,dc=example,dc=com",
        }

    def test_bind_credentials_stored(self):
        backend = make_backend(
            DAGSTER_AUTH_LDAP_BIND_DN="cn=admin,dc=example,dc=com",
            DAGSTER_AUTH_LDAP_BIND_PASSWORD="secret",
        )
        assert backend.bind_dn == "cn=admin,dc=example,dc=com"
        assert backend.bind_password == "secret"

    def test_role_attribute_stored(self):
        backend = make_backend(DAGSTER_AUTH_LDAP_ROLE_ATTRIBUTE="title")
        assert backend.role_attribute == "title"

    def test_custom_user_filter(self):
        backend = make_backend(DAGSTER_AUTH_LDAP_USER_FILTER="(sAMAccountName={username})")
        assert backend.user_filter == "(sAMAccountName={username})"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class TestHelpers:
    def test_get_name(self):
        assert make_backend().get_name() == "ldap"

    def test_get_timeout_default(self):
        assert make_backend()._get_timeout() == 10

    def test_get_timeout_from_config(self):
        assert make_backend(DAGSTER_AUTH_LDAP_TIMEOUT="30")._get_timeout() == 30

    def test_get_timeout_invalid_returns_default(self):
        assert make_backend(DAGSTER_AUTH_LDAP_TIMEOUT="abc")._get_timeout() == 10

    def test_build_auth_user(self):
        backend = make_backend()
        attrs = {
            "displayName": ["John Doe"],
            "mail": ["john@example.com"],
            "cn": ["jdoe"],
        }
        user = backend._build_auth_user("jdoe", Role.EDITOR, attrs)
        assert user.username == "jdoe"
        assert user.role == Role.EDITOR
        assert user.email == "john@example.com"
        assert user.full_name == "John Doe"

    def test_build_auth_user_fallback_cn(self):
        backend = make_backend()
        attrs = {"cn": ["jdoe"]}
        user = backend._build_auth_user("jdoe", Role.VIEWER, attrs)
        assert user.full_name == "jdoe"

    def test_build_auth_user_fallback_username(self):
        backend = make_backend()
        user = backend._build_auth_user("jdoe", Role.VIEWER, {})
        assert user.full_name == "jdoe"

    def test_first_value_present(self):
        attrs = {"cn": ["jdoe", "other"]}
        assert LDAPAuthBackend._first_value(attrs, "cn") == "jdoe"

    def test_first_value_missing(self):
        assert LDAPAuthBackend._first_value({}, "cn") == ""

    def test_first_value_custom_default(self):
        assert LDAPAuthBackend._first_value({}, "cn", "fallback") == "fallback"

    def test_get_domain_base_dn(self):
        backend = make_backend()
        backend.base_dn = "ou=users,dc=example,dc=com"
        assert backend._get_domain_base_dn() == "dc=example,dc=com"

    def test_get_domain_base_dn_only_dc(self):
        backend = make_backend()
        backend.base_dn = "dc=example,dc=com"
        assert backend._get_domain_base_dn() == "dc=example,dc=com"

    def test_get_domain_base_dn_no_dc(self):
        backend = make_backend()
        backend.base_dn = "ou=users,o=company"
        assert backend._get_domain_base_dn() == ""


# ---------------------------------------------------------------------------
# authenticate
# ---------------------------------------------------------------------------


class TestAuthenticate:
    def test_empty_password_returns_none(self):
        backend = make_backend()
        assert backend.authenticate("jdoe", "") is None

    def test_user_not_found_returns_none(self, fake_ldap3):
        backend = make_backend()
        conn = fake_ldap3["connection"]
        # _find_user_dn returns None
        conn.search.return_value = (False, [], [], [])
        assert backend.authenticate("jdoe", "pass") is None

    def test_bind_failure_returns_none(self, fake_ldap3):
        backend = make_backend()
        conn = fake_ldap3["connection"]
        conn.search.return_value = (True, [], [{"dn": "cn=jdoe,dc=example,dc=com"}], [])
        conn.bind.return_value = (False, {"description": "invalidCredentials"}, None, None)
        assert backend.authenticate("jdoe", "wrongpass") is None

    def test_success_returns_auth_user(self, fake_ldap3):
        backend = make_backend(DAGSTER_AUTH_LDAP_GROUP_PATTERN="cn={role},ou=groups,dc=example,dc=com")
        conn = fake_ldap3["connection"]

        # _find_user_dn succeeds
        conn.search.return_value = (True, [], [{"dn": "cn=jdoe,dc=example,dc=com"}], [])

        # bind succeeds
        conn.bind.return_value = (True, {"description": "success"}, None, None)

        # _get_user_attributes returns attrs
        # Need to mock the second search call for _get_user_attributes
        conn.search.side_effect = [
            (True, [], [{"dn": "cn=jdoe,dc=example,dc=com"}], []),  # _find_user_dn
            (True, [], [{"dn": "cn=jdoe,dc=example,dc=com", "attributes": {
                "displayName": ["John Doe"],
                "mail": ["john@example.com"],
                "cn": ["jdoe"],
                "memberOf": ["cn=admins,ou=groups,dc=example,dc=com"],
            }}], []),  # _get_user_attributes
        ]

        user = backend.authenticate("jdoe", "correctpass")
        assert user is not None
        assert user.username == "jdoe"
        assert user.role == Role.ADMIN
        assert user.email == "john@example.com"

    def test_exception_caught(self, fake_ldap3):
        backend = make_backend()
        conn = fake_ldap3["connection"]
        conn.search.side_effect = Exception("LDAP down")
        assert backend.authenticate("jdoe", "pass") is None

    def test_connection_unbind_called(self, fake_ldap3):
        """conn.unbind() must be called in authenticate's finally block."""
        backend = make_backend()
        conn = fake_ldap3["connection"]
        conn.search.return_value = (True, [], [{"dn": "cn=jdoe,dc=example,dc=com"}], [])
        conn.bind.return_value = (False, {"description": "fail"}, None, None)
        backend.authenticate("jdoe", "pass")
        assert conn.unbind.call_count >= 1


# ---------------------------------------------------------------------------
# get_user
# ---------------------------------------------------------------------------


class TestGetUser:
    def test_user_not_found_returns_none(self, fake_ldap3):
        backend = make_backend()
        conn = fake_ldap3["connection"]
        conn.search.return_value = (False, [], [], [])
        assert backend.get_user("jdoe") is None

    def test_success_returns_auth_user(self, fake_ldap3):
        backend = make_backend(DAGSTER_AUTH_LDAP_GROUP_PATTERN="cn={role},ou=groups,dc=example,dc=com")
        conn = fake_ldap3["connection"]
        conn.search.side_effect = [
            # _find_user_dn
            (True, [], [{"dn": "cn=jdoe,dc=example,dc=com"}], []),
            # _get_user_attributes
            (True, [], [{"dn": "cn=jdoe,dc=example,dc=com", "attributes": {
                "displayName": ["John Doe"],
                "mail": ["john@example.com"],
                "cn": ["jdoe"],
                "memberOf": ["cn=editors,ou=groups,dc=example,dc=com"],
            }}], []),
        ]
        user = backend.get_user("jdoe")
        assert user is not None
        assert user.username == "jdoe"
        assert user.role == Role.EDITOR

    def test_exception_caught(self, fake_ldap3):
        backend = make_backend()
        conn = fake_ldap3["connection"]
        conn.search.side_effect = Exception("LDAP down")
        assert backend.get_user("jdoe") is None

    def test_connection_unbind_called(self, fake_ldap3):
        backend = make_backend()
        conn = fake_ldap3["connection"]
        conn.search.return_value = (True, [], [{"dn": "cn=jdoe,dc=example,dc=com"}], [])
        backend.get_user("jdoe")
        assert conn.unbind.call_count >= 1


# ---------------------------------------------------------------------------
# _find_user_dn
# ---------------------------------------------------------------------------


class TestFindUserDN:
    def test_found(self, fake_ldap3):
        backend = make_backend()
        conn = fake_ldap3["connection"]
        conn.search.return_value = (True, [], [{"dn": "cn=jdoe,dc=example,dc=com"}], [])
        result = backend._find_user_dn("jdoe")
        assert result == "cn=jdoe,dc=example,dc=com"

    def test_not_found(self, fake_ldap3):
        backend = make_backend()
        conn = fake_ldap3["connection"]
        conn.search.return_value = (False, [], [], [])
        assert backend._find_user_dn("jdoe") is None

    def test_empty_response(self, fake_ldap3):
        backend = make_backend()
        conn = fake_ldap3["connection"]
        conn.search.return_value = (True, [], [], [])
        assert backend._find_user_dn("jdoe") is None

    def test_exception_returns_none(self, fake_ldap3):
        backend = make_backend()
        conn = fake_ldap3["connection"]
        conn.search.side_effect = Exception("timeout")
        assert backend._find_user_dn("jdoe") is None

    def test_connection_unbind_called(self, fake_ldap3):
        backend = make_backend()
        conn = fake_ldap3["connection"]
        conn.search.return_value = (True, [], [{"dn": "cn=jdoe,dc=example,dc=com"}], [])
        backend._find_user_dn("jdoe")
        conn.unbind.assert_called_once()

    def test_unbind_on_exception(self, fake_ldap3):
        backend = make_backend()
        conn = fake_ldap3["connection"]
        conn.search.side_effect = Exception("boom")
        backend._find_user_dn("jdoe")
        conn.unbind.assert_called_once()


# ---------------------------------------------------------------------------
# _get_user_attributes
# ---------------------------------------------------------------------------


class TestGetUserAttributes:
    def test_success(self, fake_ldap3):
        backend = make_backend()
        conn = fake_ldap3["connection"]
        conn.search.return_value = (True, [], [{"dn": "cn=jdoe,dc=com", "attributes": {
            "displayName": ["John"],
            "mail": ["john@c.com"],
        }}], [])
        result = backend._get_user_attributes("cn=jdoe,dc=com")
        assert result["displayName"] == ["John"]
        assert result["mail"] == ["john@c.com"]

    def test_no_response(self, fake_ldap3):
        backend = make_backend()
        conn = fake_ldap3["connection"]
        conn.search.return_value = (False, [], [], [])
        assert backend._get_user_attributes("cn=jdoe,dc=com") == {}

    def test_exception_returns_empty(self, fake_ldap3):
        backend = make_backend()
        conn = fake_ldap3["connection"]
        conn.search.side_effect = Exception("timeout")
        assert backend._get_user_attributes("cn=jdoe,dc=com") == {}

    def test_creates_new_connection_and_unbinds(self, fake_ldap3):
        backend = make_backend()
        conn = fake_ldap3["connection"]
        conn.search.return_value = (True, [], [{"dn": "x", "attributes": {"cn": ["x"]}}], [])
        backend._get_user_attributes("cn=jdoe,dc=com")
        conn.unbind.assert_called_once()

    def test_uses_existing_connection_no_unbind(self, fake_ldap3):
        backend = make_backend()
        existing_conn = MagicMock()
        existing_conn.search.return_value = (True, [], [{"dn": "x", "attributes": {"cn": ["x"]}}], [])
        backend._get_user_attributes("cn=jdoe,dc=com", existing_conn=existing_conn)
        # Connection was passed in, so we should NOT have created a new one
        assert fake_ldap3["connection"].search.call_count == 0
        # And should NOT unbind the existing connection
        existing_conn.unbind.assert_not_called()

    def test_includes_role_attribute(self, fake_ldap3):
        backend = make_backend(DAGSTER_AUTH_LDAP_ROLE_ATTRIBUTE="title")
        conn = fake_ldap3["connection"]
        conn.search.return_value = (True, [], [{"dn": "x", "attributes": {"title": ["Manager"]}}], [])
        result = backend._get_user_attributes("cn=jdoe,dc=com")
        assert result.get("title") == ["Manager"]


# ---------------------------------------------------------------------------
# _determine_role
# ---------------------------------------------------------------------------


class TestDetermineRole:
    def test_match_from_member_of(self):
        backend = make_backend(DAGSTER_AUTH_LDAP_GROUP_PATTERN="cn={role},ou=groups,dc=example,dc=com")
        attrs = {"memberOf": ["cn=admins,ou=groups,dc=example,dc=com"]}
        role = backend._determine_role("cn=jdoe,dc=com", attrs)
        assert role == Role.ADMIN

    def test_priority_admin_over_editor(self):
        backend = make_backend(DAGSTER_AUTH_LDAP_GROUP_PATTERN="cn={role},ou=groups,dc=example,dc=com")
        attrs = {
            "memberOf": [
                "cn=editors,ou=groups,dc=example,dc=com",
                "cn=admins,ou=groups,dc=example,dc=com",
            ]
        }
        role = backend._determine_role("cn=jdoe,dc=com", attrs)
        assert role == Role.ADMIN

    def test_case_insensitive_match(self):
        backend = make_backend(DAGSTER_AUTH_LDAP_GROUP_PATTERN="cn={role},ou=groups,dc=example,dc=com")
        attrs = {"memberOf": ["CN=ADMINS,OU=GROUPS,DC=EXAMPLE,DC=COM"]}
        role = backend._determine_role("cn=jdoe,dc=com", attrs)
        assert role == Role.ADMIN

    def test_no_match_fallback_viewer(self):
        backend = make_backend(DAGSTER_AUTH_LDAP_GROUP_PATTERN="cn={role},ou=groups,dc=example,dc=com")
        attrs = {"memberOf": ["cn=unknown,ou=groups,dc=example,dc=com"]}
        role = backend._determine_role("cn=jdoe,dc=com", attrs)
        assert role == Role.VIEWER

    def test_no_group_mappings_fallback_viewer(self):
        backend = make_backend()
        attrs = {"memberOf": ["cn=admins,ou=groups,dc=example,dc=com"]}
        role = backend._determine_role("cn=jdoe,dc=com", attrs)
        assert role == Role.VIEWER

    def test_empty_member_of_triggers_manual_search(self, fake_ldap3):
        backend = make_backend(DAGSTER_AUTH_LDAP_GROUP_PATTERN="cn={role},ou=groups,dc=example,dc=com")
        attrs = {"memberOf": []}
        conn = fake_ldap3["connection"]
        # manual search returns a matching group
        conn.search.return_value = (True, [], [{"dn": "cn=admins,ou=groups,dc=example,dc=com"}], [])
        role = backend._determine_role("cn=jdoe,dc=com", attrs, conn=conn)
        assert role == Role.ADMIN

    def test_role_attribute_fallback(self):
        backend = make_backend(DAGSTER_AUTH_LDAP_ROLE_ATTRIBUTE="title")
        attrs = {"title": ["EDITOR"]}
        role = backend._determine_role("cn=jdoe,dc=com", attrs)
        assert role == Role.EDITOR

    def test_role_attribute_invalid_fallback_viewer(self):
        backend = make_backend(DAGSTER_AUTH_LDAP_ROLE_ATTRIBUTE="title")
        attrs = {"title": ["SUPERUSER"]}
        role = backend._determine_role("cn=jdoe,dc=com", attrs)
        assert role == Role.VIEWER


# ---------------------------------------------------------------------------
# _get_user_groups_manually
# ---------------------------------------------------------------------------


class TestManualGroupSearch:
    def test_groups_found(self, fake_ldap3):
        backend = make_backend()
        conn = fake_ldap3["connection"]
        conn.search.return_value = (True, [], [
            {"dn": "cn=admins,ou=groups,dc=example,dc=com"},
            {"dn": "cn=editors,ou=groups,dc=example,dc=com"},
        ], [])
        groups = backend._get_user_groups_manually("cn=jdoe,dc=example,dc=com")
        assert "cn=admins,ou=groups,dc=example,dc=com" in groups
        assert "cn=editors,ou=groups,dc=example,dc=com" in groups

    def test_no_groups_returns_empty(self, fake_ldap3):
        backend = make_backend()
        conn = fake_ldap3["connection"]
        conn.search.return_value = (False, [], [], [])
        assert backend._get_user_groups_manually("cn=jdoe,dc=com") == []

    def test_exception_returns_empty(self, fake_ldap3):
        backend = make_backend()
        conn = fake_ldap3["connection"]
        conn.search.side_effect = Exception("timeout")
        assert backend._get_user_groups_manually("cn=jdoe,dc=com") == []

    def test_connection_unbind_called(self, fake_ldap3):
        backend = make_backend()
        conn = fake_ldap3["connection"]
        conn.search.return_value = (False, [], [], [])
        backend._get_user_groups_manually("cn=jdoe,dc=com")
        conn.unbind.assert_called_once()


# ---------------------------------------------------------------------------
# list_users
# ---------------------------------------------------------------------------


class TestListUsers:
    def test_success(self, fake_ldap3):
        backend = make_backend(DAGSTER_AUTH_LDAP_GROUP_PATTERN="cn={role},ou=groups,dc=example,dc=com")
        conn = fake_ldap3["connection"]
        conn.search.return_value = (True, [], [
            {"dn": "cn=jdoe,dc=com", "attributes": {
                "cn": ["jdoe"],
                "displayName": ["John Doe"],
                "mail": ["john@c.com"],
                "memberOf": ["cn=admins,ou=groups,dc=example,dc=com"],
            }},
            {"dn": "cn=jsmith,dc=com", "attributes": {
                "cn": ["jsmith"],
                "displayName": ["Jane Smith"],
                "mail": ["jane@c.com"],
                "memberOf": ["cn=editors,ou=groups,dc=example,dc=com"],
            }},
        ], [])
        users = backend.list_users()
        assert len(users) == 2
        assert users[0].username == "jdoe"
        assert users[0].role == Role.ADMIN
        assert users[1].username == "jsmith"
        assert users[1].role == Role.EDITOR

    def test_no_users(self, fake_ldap3):
        backend = make_backend()
        conn = fake_ldap3["connection"]
        conn.search.return_value = (False, [], [], [])
        assert backend.list_users() == []

    def test_exception_returns_empty(self, fake_ldap3):
        backend = make_backend()
        conn = fake_ldap3["connection"]
        conn.search.side_effect = Exception("timeout")
        assert backend.list_users() == []

    def test_connection_unbind_called(self, fake_ldap3):
        backend = make_backend()
        conn = fake_ldap3["connection"]
        conn.search.return_value = (False, [], [], [])
        backend.list_users()
        conn.unbind.assert_called_once()


# ---------------------------------------------------------------------------
# Write Operations
# ---------------------------------------------------------------------------


class TestWriteOperations:
    def test_add_user_returns_false(self):
        assert make_backend().add_user("x", "y") is False

    def test_delete_user_returns_false(self):
        assert make_backend().delete_user("x") is False

    def test_change_password_returns_false(self):
        assert make_backend().change_password("x", "y") is False

    def test_change_role_returns_false(self):
        assert make_backend().change_role("x", Role.ADMIN) is False
