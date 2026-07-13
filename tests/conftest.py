"""
Shared fixtures and configuration for dagster-authkit test suite.

Provides reusable test data, mock objects, and environment setup
to keep tests DRY and maintainable.
"""

import os

# Must be set BEFORE dagster_authkit modules are imported, because
# AuthConfig runs at module level and fails in production without a key.
os.environ.setdefault("DAGSTER_AUTH_ENV", "testing")
os.environ.setdefault("DAGSTER_AUTH_SECRET_KEY", "test-secret-key-for-pytest")
os.environ.setdefault("DAGSTER_AUTH_BACKEND", "dummy")  # default for tests without DB

import tempfile
from unittest.mock import MagicMock, patch

import pytest

from dagster_authkit.auth.backends.base import AuthUser, Role


@pytest.fixture
def admin_user():
    """Returns an AuthUser with ADMIN role."""
    return AuthUser(
        username="admin",
        role=Role.ADMIN,
        email="admin@localhost",
        full_name="System Administrator",
    )


@pytest.fixture
def editor_user():
    """Returns an AuthUser with EDITOR role."""
    return AuthUser(
        username="editor",
        role=Role.EDITOR,
        email="editor@localhost",
        full_name="Editor User",
    )


@pytest.fixture
def launcher_user():
    """Returns an AuthUser with LAUNCHER role."""
    return AuthUser(
        username="launcher",
        role=Role.LAUNCHER,
        email="launcher@localhost",
        full_name="Launcher User",
    )


@pytest.fixture
def viewer_user():
    """Returns an AuthUser with VIEWER role."""
    return AuthUser(
        username="viewer",
        role=Role.VIEWER,
        email="viewer@localhost",
        full_name="Viewer User",
    )


@pytest.fixture
def all_users(admin_user, editor_user, launcher_user, viewer_user):
    """Returns a list of all four standard role users."""
    return [admin_user, editor_user, launcher_user, viewer_user]


@pytest.fixture
def mock_config_dict():
    """Returns a minimal config dictionary for backend initialization."""
    return {
        "ENV": "test",
        "SECRET_KEY": "test-secret-key-for-testing-purposes-only",
        "SESSION_COOKIE_NAME": "test_session",
        "SESSION_MAX_AGE": 3600,
        "AUTH_BACKEND": "dummy",
        "RATE_LIMIT_ENABLED": False,
    }


@pytest.fixture
def proxy_headers():
    """Returns typical Authelia forward-auth headers."""
    return {
        "Remote-User": "john",
        "Remote-Groups": "admins,editors",
        "Remote-Email": "john@company.com",
        "Remote-Name": "John Doe",
    }


@pytest.fixture
def mock_request():
    """Returns a MagicMock simulating a Starlette Request."""
    request = MagicMock()
    request.url.path = "/"
    request.method = "GET"
    request.cookies = {}
    request.headers = {}
    request.query_params = {}
    return request


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Reset relevant environment variables before each test to avoid leakage."""
    monkeypatch.setenv("DAGSTER_AUTH_ENV", "testing")
    monkeypatch.setenv("DAGSTER_AUTH_SECRET_KEY", "test-secret-key-for-pytest")
    monkeypatch.setenv("DAGSTER_AUTH_BACKEND", "dummy")
    env_vars = [
        "DAGSTER_AUTH_COOKIE_NAME",
        "DAGSTER_AUTH_SESSION_MAX_AGE",
        "DAGSTER_AUTH_DB",
        "DAGSTER_AUTH_DATABASE_URL",
        "DAGSTER_AUTH_REDIS_URL",
        "DAGSTER_AUTH_RATE_LIMIT",
        "DAGSTER_AUTH_ADMIN_PASSWORD",
        "DAGSTER_AUTH_ENV",
        "DAGSTER_AUTH_LOG_LEVEL",
    ]
    for var in env_vars:
        monkeypatch.delenv(var, raising=False)
