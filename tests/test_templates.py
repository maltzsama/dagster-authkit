"""
Unit tests for utils/templates.py

Covers:
- render_login_page basic output
- render_login_page XSS escaping
- render_login_page CSRF token injection
- render_login_page error message display
- render_403_page output
- render_403_page XSS escaping
- render_user_menu_injection output
"""

import html

import pytest

from dagster_authkit.auth.backends.base import AuthUser, Role
from dagster_authkit.utils.templates import (
    render_403_page,
    render_login_page,
    render_user_menu_injection,
)


def make_user(username="testuser", role=Role.VIEWER, email="test@test.com", full_name="Test User"):
    return AuthUser(username=username, role=role, email=email, full_name=full_name)


class TestRenderLoginPage:
    """Verifies the login page template."""

    def test_returns_html_string(self):
        """Should return a non-empty string."""
        result = render_login_page()
        assert isinstance(result, str)
        assert len(result) > 0

    def test_contains_doctype(self):
        """Should start with DOCTYPE."""
        result = render_login_page()
        assert "<!DOCTYPE html>" in result

    def test_contains_form(self):
        """Should contain a login form."""
        result = render_login_page()
        assert '<form method="post"' in result
        assert "username" in result
        assert "password" in result

    def test_default_next_url(self):
        """Default next_url should be /."""
        result = render_login_page()
        assert 'value="/"' in result

    def test_custom_next_url(self):
        """Should include the provided next_url."""
        result = render_login_page(next_url="/workspace/my-pipeline")
        assert 'value="/workspace/my-pipeline"' in result

    def test_escapes_next_url(self):
        """next_url should be HTML-escaped."""
        result = render_login_page(next_url='/?foo=<script>alert(1)</script>')
        safe = html.escape('/?foo=<script>alert(1)</script>', quote=True)
        assert safe in result
        assert '<script>alert(1)</script>' not in result

    def test_no_error_div_when_no_error(self):
        """No error div should be present when error is empty."""
        result = render_login_page(error="")
        assert "<div class='error-message'>" not in result

    def test_renders_error_message(self):
        """Should display error message when provided."""
        result = render_login_page(error="Invalid credentials")
        assert "error-message" in result
        assert "Invalid credentials" in result

    def test_escapes_error_message(self):
        """Error message should be HTML-escaped."""
        result = render_login_page(error='<script>alert("xss")</script>')
        safe = html.escape('<script>alert("xss")</script>', quote=True)
        assert safe in result
        assert '<script>alert("xss")</script>' not in result

    def test_includes_csrf_token_hidden_field(self):
        """CSRF token should be in a hidden input."""
        result = render_login_page(csrf_token="csrf-abc-123")
        assert 'name="csrf_token"' in result
        assert 'value="csrf-abc-123"' in result

    def test_escapes_csrf_token(self):
        """CSRF token should be HTML-escaped."""
        result = render_login_page(csrf_token='<script>bad</script>')
        safe = html.escape('<script>bad</script>', quote=True)
        assert safe in result


class TestRender403Page:
    """Verifies the 403 Forbidden page template."""

    def test_returns_html_string(self):
        """Should return a non-empty string."""
        user = make_user()
        result = render_403_page(user, "/graphql", "POST", "Insufficient role")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_contains_403_title(self):
        """Should display 403 Forbidden."""
        user = make_user()
        result = render_403_page(user, "/graphql", "POST", "Insufficient role")
        assert "403 Forbidden" in result

    def test_shows_username(self):
        """Should display the user's username."""
        user = make_user(username="john_doe")
        result = render_403_page(user, "/path", "GET", "reason")
        assert "john_doe" in result

    def test_shows_role(self):
        """Should display the user's role name."""
        user = make_user(role=Role.VIEWER)
        result = render_403_page(user, "/path", "GET", "reason")
        assert Role.VIEWER.name in result

    def test_shows_method_and_path(self):
        """Should display HTTP method and path."""
        user = make_user()
        result = render_403_page(user, "/workspace/assets", "DELETE", "Not allowed")
        assert "DELETE" in result
        assert "/workspace/assets" in result

    def test_shows_reason(self):
        """Should display denial reason."""
        user = make_user()
        result = render_403_page(user, "/path", "GET", "Requires ADMIN role")
        assert "Requires ADMIN role" in result

    def test_escapes_username(self):
        """Username should be HTML-escaped."""
        user = make_user(username='<script>alert(1)</script>')
        result = render_403_page(user, "/path", "GET", "reason")
        safe = html.escape('<script>alert(1)</script>', quote=True)
        assert safe in result
        assert '<script>alert(1)</script>' not in result

    def test_escapes_path(self):
        """Path should be HTML-escaped."""
        user = make_user()
        result = render_403_page(user, '/path?q=<img onerror=alert(1)>', "GET", "reason")
        safe = html.escape('/path?q=<img onerror=alert(1)>', quote=True)
        assert safe in result

    def test_escapes_reason(self):
        """Reason should be HTML-escaped."""
        user = make_user()
        result = render_403_page(user, "/path", "GET", '<b>bad</b>')
        safe = html.escape('<b>bad</b>', quote=True)
        assert safe in result


class TestRenderUserMenuInjection:
    """Verifies the user menu injection script."""

    def test_returns_html_string(self):
        """Should return a non-empty string."""
        result = render_user_menu_injection('{"username": "test"}', debug=False, safe_mode=True)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_contains_user_data(self):
        """Should inject the user JSON data."""
        result = render_user_menu_injection('{"full_name": "John"}', debug=False, safe_mode=True)
        assert '{"full_name": "John"}' in result

    def test_contains_logout_link(self):
        """Should include a logout link."""
        result = render_user_menu_injection('{}', debug=False, safe_mode=True)
        assert "/auth/logout" in result

    def test_debug_disabled_by_default(self):
        """When debug is False, DEBUG should be false."""
        result = render_user_menu_injection('{}', debug=False, safe_mode=True)
        assert "const DEBUG = false" in result

    def test_debug_enabled(self):
        """When debug is True, DEBUG should be true."""
        result = render_user_menu_injection('{}', debug=True, safe_mode=True)
        assert "const DEBUG = true" in result

    def test_safe_mode_enabled(self):
        """When safe_mode is True, SAFE_MODE should be true."""
        result = render_user_menu_injection('{}', debug=False, safe_mode=True)
        assert "const SAFE_MODE = true" in result

    def test_safe_mode_disabled(self):
        """When safe_mode is False, SAFE_MODE should be false."""
        result = render_user_menu_injection('{}', debug=False, safe_mode=False)
        assert "const SAFE_MODE = false" in result

    def test_contains_script_tag(self):
        """Should contain a script block."""
        result = render_user_menu_injection('{}', debug=False, safe_mode=True)
        assert "<script>" in result
        assert "</script>" in result

    def test_contains_style_tag(self):
        """Should contain a style block."""
        result = render_user_menu_injection('{}', debug=False, safe_mode=True)
        assert "<style>" in result
