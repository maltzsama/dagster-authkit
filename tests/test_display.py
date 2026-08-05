"""
Unit tests for utils/display.py

Covers:
- print_banner output format
- print_config_summary masking of sensitive keys
- show_security_banner output format
"""

import pytest

from dagster_authkit.utils.display import (
    print_banner,
    print_config_summary,
    show_security_banner,
)


class TestPrintBanner:
    """Verifies the startup banner."""

    def test_prints_dagster_authkit(self, capsys):
        """Banner should mention Dagster AuthKit."""
        print_banner()
        output = capsys.readouterr().out
        assert "DAGSTER AUTHKIT" in output

    def test_returns_none(self):
        """print_banner should return None."""
        assert print_banner() is None


class TestPrintConfigSummary:
    """Verifies configuration summary printing."""

    def test_prints_config_keys(self, capsys):
        """Summary should include non-sensitive config keys."""
        print_config_summary({"AUTH_BACKEND": "sql", "ENV": "production"})
        output = capsys.readouterr().out
        assert "AUTH_BACKEND" in output
        assert "sql" in output

    def test_masks_password(self, capsys):
        """PASSWORD keys should be masked."""
        print_config_summary({"ADMIN_PASSWORD": "secret123"})
        output = capsys.readouterr().out
        assert "********" in output
        assert "secret123" not in output

    def test_masks_secret_key(self, capsys):
        """SECRET_KEY should be masked."""
        print_config_summary({"SECRET_KEY": "my-secret"})
        output = capsys.readouterr().out
        assert "********" in output
        assert "my-secret" not in output

    def test_masks_token(self, capsys):
        """TOKEN keys should be masked."""
        print_config_summary({"OAUTH_TOKEN": "abc123"})
        output = capsys.readouterr().out
        assert "********" in output

    def test_shows_non_sensitive_values(self, capsys):
        """Non-sensitive values should be visible."""
        print_config_summary({"SESSION_MAX_AGE": 86400})
        output = capsys.readouterr().out
        assert "86400" in output

    def test_returns_none(self):
        """print_config_summary should return None."""
        assert print_config_summary({}) is None


class TestShowSecurityBanner:
    """Verifies first-run security banner."""

    def test_prints_admin_password(self, capsys):
        """Banner should display the generated password."""
        show_security_banner("temp-pass-123")
        output = capsys.readouterr().out
        assert "temp-pass-123" in output

    def test_prints_warning_message(self, capsys):
        """Banner should warn user to save the password."""
        show_security_banner("pass")
        output = capsys.readouterr().out
        assert "SAVE THIS PASSWORD" in output

    def test_prints_username_admin(self, capsys):
        """Banner should show username as admin."""
        show_security_banner("pass")
        output = capsys.readouterr().out
        assert "Username: admin" in output

    def test_returns_none(self):
        """show_security_banner should return None."""
        assert show_security_banner("pass") is None
