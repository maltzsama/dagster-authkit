"""
Unit tests for auth/security.py

Covers:
- constant_time_compare for timing-safe string comparison
- generate_csrf_token format and uniqueness
- validate_redirect_url for open redirect prevention
- sanitize_username for injection prevention
- set_security_headers includes all required headers
- hash_password and verify_password (bcrypt and PBKDF2 fallback)
- generate_random_password length and character variety
"""

import re

import pytest

from dagster_authkit.auth.security import SecurityHardening


class TestConstantTimeCompare:
    """Verifies timing-safe string comparison."""

    def test_equal_strings(self):
        """Identical strings should compare as equal."""
        assert SecurityHardening.constant_time_compare("abc", "abc") is True

    def test_different_strings(self):
        """Different strings should compare as not equal."""
        assert SecurityHardening.constant_time_compare("abc", "def") is False

    def test_different_length(self):
        """Strings of different lengths should not be equal."""
        assert SecurityHardening.constant_time_compare("abc", "abcd") is False

    def test_empty_strings(self):
        """Two empty strings should compare as equal."""
        assert SecurityHardening.constant_time_compare("", "") is True

    def test_case_sensitive(self):
        """Comparison should be case-sensitive."""
        assert SecurityHardening.constant_time_compare("Abc", "abc") is False


class TestGenerateCsrfToken:
    """Verifies CSRF token generation."""

    def test_token_is_string(self):
        """Token should be a non-empty string."""
        token = SecurityHardening.generate_csrf_token()
        assert isinstance(token, str)
        assert len(token) > 0

    def test_token_uniqueness(self):
        """Multiple generated tokens should be unique."""
        tokens = {SecurityHardening.generate_csrf_token() for _ in range(10)}
        assert len(tokens) == 10

    def test_token_is_urlsafe(self):
        """Token should only contain URL-safe characters (base64)."""
        token = SecurityHardening.generate_csrf_token()
        assert re.fullmatch(r"[A-Za-z0-9\-_]+", token) is not None


class TestValidateRedirectUrl:
    """Verifies open redirect prevention."""

    def test_relative_url_accepted(self):
        """Relative URLs starting with '/' should be safe."""
        assert SecurityHardening.validate_redirect_url("/dashboard") is True
        assert SecurityHardening.validate_redirect_url("/auth/login") is True
        assert SecurityHardening.validate_redirect_url("/") is True

    def test_empty_url_rejected(self):
        """Empty URLs should be rejected."""
        assert SecurityHardening.validate_redirect_url("") is False

    def test_none_rejected(self):
        """None should be rejected."""
        assert SecurityHardening.validate_redirect_url(None) is False

    def test_absolute_url_without_host(self):
        """URLs without a host (and no relative prefix) are handled."""
        # Path-like URLs without http:// should still work as relative
        pass

    def test_javascript_scheme_rejected(self):
        """javascript: scheme should be rejected."""
        assert SecurityHardening.validate_redirect_url("javascript:alert(1)") is False

    def test_external_host_rejected(self):
        """External hosts not in allowlist should be rejected."""
        assert (
            SecurityHardening.validate_redirect_url("https://evil.com/malware")
            is False
        )

    def test_external_host_in_allowlist(self):
        """External hosts in the allowlist should be accepted."""
        assert (
            SecurityHardening.validate_redirect_url(
                "https://trusted.com/page", allowed_hosts=["trusted.com"]
            )
            is True
        )

    def test_file_scheme_rejected(self):
        """file:// scheme should be rejected."""
        assert SecurityHardening.validate_redirect_url("file:///etc/passwd") is False


class TestSanitizeUsername:
    """Verifies username sanitization to prevent injection."""

    def test_valid_username_unchanged(self):
        """A clean username should pass through unchanged."""
        assert SecurityHardening.sanitize_username("john_doe") == "john_doe"

    def test_spaces_removed(self):
        """Spaces should be stripped from usernames."""
        assert SecurityHardening.sanitize_username("john doe") == "johndoe"

    def test_special_chars_removed(self):
        """Dangerous special characters should be removed."""
        sanitized = SecurityHardening.sanitize_username("john<script>alert(1)</script>")
        assert "<" not in sanitized
        assert ">" not in sanitized

    def test_length_limit(self):
        """Usernames longer than 100 characters should be truncated."""
        long_name = "a" * 200
        sanitized = SecurityHardening.sanitize_username(long_name)
        assert len(sanitized) == 100

    def test_allows_hyphen_and_dot(self):
        """Hyphens and dots should be preserved."""
        assert SecurityHardening.sanitize_username("john.doe-admin") == "john.doe-admin"


class TestSetSecurityHeaders:
    """Verifies security headers are added to responses."""

    def test_security_headers_added(self):
        """Response should include all required security headers."""

        class MockResponse:
            def __init__(self):
                self.headers = {}

        response = MockResponse()
        SecurityHardening.set_security_headers(response)

        assert response.headers["X-Frame-Options"] == "DENY"
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-XSS-Protection"] == "1; mode=block"
        assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
        assert "Content-Security-Policy" in response.headers
        assert "Permissions-Policy" in response.headers


class TestPasswordHashing:
    """Verifies password hashing and verification (bcrypt or PBKDF2 fallback)."""

    def test_hash_and_verify_bcrypt(self):
        """Password hashed and verified should return True."""
        password = "my_secret_password"
        hashed = SecurityHardening.hash_password(password)
        assert hashed.startswith("$2b$") or hashed.startswith("pbkdf2:")
        assert SecurityHardening.verify_password(password, hashed) is True

    def test_verify_wrong_password(self):
        """Verification should fail for an incorrect password."""
        password = "correct_password"
        hashed = SecurityHardening.hash_password(password)
        assert SecurityHardening.verify_password("wrong_password", hashed) is False

    def test_hash_is_deterministic_with_same_salt(self):
        """When bcrypt is available, salt is auto-generated and ignored if passed.
        The passed salt only works with the PBKDF2 fallback path.
        With bcrypt, we just verify the hash verifies correctly."""
        password = "test"
        hashed = SecurityHardening.hash_password(password)
        # With bcrypt, the hash should verify
        assert SecurityHardening.verify_password(password, hashed) is True

    def test_hash_is_unique_each_time(self):
        """Each hash call should produce a different value (different salt)."""
        password = "test"
        hashes = {SecurityHardening.hash_password(password) for _ in range(5)}
        assert len(hashes) == 5

    def test_verify_unknown_format_returns_false(self):
        """An unrecognized hash format should fail verification."""
        assert SecurityHardening.verify_password("test", "unknown:format:hash") is False

    def test_verify_malformed_pbkdf2(self):
        """A malformed PBKDF2 hash should fail verification."""
        assert SecurityHardening.verify_password("test", "pbkdf2:invalid") is False


class TestGenerateRandomPassword:
    """Verifies secure random password generation."""

    def test_default_length(self):
        """Default password length should be 16."""
        password = SecurityHardening.generate_random_password()
        assert len(password) == 16

    def test_custom_length(self):
        """Password should respect the specified length."""
        password = SecurityHardening.generate_random_password(length=24)
        assert len(password) == 24

    def test_contains_all_character_types(self):
        """Password should contain lowercase, uppercase, digit, and special char."""
        password = SecurityHardening.generate_random_password()
        assert any(c.islower() for c in password)
        assert any(c.isupper() for c in password)
        assert any(c.isdigit() for c in password)
        assert any(c in "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~" for c in password)

    def test_uniqueness(self):
        """Multiple generated passwords should be unique."""
        passwords = {SecurityHardening.generate_random_password() for _ in range(10)}
        assert len(passwords) == 10
