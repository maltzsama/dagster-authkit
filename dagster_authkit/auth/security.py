"""
Security Hardening Module

Critical security measures to prevent common attacks.
"""

import hashlib
import hmac
import logging
import secrets
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class SecurityHardening:
    """
    Class with static methods for security hardening.
    """

    @staticmethod
    def constant_time_compare(a: str, b: str) -> bool:
        """
        Constant time comparison to prevent timing attacks.

        Critical for password, token comparisons, etc.

        Args:
            a: First string
            b: Second string

        Returns:
            bool: True if strings are equal
        """
        return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))

    @staticmethod
    def generate_csrf_token() -> str:
        """
        Generates secure CSRF token for login forms.

        Returns:
            str: Random 32-byte token
        """
        return secrets.token_urlsafe(32)

    @staticmethod
    def validate_redirect_url(url: str, allowed_hosts: list = None) -> bool:
        """
        Validates redirect URL to prevent open redirect attacks.

        Accepts only:
        - Relative URLs (/path)
        - Same host URLs
        - Allowed host URLs

        Args:
            url: URL to validate
            allowed_hosts: List of allowed hosts (optional)

        Returns:
            bool: True if URL is safe
        """
        if not url:
            return False

        # Accept relative URLs (start with /)
        if url.startswith("/") and "://" not in url:
            return True

        # Parse absolute URL
        try:
            parsed = urlparse(url)

            # Reject if has scheme but not http/https
            if parsed.scheme and parsed.scheme not in ["http", "https"]:
                logger.warning(f"Rejected redirect URL with invalid scheme: {url}")
                return False

            # If has host, check if in allowlist
            if parsed.netloc:
                if allowed_hosts and parsed.netloc in allowed_hosts:
                    return True
                else:
                    logger.warning(f"Rejected redirect to external host: {parsed.netloc}")
                    return False

            return True

        except Exception as e:
            logger.error(f"Error parsing redirect URL {url}: {e}")
            return False

    @staticmethod
    def sanitize_username(username: str) -> str:
        """
        Sanitizes username to prevent injection attacks.

        Removes dangerous characters keeping alphanumeric, underscore, hyphen, dot.

        Args:
            username: Raw username

        Returns:
            str: Sanitized username
        """
        import re

        # Allows: letters, numbers, underscore, hyphen, dot
        sanitized = re.sub(r"[^a-zA-Z0-9_\-\.]", "", username)

        # Limit length
        sanitized = sanitized[:100]

        if sanitized != username:
            logger.warning(f"Username sanitized: '{username}' -> '{sanitized}'")

        return sanitized

    @staticmethod
    def set_security_headers(response):
        """
        Adds mandatory security headers to response.

        Applied headers:
        - X-Frame-Options: Prevents clickjacking
        - X-Content-Type-Options: Prevents MIME sniffing
        - X-XSS-Protection: Enables XSS filter (old browsers)
        - Referrer-Policy: Controls referrer leakage
        - Content-Security-Policy: Restricts resources

        Args:
            response: Starlette Response object
        """
        security_headers = {
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Content-Security-Policy": (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline'; "  # Dagster needs inline scripts
                "style-src 'self' 'unsafe-inline'; "  # Dagster needs inline styles
                "img-src 'self' data:; "
                "font-src 'self' data:; "
                "connect-src 'self';"
            ),
            # Adds Permissions-Policy (replaces Feature-Policy)
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
        }

        response.headers.update(security_headers)
        return response

    @staticmethod
    def hash_password(password: str, salt: Optional[bytes] = None) -> str:
        """
        Hashes password with BCrypt (if available) or PBKDF2.

        For BCrypt, first does SHA-256 hash to:
        1. Protect passwords > 72 chars (BCrypt limit)
        2. Prevent null-byte truncation
        3. Normalize length

        Args:
            password: Plain text password
            salt: Optional salt (bcrypt generates automatically)

        Returns:
            str: Hashed password
        """
        try:
            import bcrypt

            # CRITICAL: BCrypt has 72-byte limit
            # First hash with SHA-256 to normalize
            sha256_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()

            # Now bcrypt the hash (always 64 hex chars)
            if salt is None:
                salt = bcrypt.gensalt(rounds=12)

            return bcrypt.hashpw(sha256_hash.encode("utf-8"), salt).decode("utf-8")

        except ImportError:
            # Fallback to PBKDF2 if bcrypt unavailable
            logger.warning("bcrypt not available, using PBKDF2 (less secure)")
            if salt is None:
                salt = secrets.token_bytes(32)

            hash_obj = hashlib.pbkdf2_hmac(
                "sha256", password.encode("utf-8"), salt, 100000  # 100k iterations
            )
            # Returns: salt + hash in hex
            return f"pbkdf2:sha256:{salt.hex()}:{hash_obj.hex()}"

    @staticmethod
    def verify_password(password: str, password_hash: str) -> bool:
        """
        Verifies password against hash.

        Supports both bcrypt and PBKDF2 fallback.
        For bcrypt, first does SHA-256 (same as in hashing).

        Args:
            password: Plain text password
            password_hash: Stored hash

        Returns:
            bool: True if password is correct
        """
        try:
            if password_hash.startswith("$2b$"):
                # BCrypt hash (with SHA-256 pre-hash)
                import bcrypt

                # CRITICAL: Apply same pre-hash used in hashing
                sha256_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()

                password_bytes = sha256_hash.encode("utf-8")
                hash_bytes = password_hash.encode("utf-8")
                return bcrypt.checkpw(password_bytes, hash_bytes)

            elif password_hash.startswith("pbkdf2:"):
                # PBKDF2 fallback
                _, algo, salt_hex, stored_hash = password_hash.split(":")
                salt = bytes.fromhex(salt_hex)

                computed_hash = hashlib.pbkdf2_hmac(
                    "sha256", password.encode("utf-8"), salt, 100000
                )

                return SecurityHardening.constant_time_compare(computed_hash.hex(), stored_hash)

            else:
                # Unknown format
                logger.error(f"Unknown password hash format: {password_hash[:20]}...")
                return False

        except Exception as e:
            logger.error(f"Password verification error: {e}")
            return False

    @staticmethod
    def generate_random_password(length: int = 16) -> str:
        """
        Generates secure random password.

        Useful for password reset, temporary passwords, etc.

        Args:
            length: Password length

        Returns:
            str: Random password
        """
        import string

        alphabet = string.ascii_letters + string.digits + string.punctuation
        # Ensure at least one of each type
        password = [
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.digits),
            secrets.choice(string.punctuation),
        ]
        # Fill the rest
        password += [secrets.choice(alphabet) for _ in range(length - 4)]
        # Shuffle
        secrets.SystemRandom().shuffle(password)
        return "".join(password)
