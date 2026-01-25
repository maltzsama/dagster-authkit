"""SQLite-based authentication backend - secure user management with database."""

import hashlib
import logging
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

from .base import AuthBackend

logger = logging.getLogger(__name__)


class SQLiteAuthBackend(AuthBackend):
    """
    SQLite-based authentication backend.

    Perfect for small to medium teams (5-500 people) who want:
    - Secure password storage (not visible in text files)
    - Easy user management via CLI
    - Audit trail of changes
    - Zero external dependencies (SQLite is built into Python)

    Configuration:
    - DAGSTER_AUTH_DB: Path to SQLite database (default: ./dagster_auth.db)

    Database schema:
    - users: User accounts with hashed passwords
    - roles: User role assignments
    - audit_log: User management audit trail

    CLI commands:
    ```bash
    # Initialize database
    dagster-authkit init-db

    # Add user
    dagster-authkit add-user admin --email admin@company.com --role admin

    # Change password
    dagster-authkit change-password admin

    # List users
    dagster-authkit list-users

    # Delete user
    dagster-authkit delete-user old-user
    ```
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.config = config
        self.db_path = config.get("DAGSTER_AUTH_DB", "./dagster_auth.db")

        # Try to import bcrypt (optional but recommended)
        try:
            import bcrypt

            self.bcrypt = bcrypt
        except ImportError:
            logger.warning(
                "bcrypt not installed. Using SHA256 (less secure). "
                "Install with: pip install bcrypt"
            )
            self.bcrypt = None

        # Ensure database exists and is initialized
        self._ensure_database()

    def authenticate(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticate user against SQLite database."""
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            # Get user
            cursor.execute(
                """
                SELECT username, password_hash, email, display_name, is_active
                FROM users
                WHERE username = ? AND is_active = 1
            """,
                (username,),
            )

            row = cursor.fetchone()
            if not row:
                logger.warning(f"User not found or inactive: {username}")
                self._log_auth_attempt(username, False, "User not found")
                return None

            username_db, password_hash, email, display_name, is_active = row

            # Verify password
            if not self._verify_password(password, password_hash):
                logger.warning(f"Invalid password for user: {username}")
                self._log_auth_attempt(username, False, "Invalid password")
                return None

            # Get user roles
            cursor.execute(
                """
                SELECT role_name
                FROM user_roles
                WHERE username = ?
            """,
                (username,),
            )

            roles = [row[0] for row in cursor.fetchall()]

            # Validate roles
            roles = self.validate_roles(roles)

            # Update last login
            cursor.execute(
                """
                UPDATE users
                SET last_login = CURRENT_TIMESTAMP
                WHERE username = ?
            """,
                (username,),
            )
            conn.commit()

            # Build user data
            user_data = {
                "username": username,
                "email": email or f"{username}@localhost",
                "display_name": display_name or username,
                "roles": roles,
                "metadata": {},
            }

            logger.info(f"SQLite authentication successful for user: {username}")
            self._log_auth_attempt(username, True)

            return user_data

        except Exception as e:
            logger.error(f"Authentication error: {e}", exc_info=True)
            return None
        finally:
            conn.close()

    def _verify_password(self, password: str, stored_hash: str) -> bool:
        """Verify password against stored hash."""
        if self.bcrypt and stored_hash.startswith("$2b$"):
            # BCrypt hash
            try:
                password_bytes = password.encode("utf-8")
                hash_bytes = stored_hash.encode("utf-8")
                return self.bcrypt.checkpw(password_bytes, hash_bytes)
            except Exception as e:
                logger.error(f"BCrypt verification failed: {e}")
                return False
        else:
            # SHA256 fallback
            hashed = hashlib.sha256(password.encode()).hexdigest()
            return hashed == stored_hash

    def _hash_password(self, password: str) -> str:
        """Hash a password for storage."""
        if self.bcrypt:
            password_bytes = password.encode("utf-8")
            salt = self.bcrypt.gensalt()
            return self.bcrypt.hashpw(password_bytes, salt).decode("utf-8")
        else:
            return hashlib.sha256(password.encode()).hexdigest()

    def _get_connection(self) -> sqlite3.Connection:
        """Get database connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_database(self):
        """Ensure database exists and has correct schema."""
        db_file = Path(self.db_path)

        if not db_file.exists():
            logger.info(f"Creating new database: {self.db_path}")
            self._create_database()
        else:
            # Verify schema version
            self._verify_schema()

    def _create_database(self):
        """Create database with schema."""
        conn = self._get_connection()
        cursor = conn.cursor()

        # Users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                email TEXT,
                display_name TEXT,
                is_active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        """)

        # User roles table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_roles (
                username TEXT NOT NULL,
                role_name TEXT NOT NULL,
                granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                granted_by TEXT,
                PRIMARY KEY (username, role_name),
                FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
            )
        """)

        # Audit log table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                event_type TEXT NOT NULL,
                username TEXT,
                details TEXT,
                performed_by TEXT
            )
        """)

        # Schema version table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Insert initial schema version
        cursor.execute("INSERT INTO schema_version (version) VALUES (1)")

        # Create indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)")

        conn.commit()
        conn.close()

        logger.info("Database schema created successfully")

    def _verify_schema(self):
        """Verify database has correct schema version."""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("SELECT MAX(version) FROM schema_version")
            row = cursor.fetchone()
            version = row[0] if row else 0

            if version < 1:
                logger.warning("Database schema outdated, recreating...")
                self._create_database()
        except sqlite3.OperationalError:
            # Schema version table doesn't exist
            logger.warning("Schema version table missing, recreating database...")
            self._create_database()
        finally:
            conn.close()

    def _log_auth_attempt(self, username: str, success: bool, details: str = None):
        """Log authentication attempt to audit log."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            event_type = "AUTH_SUCCESS" if success else "AUTH_FAILURE"

            cursor.execute(
                """
                INSERT INTO audit_log (event_type, username, details)
                VALUES (?, ?, ?)
            """,
                (event_type, username, details),
            )

            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Failed to log auth attempt: {e}")

    def get_name(self) -> str:
        return "sqlite"

    # ========== User Management Methods (for CLI) ==========

    def add_user(
        self,
        username: str,
        password: str,
        email: Optional[str] = None,
        display_name: Optional[str] = None,
        roles: List[str] = None,
        performed_by: str = "system",
    ) -> bool:
        """
        Add a new user to the database.

        Args:
            username: Username
            password: Plain text password (will be hashed)
            email: User email
            display_name: User display name
            roles: List of roles to assign
            performed_by: Who is creating this user

        Returns:
            True if successful, False otherwise
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            # Check if user exists
            cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
            if cursor.fetchone():
                logger.error(f"User already exists: {username}")
                return False

            # Hash password
            password_hash = self._hash_password(password)

            # Insert user
            cursor.execute(
                """
                INSERT INTO users (username, password_hash, email, display_name)
                VALUES (?, ?, ?, ?)
            """,
                (username, password_hash, email, display_name),
            )

            # Assign roles
            if roles:
                for role in roles:
                    cursor.execute(
                        """
                        INSERT INTO user_roles (username, role_name, granted_by)
                        VALUES (?, ?, ?)
                    """,
                        (username, role, performed_by),
                    )

            # Log audit event
            cursor.execute(
                """
                INSERT INTO audit_log (event_type, username, details, performed_by)
                VALUES ('USER_CREATED', ?, ?, ?)
            """,
                (username, f"Roles: {','.join(roles or [])}", performed_by),
            )

            conn.commit()
            conn.close()

            logger.info(f"User created: {username}")
            return True

        except Exception as e:
            logger.error(f"Failed to create user: {e}", exc_info=True)
            return False

    def change_password(
        self, username: str, new_password: str, performed_by: str = "system"
    ) -> bool:
        """Change user password."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            # Check if user exists
            cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
            if not cursor.fetchone():
                logger.error(f"User not found: {username}")
                return False

            # Hash new password
            password_hash = self._hash_password(new_password)

            # Update password
            cursor.execute(
                """
                UPDATE users
                SET password_hash = ?, updated_at = CURRENT_TIMESTAMP
                WHERE username = ?
            """,
                (password_hash, username),
            )

            # Log audit event
            cursor.execute(
                """
                INSERT INTO audit_log (event_type, username, performed_by)
                VALUES ('PASSWORD_CHANGED', ?, ?)
            """,
                (username, performed_by),
            )

            conn.commit()
            conn.close()

            logger.info(f"Password changed for user: {username}")
            return True

        except Exception as e:
            logger.error(f"Failed to change password: {e}", exc_info=True)
            return False

    def delete_user(self, username: str, performed_by: str = "system") -> bool:
        """Delete a user (soft delete - marks as inactive)."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            # Mark user as inactive
            cursor.execute(
                """
                UPDATE users
                SET is_active = 0, updated_at = CURRENT_TIMESTAMP
                WHERE username = ?
            """,
                (username,),
            )

            if cursor.rowcount == 0:
                logger.error(f"User not found: {username}")
                return False

            # Log audit event
            cursor.execute(
                """
                INSERT INTO audit_log (event_type, username, performed_by)
                VALUES ('USER_DELETED', ?, ?)
            """,
                (username, performed_by),
            )

            conn.commit()
            conn.close()

            logger.info(f"User deleted (soft): {username}")
            return True

        except Exception as e:
            logger.error(f"Failed to delete user: {e}", exc_info=True)
            return False

    def list_users(self) -> List[Dict[str, Any]]:
        """List all active users."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            cursor.execute("""
                SELECT u.username, u.email, u.display_name, u.created_at, u.last_login,
                       GROUP_CONCAT(r.role_name) as roles
                FROM users u
                LEFT JOIN user_roles r ON u.username = r.username
                WHERE u.is_active = 1
                GROUP BY u.username
                ORDER BY u.username
            """)

            users = []
            for row in cursor.fetchall():
                users.append(
                    {
                        "username": row[0],
                        "email": row[1],
                        "display_name": row[2],
                        "created_at": row[3],
                        "last_login": row[4],
                        "roles": row[5].split(",") if row[5] else [],
                    }
                )

            conn.close()
            return users

        except Exception as e:
            logger.error(f"Failed to list users: {e}", exc_info=True)
            return []

    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        """Get user info without authenticating."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT username, email, display_name, is_active
                FROM users
                WHERE username = ? AND is_active = 1
                """,
                (username,),
            )

            row = cursor.fetchone()
            if not row:
                return None

            # Get roles
            cursor.execute(
                "SELECT role_name FROM user_roles WHERE username = ?",
                (username,),
            )
            roles = [r[0] for r in cursor.fetchall()]

            conn.close()

            return {
                "username": row[0],
                "email": row[1] or f"{row[0]}@localhost",
                "display_name": row[2] or row[0],
                "roles": self.validate_roles(roles),
            }

        except Exception as e:
            logger.error(f"Error getting user: {e}")
            return None
