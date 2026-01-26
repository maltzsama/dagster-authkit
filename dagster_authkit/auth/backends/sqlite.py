"""
SQLite-based authentication backend.

Production-ready backend for small to medium teams (5-500 users).
Zero external dependencies - SQLite is built into Python.
"""

import logging
import os
import sqlite3
from typing import Optional, List

from .base import AuthBackend, AuthUser, Role
from ..security import SecurityHardening

logger = logging.getLogger(__name__)


class SQLiteAuthBackend(AuthBackend):
    """
    SQLite-based authentication backend.

    Features:
    - Secure password storage (bcrypt via SecurityHardening)
    - Role-based access control (4 levels)
    - Audit logging in database
    - Admin bootstrap via environment variable

    Configuration:
    - DAGSTER_AUTH_DB: Path to database (default: ./dagster_auth.db)
    - DAGSTER_AUTH_ADMIN_PASSWORD: Admin password (for first-run bootstrap)

    Database schema:
    - users: username, password_hash, role (INTEGER), email, full_name
    - audit_log: timestamp, event_type, username, details, performed_by
    """

    def __init__(self, config: dict):
        super().__init__(config)
        self.db_path = config.get("DAGSTER_AUTH_DB", "./dagster_auth.db")
        self._ensure_database()

    # ========================================
    # CORE METHODS (Abstract Implementation)
    # ========================================

    def authenticate(self, username: str, password: str) -> Optional[AuthUser]:
        """Authenticate user against SQLite database."""
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            # Get user
            cursor.execute(
                """
                SELECT password_hash, role, email, full_name
                FROM users
                WHERE username = ?
                """,
                (username,),
            )

            row = cursor.fetchone()
            if not row:
                logger.warning(f"User not found: {username}")
                self._log_auth_attempt(username, False, "User not found")
                return None

            password_hash, role_value, email, full_name = row

            # Verify password
            if not SecurityHardening.verify_password(password, password_hash):
                logger.warning(f"Invalid password for user: {username}")
                self._log_auth_attempt(username, False, "Invalid password")
                return None

            # Update last login
            cursor.execute(
                "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE username = ?", (username,)
            )
            conn.commit()

            # Log success
            logger.info(f"Authentication successful: {username}")
            self._log_auth_attempt(username, True)

            return AuthUser(
                username=username,
                role=Role(role_value),
                email=email or "",
                full_name=full_name or "",
            )

        except Exception as e:
            logger.error(f"Authentication error: {e}", exc_info=True)
            return None
        finally:
            if conn:
                conn.close()

    def get_user(self, username: str) -> Optional[AuthUser]:
        """Get user info without authenticating (for session validation)."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            cursor.execute(
                "SELECT role, email, full_name FROM users WHERE username = ?", (username,)
            )

            row = cursor.fetchone()
            conn.close()

            if row:
                role_value, email, full_name = row
                return AuthUser(
                    username=username,
                    role=Role(role_value),
                    email=email or "",
                    full_name=full_name or "",
                )

            return None

        except Exception as e:
            logger.error(f"Error getting user: {e}")
            return None

    def get_name(self) -> str:
        return "sqlite"

    # ========================================
    # USER MANAGEMENT (CLI Methods)
    # ========================================

    def add_user(
        self,
        username: str,
        password: str,
        role: Role,
        email: str = "",
        full_name: str = "",
        performed_by: str = "system",
        **kwargs,
    ) -> bool:
        """Create a new user."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            # Check if user exists
            cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
            if cursor.fetchone():
                logger.error(f"User already exists: {username}")
                conn.close()
                return False

            # Hash password
            password_hash = SecurityHardening.hash_password(password)

            # Insert user
            cursor.execute(
                """
                INSERT INTO users (username, password_hash, role, email, full_name)
                VALUES (?, ?, ?, ?, ?)
                """,
                (username, password_hash, role.value, email, full_name),
            )

            # Log audit event
            cursor.execute(
                """
                INSERT INTO audit_log (event_type, username, details, performed_by)
                VALUES ('USER_CREATED', ?, ?, ?)
                """,
                (username, f"Role: {role.name}", performed_by),
            )

            conn.commit()
            conn.close()

            logger.info(f"User created: {username} (role: {role.name})")
            return True

        except Exception as e:
            logger.error(f"Failed to create user: {e}", exc_info=True)
            return False

    def delete_user(self, username: str, performed_by: str = "system") -> bool:
        """Delete a user (hard delete - removes from database)."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            # Delete user
            cursor.execute("DELETE FROM users WHERE username = ?", (username,))

            if cursor.rowcount == 0:
                logger.error(f"User not found: {username}")
                conn.close()
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

            logger.info(f"User deleted: {username}")
            return True

        except Exception as e:
            logger.error(f"Failed to delete user: {e}", exc_info=True)
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
                conn.close()
                return False

            # Hash new password
            password_hash = SecurityHardening.hash_password(new_password)

            # Update password
            cursor.execute(
                "UPDATE users SET password_hash = ? WHERE username = ?", (password_hash, username)
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

    def change_role(self, username: str, new_role: Role, performed_by: str = "system") -> bool:
        """Change user's role."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            # Check if user exists
            cursor.execute("SELECT role FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()
            if not row:
                logger.error(f"User not found: {username}")
                conn.close()
                return False

            old_role = Role(row[0])

            # Update role
            cursor.execute(
                "UPDATE users SET role = ? WHERE username = ?", (new_role.value, username)
            )

            # Log audit event
            cursor.execute(
                """
                INSERT INTO audit_log (event_type, username, details, performed_by)
                VALUES ('ROLE_CHANGED', ?, ?, ?)
                """,
                (username, f"{old_role.name} → {new_role.name}", performed_by),
            )

            conn.commit()
            conn.close()

            logger.info(f"Role changed for {username}: {old_role.name} → {new_role.name}")
            return True

        except Exception as e:
            logger.error(f"Failed to change role: {e}", exc_info=True)
            return False

    def list_users(self) -> List[AuthUser]:
        """List all users."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            cursor.execute("""
                SELECT username, role, email, full_name
                FROM users
                ORDER BY username
                """)

            users = []
            for row in cursor.fetchall():
                username, role_value, email, full_name = row
                users.append(
                    AuthUser(
                        username=username,
                        role=Role(role_value),
                        email=email or "",
                        full_name=full_name or "",
                    )
                )

            conn.close()
            return users

        except Exception as e:
            logger.error(f"Failed to list users: {e}", exc_info=True)
            return []

    # ========================================
    # INTERNAL HELPERS
    # ========================================

    def _get_connection(self) -> sqlite3.Connection:
        """Get database connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_database(self):
        """Ensure database exists with correct schema."""
        conn = self._get_connection()
        cursor = conn.cursor()

        # Users table (SIMPLIFIED SCHEMA)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                role INTEGER NOT NULL,
                email TEXT,
                full_name TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
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

        # Create indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_role ON users(role)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)")

        conn.commit()

        # ========================================
        # ADMIN BOOTSTRAP (via ENV variable)
        # ========================================
        admin_password = os.getenv("DAGSTER_AUTH_ADMIN_PASSWORD")

        if admin_password:
            cursor.execute("SELECT COUNT(*) FROM users")
            user_count = cursor.fetchone()[0]

            if user_count == 0:
                # Create admin user
                cursor.execute(
                    "INSERT INTO users (username, password_hash, role, email, full_name) VALUES (?, ?, ?, ?, ?)",
                    (
                        "admin",
                        SecurityHardening.hash_password(admin_password),
                        Role.ADMIN.value,
                        "admin@localhost",
                        "Administrator",
                    ),
                )

                cursor.execute(
                    "INSERT INTO audit_log (event_type, username, performed_by) VALUES ('USER_CREATED', 'admin', 'system')"
                )

                conn.commit()

                print("\n" + "=" * 60)
                print("✅ ADMIN USER CREATED")
                print("=" * 60)
                print("Username: admin")
                print("Password: (from DAGSTER_AUTH_ADMIN_PASSWORD)")
                print("Role: ADMIN")
                print("=" * 60 + "\n")

        conn.close()
        logger.info("Database initialized successfully")

    def _log_auth_attempt(self, username: str, success: bool, details: str = None):
        """Log authentication attempt to audit log."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            event_type = "AUTH_SUCCESS" if success else "AUTH_FAILURE"

            cursor.execute(
                "INSERT INTO audit_log (event_type, username, details) VALUES (?, ?, ?)",
                (event_type, username, details),
            )

            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Failed to log auth attempt: {e}")
