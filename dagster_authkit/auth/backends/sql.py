"""
Unified SQL Backend via Peewee - v1.0 Production-Ready
Implements identity management with support for SQLite, PostgreSQL, and MySQL.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from peewee import Model, CharField, IntegerField, BooleanField, DateTimeField, DoesNotExist
from playhouse.db_url import connect

from dagster_authkit.auth.backends.base import AuthBackend, AuthUser, Role
from dagster_authkit.auth.security import SecurityHardening
from dagster_authkit.auth.session import sessions
from dagster_authkit.utils.audit import log_audit_event

logger = logging.getLogger(__name__)


class UserTable(Model):
    """
    Internal Peewee model for user persistence.
    Mapped to 'users' table.
    """

    username = CharField(primary_key=True, max_length=255)
    password_hash = CharField(max_length=255)
    role_value = IntegerField(column_name="role")  # Stored as INT (e.g., 40)
    email = CharField(max_length=255, null=True)
    full_name = CharField(max_length=255, null=True)
    is_active = BooleanField(default=True)
    created_at = DateTimeField(default=datetime.utcnow)
    last_login = DateTimeField(null=True)

    class Meta:
        table_name = "users"


# --- Backend Implementation ---


class PeeweeAuthBackend(AuthBackend):
    """
    Identity backend using Peewee ORM.
    Handles authentication, user management, and security events.
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)

        # Connection string from ENV (e.g., postgresql://user:pass@localhost:5432/db)
        # Defaults to local SQLite for development
        db_url = config.get("DAGSTER_AUTH_DATABASE_URL") or "sqlite:///dagster_auth.db"

        try:
            self.db = connect(db_url)
            UserTable._meta.database = self.db

            # Idempotent table creation
            self.db.create_tables([UserTable])
            self._bootstrap_admin()

            logger.info(f"PeeweeAuthBackend: Initialized using {type(self.db).__name__}")
        except Exception as e:
            logger.error(f"Failed to initialize SQL database: {e}")
            raise

    def get_name(self) -> str:
        return "sql"

    # ========================================
    # Core Authentication Methods
    # ========================================

    def authenticate(self, username: str, password: str) -> Optional[AuthUser]:
        """Validates credentials and returns a universal AuthUser."""
        try:
            user_obj = UserTable.get(
                (UserTable.username == username) & (UserTable.is_active == True)
            )

            if SecurityHardening.verify_password(password, user_obj.password_hash):
                # Update last login timestamp
                user_obj.last_login = datetime.utcnow()
                user_obj.save()

                return AuthUser.from_dict(
                    {
                        "username": user_obj.username,
                        "role": user_obj.role_value,  # Int handled by AuthUser logic
                        "email": user_obj.email or "",
                        "full_name": user_obj.full_name or "",
                    }
                )
        except DoesNotExist:
            pass

        return None

    def get_user(self, username: str) -> Optional[AuthUser]:
        """Fetches user metadata without password verification."""
        try:
            user_obj = UserTable.get(UserTable.username == username)
            return AuthUser.from_dict(
                {
                    "username": user_obj.username,
                    "role": user_obj.role_value,
                    "email": user_obj.email or "",
                    "full_name": user_obj.full_name or "",
                }
            )
        except DoesNotExist:
            return None

    # ========================================
    # Management Methods (Optional Implementation)
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
        """Creates a new user and logs the event to stdout."""
        try:
            UserTable.create(
                username=username,
                password_hash=SecurityHardening.hash_password(password),
                role_value=role.value,
                email=email,
                full_name=full_name,
            )
            log_audit_event("USER_CREATED", performed_by, target=username, role=role.name)
            return True
        except Exception as e:
            logger.error(f"SQL Error adding user {username}: {e}")
            return False

    def delete_user(self, username: str, performed_by: str = "system") -> bool:
        """Deactivates user (soft delete) and revokes all active sessions."""
        query = UserTable.update(is_active=False).where(UserTable.username == username)

        if query.execute() > 0:
            # Force global session invalidation
            sessions.revoke_all(username)
            log_audit_event("USER_DELETED", performed_by, target=username)
            return True
        return False

    def change_password(self, username: str, new_password: str, performed_by: str = "system") -> bool:
        """
        Updates password hash and revokes all active sessions for THIS user.
        """
        query = UserTable.update(
            password_hash=SecurityHardening.hash_password(new_password)
        ).where(UserTable.username == username)

        if query.execute() > 0:
            # O "Doom" aqui é só no CPF do cara, não na firma toda.
            from dagster_authkit.auth.session import sessions
            sessions.revoke_all(username)

            log_audit_event("PASSWORD_CHANGED", performed_by, target=username)
            return True
        return False

    def list_users(self) -> List[AuthUser]:
        """Lists all active users in the system."""
        users = UserTable.select().where(UserTable.is_active == True)
        return [
            AuthUser.from_dict(
                {
                    "username": u.username,
                    "role": u.role_value,
                    "email": u.email or "",
                    "full_name": u.full_name or "",
                }
            )
            for u in users
        ]

    def change_role(self, username: str, new_role: Role, performed_by: str = "system") -> bool:
        """Updates user role and logs the permission change."""
        query = UserTable.update(role_value=new_role.value).where(UserTable.username == username)

        if query.execute() > 0:
            log_audit_event("ROLE_CHANGED", performed_by, target=username, new_role=new_role.name)
            return True
        return False

    # ========================================
    # Private Helpers
    # ========================================

    def _bootstrap_admin(self):
        """Auto-creates admin user if specified in configuration."""
        admin_pass = self.config.get("DAGSTER_AUTH_ADMIN_PASSWORD")
        if admin_pass and not self.get_user("admin"):
            self.add_user(
                username="admin",
                password=admin_pass,
                role=Role.ADMIN,
                full_name="System Administrator",
                performed_by="bootstrap",
            )
            logger.info("Bootstrap: Admin user 'admin' created via environment variable.")
