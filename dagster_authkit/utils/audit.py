"""
Audit Logging System

Structured JSON logging for security events.
Compatible with Datadog, Splunk, CloudWatch, ELK, etc.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)


class AuditLogger:
    """
    Audit logger that emits structured JSON to stdout.

    Tracked events:
    - LOGIN_ATTEMPT (success/failure)
    - LOGOUT
    - ACCESS_CONTROL (allowed/denied)
    - PASSWORD_CHANGED
    - USER_CREATED/DELETED
    - RATE_LIMIT_VIOLATION
    - SESSION_CREATED/EXPIRED
    """

    def __init__(self, enabled: bool = True):
        """
        Args:
            enabled: If False, audit logs are silenced
        """
        self.enabled = enabled

    def _emit(self, event: Dict[str, Any]) -> None:
        """
        Emits audit event as JSON to stdout.

        Args:
            event: Dict with event data
        """
        if not self.enabled:
            return

        # Adds timestamp if not present
        if "timestamp" not in event:
            event["timestamp"] = datetime.now(timezone.utc).isoformat()

        # Log as single-line JSON (parseable)
        logger.info(json.dumps(event, ensure_ascii=False))

    def login_attempt(
        self,
        username: str,
        success: bool,
        ip_address: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> None:
        """
        Log login attempt.

        Args:
            username: Username
            success: True if login successful
            ip_address: Client IP (optional)
            reason: Failure reason (optional)
        """
        event: Dict[str, Union[str, bool]] = {
            "event_type": "LOGIN_ATTEMPT",
            "username": username,
            "status": "SUCCESS" if success else "FAILURE",
        }

        if ip_address:
            event["ip"] = ip_address

        if not success and reason:
            event["reason"] = reason

        self._emit(event)

    def logout(self, username: str, ip_address: Optional[str] = None) -> None:
        """
        Log user logout.

        Args:
            username: Username
            ip_address: Client IP (optional)
        """
        event: Dict[str, str] = {
            "event_type": "LOGOUT",
            "username": username,
        }

        if ip_address:
            event["ip"] = ip_address

        self._emit(event)

    def access_control(
        self,
        username: str,
        action: str,
        resource: str,
        allowed: bool,
        roles: Optional[List[str]] = None,
        reason: Optional[str] = None,
    ) -> None:
        """
        Log access control decision (RBAC).

        Args:
            username: Username
            action: Attempted action (GET, POST, etc.)
            resource: Accessed resource (/graphql, /runs, etc.)
            allowed: True if access allowed
            roles: User roles (optional)
            reason: Denial reason (optional)
        """
        event: Dict[str, Union[str, bool, List[str]]] = {
            "event_type": "ACCESS_CONTROL",
            "username": username,
            "action": action,
            "resource": resource,
            "status": "ALLOWED" if allowed else "DENIED",
        }

        if roles:
            event["roles"] = roles

        if not allowed and reason:
            event["reason"] = reason

        self._emit(event)

    def password_changed(
        self, username: str, performed_by: str, self_service: bool = False
    ) -> None:
        """
        Log password change.

        Args:
            username: User whose password was changed
            performed_by: Who changed the password
            self_service: True if user changed their own password
        """
        event: Dict[str, Union[str, bool]] = {
            "event_type": "PASSWORD_CHANGED",
            "username": username,
            "performed_by": performed_by,
            "self_service": self_service,
        }

        self._emit(event)

    def user_created(self, username: str, roles: List[str], performed_by: str) -> None:
        """
        Log user creation.

        Args:
            username: User created
            roles: Assigned roles
            performed_by: Who created
        """
        event: Dict[str, Union[str, List[str]]] = {
            "event_type": "USER_CREATED",
            "username": username,
            "roles": roles,
            "performed_by": performed_by,
        }

        self._emit(event)

    def user_deleted(self, username: str, performed_by: str) -> None:
        """
        Log user deletion.

        Args:
            username: User deleted
            performed_by: Who deleted
        """
        event: Dict[str, str] = {
            "event_type": "USER_DELETED",
            "username": username,
            "performed_by": performed_by,
        }

        self._emit(event)

    def rate_limit_violation(
        self, username: str, ip_address: Optional[str] = None, attempts: int = 0
    ) -> None:
        """
        Log rate limit violation.

        Args:
            username: User who violated
            ip_address: Client IP
            attempts: Number of attempts
        """
        event: Dict[str, Union[str, int]] = {
            "event_type": "RATE_LIMIT_VIOLATION",
            "username": username,
            "attempts": attempts,
        }

        if ip_address:
            event["ip"] = ip_address

        self._emit(event)

    def session_created(self, username: str, session_id: str) -> None:
        """
        Log session creation.

        Args:
            username: Session user
            session_id: Session ID (hash)
        """
        event: Dict[str, str] = {
            "event_type": "SESSION_CREATED",
            "username": username,
            "session_id": session_id,
        }

        self._emit(event)

    def session_expired(self, username: str, session_id: str) -> None:
        """
        Log session expiration.

        Args:
            username: Session user
            session_id: Session ID (hash)
        """
        event: Dict[str, str] = {
            "event_type": "SESSION_EXPIRED",
            "username": username,
            "session_id": session_id,
        }

        self._emit(event)

    def custom_event(self, event_type: str, **kwargs: Any) -> None:
        """
        Log custom event.

        Args:
            event_type: Event type
            **kwargs: Additional fields
        """
        event: Dict[str, Any] = {"event_type": event_type, **kwargs}

        self._emit(event)


# ========================================
# Global Singleton Instance
# ========================================

_audit_logger: Optional[AuditLogger] = None


def get_audit_logger() -> AuditLogger:
    """
    Returns audit logger singleton.

    Returns:
        Global AuditLogger instance
    """
    global _audit_logger

    if _audit_logger is None:
        from .config import config

        enabled = config.AUDIT_LOG_ENABLED if hasattr(config, "AUDIT_LOG_ENABLED") else True
        _audit_logger = AuditLogger(enabled=enabled)

    return _audit_logger


# ========================================
# Convenience Functions
# ========================================


def log_login_attempt(
    username: str, success: bool, ip: Optional[str] = None, reason: Optional[str] = None
) -> None:
    """Convenience function for login attempt."""
    get_audit_logger().login_attempt(username, success, ip, reason)


def log_logout(username: str, ip: Optional[str] = None) -> None:
    """Convenience function for logout."""
    get_audit_logger().logout(username, ip)


def log_access_control(
    username: str,
    action: str,
    resource: str,
    allowed: bool,
    roles: Optional[List[str]] = None,
    reason: Optional[str] = None,
) -> None:
    """Convenience function for access control."""
    get_audit_logger().access_control(username, action, resource, allowed, roles, reason)


def log_password_changed(username: str, performed_by: str, self_service: bool = False) -> None:
    """Convenience function for password change."""
    get_audit_logger().password_changed(username, performed_by, self_service)


def log_user_created(username: str, roles: List[str], performed_by: str) -> None:
    """Convenience function for user creation."""
    get_audit_logger().user_created(username, roles, performed_by)


def log_user_deleted(username: str, performed_by: str) -> None:
    """Convenience function for user deletion."""
    get_audit_logger().user_deleted(username, performed_by)


def log_rate_limit_violation(username: str, ip: Optional[str] = None, attempts: int = 0) -> None:
    """Convenience function for rate limit violation."""
    get_audit_logger().rate_limit_violation(username, ip, attempts)
