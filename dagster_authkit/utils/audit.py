"""
Structured JSON audit logging to stdout.

All security-relevant events (logins, access control, rate limit
violations, password changes) are emitted as single-line JSON objects
suitable for ingestion by log aggregators (Splunk, Datadog, ELK).

Public API:
- ``log_audit_event``          — generic audit event
- ``log_login_attempt``        — login success/failure
- ``log_logout``               — session termination
- ``log_access_control``       — RBAC allow/deny
- ``log_rate_limit_violation`` — brute-force protection trigger
- ``log_password_changed``     — credential rotation
"""

import json
import logging
import sys
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

audit_logger = logging.getLogger("dagster_authkit.audit")
audit_logger.propagate = False

_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(logging.Formatter("%(message)s"))
audit_logger.addHandler(_handler)
audit_logger.setLevel(logging.INFO)


class AuditLogger:
    """
    Thread-safe audit event emitter.

    All events are serialised as single-line JSON to stdout via a
    dedicated ``dagster_authkit.audit`` logger. The ``service`` and
    ``env`` fields are automatically stamped on every event.

    Usage::

        audit = AuditLogger()
        audit.login_attempt("admin", True, ip="10.0.0.1")
    """

    def __init__(self):
        """Initialise with service name and environment tag."""
        self.service = "dagster-authkit"
        self.env = os.getenv("DAGSTER_AUTH_ENV", "production")

    def _emit(self, event: Dict[str, Any]):
        """Emit a pure JSON event to stdout."""
        event["timestamp"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        event["service"] = self.service
        event["env"] = self.env
        audit_logger.info(json.dumps(event, ensure_ascii=False))

    def log_event(self, event_type: str, performed_by: str, **kwargs):
        """
        Emit a generic audit event.

        Args:
            event_type:   Category label (e.g. ``USER_CREATED``, ``LOGOUT``).
            performed_by: Actor that triggered the event (username or ``system``).
            **kwargs:     Arbitrary context fields serialised into the JSON payload.
        """
        self._emit({"event_type": event_type, "performed_by": performed_by, **kwargs})

    def login_attempt(self, username, success, ip=None, reason=None):
        """
        Log a login attempt.

        Args:
            username: Authenticated username (or attempted username on failure).
            success:  ``True`` if authentication succeeded.
            ip:       Client IP address.
            reason:   Failure reason (e.g. ``INVALID_CREDENTIALS``, ``RATE_LIMIT``).
        """
        self._emit(
            {
                "event_type": "LOGIN_ATTEMPT",
                "username": username,
                "status": "SUCCESS" if success else "FAILURE",
                "ip": ip,
                "reason": reason,
            }
        )

    def access_control(self, username, action, resource, allowed, roles=None, reason=None):
        """
        Log an RBAC access control decision.

        Args:
            username: User performing the action.
            action:   Operation attempted (mutation name or REST method).
            resource: Target resource (URL path or GraphQL field).
            allowed:  ``True`` if access was granted.
            roles:    List of roles held by the user.
            reason:   Explanation if denied (e.g. ``REQUIRES_ADMIN``).
        """
        self._emit(
            {
                "event_type": "ACCESS_CONTROL",
                "username": username,
                "action": action,
                "resource": resource,
                "status": "ALLOWED" if allowed else "DENIED",
                "roles": roles,
                "reason": reason,
            }
        )

    def rate_limit_violation(self, username, ip=None, attempts=0):
        """
        Log a rate-limit violation.

        Args:
            username: Identifier that triggered the limit.
            ip:       Client IP address.
            attempts: Number of attempts within the window.
        """
        self._emit(
            {
                "event_type": "SECURITY_VIOLATION",
                "subtype": "RATE_LIMIT_EXCEEDED",
                "username": username,
                "ip": ip,
                "attempts": attempts,
            }
        )


# Singleton
_inst = AuditLogger()


def log_audit_event(event_type, performed_by, **kwargs):
    """
    Emit a generic audit event (convenience wrapper).

    Args:
        event_type:   Category label (e.g. ``USER_CREATED``, ``SESSION_CREATED``).
        performed_by: Actor identifier (username or ``system``).
        **kwargs:     Additional context fields (target, role, ip, etc.).
    """
    _inst.log_event(event_type, performed_by, **kwargs)


def log_login_attempt(u, s, ip=None, r=None):
    """Log a login attempt. See ``AuditLogger.login_attempt``."""
    _inst.login_attempt(u, s, ip, r)


def log_logout(u, ip=None):
    """
    Log a user logout event.

    Args:
        u:  Username that logged out.
        ip: Client IP address.
    """
    _inst.log_event("LOGOUT", u, ip=ip)


def log_access_control(u, a, res, al, roles=None, r=None):
    """Log an RBAC access control decision. See ``AuditLogger.access_control``."""
    _inst.access_control(u, a, res, al, roles, r)


def log_rate_limit_violation(u, ip=None, att=0):
    """Log a rate-limit violation. See ``AuditLogger.rate_limit_violation``."""
    _inst.rate_limit_violation(u, ip, att)


def log_password_changed(u, pb, ss=False):
    """
    Log a password change event.

    Args:
        u:  Username of the target user.
        pb: Actor who performed the change.
        ss: ``True`` if the user changed their own password (self-service).
    """
    _inst.log_event("PASSWORD_CHANGED", pb, target=u, self_service=ss)
