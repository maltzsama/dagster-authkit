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
    def __init__(self):
        self.service = "dagster-authkit"
        self.env = os.getenv("DAGSTER_AUTH_ENV", "production")

    def _emit(self, event: Dict[str, Any]):
        """Cuspe o JSON puro no stdout."""
        event["timestamp"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        event["service"] = self.service
        event["env"] = self.env
        audit_logger.info(json.dumps(event, ensure_ascii=False))

    def log_event(self, event_type: str, performed_by: str, **kwargs):
        self._emit({"event_type": event_type, "performed_by": performed_by, **kwargs})

    def login_attempt(self, username, success, ip=None, reason=None):
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
    _inst.log_event(event_type, performed_by, **kwargs)


def log_login_attempt(u, s, ip=None, r=None):
    _inst.login_attempt(u, s, ip, r)


def log_logout(u, ip=None):
    _inst.log_event("LOGOUT", u, ip=ip)


def log_access_control(u, a, res, al, roles=None, r=None):
    _inst.access_control(u, a, res, al, roles, r)


def log_rate_limit_violation(u, ip=None, att=0):
    _inst.rate_limit_violation(u, ip, att)


def log_password_changed(u, pb, ss=False):
    _inst.log_event("PASSWORD_CHANGED", pb, target=u, self_service=ss)
