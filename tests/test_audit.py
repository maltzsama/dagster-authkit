"""
Unit tests for utils/audit.py

Covers:
- AuditLogger initialization and default values
- Log event emission (JSON to stdout)
- Specialized loggers: login_attempt, access_control, rate_limit_violation
- Convenience functions: log_audit_event, log_login_attempt, log_logout,
  log_access_control, log_rate_limit_violation, log_password_changed
"""

import io
import json
import logging
import sys

import pytest

from dagster_authkit.utils.audit import (
    AuditLogger,
    log_access_control,
    log_audit_event,
    log_login_attempt,
    log_logout,
    log_password_changed,
    log_rate_limit_violation,
)


@pytest.fixture
def audit_logger():
    """Returns a fresh AuditLogger instance."""
    return AuditLogger()


@pytest.fixture
def captured_output():
    """Captures stdout output from audit logging."""
    capture = io.StringIO()
    handler = logging.StreamHandler(capture)
    handler.setFormatter(logging.Formatter("%(message)s"))

    audit_log = logging.getLogger("dagster_authkit.audit")
    audit_log.handlers.clear()
    audit_log.addHandler(handler)
    audit_log.setLevel(logging.INFO)

    yield capture

    audit_log.handlers.clear()


class TestAuditLogger:
    """Verifies the AuditLogger class."""

    def test_default_service_name(self, audit_logger):
        """Default service name should be 'dagster-authkit'."""
        assert audit_logger.service == "dagster-authkit"

    def test_emit_includes_timestamp(self, captured_output, audit_logger):
        """Emitted events should include an ISO 8601 timestamp."""
        audit_logger.log_event("TEST_EVENT", "system")
        output = captured_output.getvalue()
        data = json.loads(output)
        assert "timestamp" in data
        assert data["timestamp"].endswith("Z")

    def test_emit_includes_service(self, captured_output, audit_logger):
        """Emitted events should include the service name."""
        audit_logger.log_event("TEST_EVENT", "system")
        output = captured_output.getvalue()
        data = json.loads(output)
        assert data["service"] == "dagster-authkit"

    def test_emit_includes_env(self, captured_output, audit_logger):
        """Emitted events should include the environment."""
        audit_logger.log_event("TEST_EVENT", "system")
        output = captured_output.getvalue()
        data = json.loads(output)
        assert "env" in data

    def test_emit_includes_event_type(self, captured_output, audit_logger):
        """Emitted events should include the event_type."""
        audit_logger.log_event("USER_CREATED", "admin", target="john")
        output = captured_output.getvalue()
        data = json.loads(output)
        assert data["event_type"] == "USER_CREATED"
        assert data["performed_by"] == "admin"
        assert data["target"] == "john"

    def test_login_attempt_success(self, captured_output, audit_logger):
        """Successful login should emit SUCCESS status."""
        audit_logger.login_attempt("john", True, ip="192.168.1.1")
        output = captured_output.getvalue()
        data = json.loads(output)
        assert data["event_type"] == "LOGIN_ATTEMPT"
        assert data["username"] == "john"
        assert data["status"] == "SUCCESS"
        assert data["ip"] == "192.168.1.1"

    def test_login_attempt_failure(self, captured_output, audit_logger):
        """Failed login should emit FAILURE status with reason."""
        audit_logger.login_attempt("john", False, ip="10.0.0.1", reason="INVALID_CREDENTIALS")
        output = captured_output.getvalue()
        data = json.loads(output)
        assert data["status"] == "FAILURE"
        assert data["reason"] == "INVALID_CREDENTIALS"

    def test_access_control_allowed(self, captured_output, audit_logger):
        """Allowed access control should emit ALLOWED status."""
        audit_logger.access_control("admin", "POST", "/graphql", True, roles=["ADMIN"])
        output = captured_output.getvalue()
        data = json.loads(output)
        assert data["event_type"] == "ACCESS_CONTROL"
        assert data["status"] == "ALLOWED"

    def test_access_control_denied(self, captured_output, audit_logger):
        """Denied access control should emit DENIED status with reason."""
        audit_logger.access_control(
            "viewer", "POST", "/graphql", False, roles=["VIEWER"], reason="REQUIRES_LAUNCHER"
        )
        output = captured_output.getvalue()
        data = json.loads(output)
        assert data["status"] == "DENIED"
        assert data["reason"] == "REQUIRES_LAUNCHER"

    def test_rate_limit_violation(self, captured_output, audit_logger):
        """Rate limit violation should emit correct subtype."""
        audit_logger.rate_limit_violation("attacker", ip="10.0.0.5", attempts=10)
        output = captured_output.getvalue()
        data = json.loads(output)
        assert data["event_type"] == "SECURITY_VIOLATION"
        assert data["subtype"] == "RATE_LIMIT_EXCEEDED"
        assert data["attempts"] == 10


class TestAuditConvenienceFunctions:
    """Verifies module-level convenience logging functions."""

    def test_log_audit_event(self, captured_output):
        """log_audit_event should write a valid JSON event."""
        log_audit_event("USER_CREATED", "system", target="testuser", role="ADMIN")
        output = captured_output.getvalue()
        data = json.loads(output)
        assert data["event_type"] == "USER_CREATED"

    def test_log_login_attempt(self, captured_output):
        """log_login_attempt should emit LOGIN_ATTEMPT event."""
        log_login_attempt("admin", True, "192.168.1.1")
        output = captured_output.getvalue()
        data = json.loads(output)
        assert data["event_type"] == "LOGIN_ATTEMPT"

    def test_log_logout(self, captured_output):
        """log_logout should emit LOGOUT event."""
        log_logout("admin", "192.168.1.1")
        output = captured_output.getvalue()
        data = json.loads(output)
        assert data["event_type"] == "LOGOUT"

    def test_log_access_control(self, captured_output):
        """log_access_control should emit ACCESS_CONTROL event."""
        log_access_control("admin", "POST", "/graphql", True)
        output = captured_output.getvalue()
        data = json.loads(output)
        assert data["event_type"] == "ACCESS_CONTROL"

    def test_log_rate_limit_violation(self, captured_output):
        """log_rate_limit_violation should emit SECURITY_VIOLATION event."""
        log_rate_limit_violation("attacker", "10.0.0.1", att=5)
        output = captured_output.getvalue()
        data = json.loads(output)
        assert data["event_type"] == "SECURITY_VIOLATION"

    def test_log_password_changed(self, captured_output):
        """log_password_changed should emit PASSWORD_CHANGED event."""
        log_password_changed("user1", "admin", ss=True)
        output = captured_output.getvalue()
        data = json.loads(output)
        assert data["event_type"] == "PASSWORD_CHANGED"
        assert data["self_service"] is True
