"""
Unit tests for api/health.py

Covers:
- MetricsCollector: increment_counter, set_gauge, observe_histogram
- MetricsCollector: get_metrics summary stats (min, max, avg)
- MetricsCollector: reset and uptime tracking
- Global metric tracking functions
- get_health_status structure and backend/database checks
"""

import json
import time
from unittest.mock import MagicMock, patch

import pytest

from dagster_authkit.api.health import (
    MetricsCollector,
    _check_db_connection,
    get_health_status,
    get_metrics_collector,
    health_endpoint,
    metrics_endpoint,
    track_login_attempt,
    track_rbac_decision,
    track_request_duration,
    track_session_created,
)


class TestMetricsCollector:
    """Verifies the in-memory MetricsCollector."""

    @pytest.fixture
    def collector(self):
        """Returns a fresh MetricsCollector for isolation."""
        mc = MetricsCollector()
        yield mc
        mc.reset()

    def test_increment_counter_default(self, collector):
        """increment_counter with defaults should increment by 1."""
        collector.increment_counter("test_counter")
        metrics = collector.get_metrics()
        assert metrics["counters"]["test_counter"] == 1

    def test_increment_counter_custom_value(self, collector):
        """increment_counter should support custom value."""
        collector.increment_counter("test_counter", value=5)
        metrics = collector.get_metrics()
        assert metrics["counters"]["test_counter"] == 5

    def test_increment_counter_with_labels(self, collector):
        """Labels should produce unique metric keys."""
        collector.increment_counter("requests", labels={"status": "200"})
        collector.increment_counter("requests", labels={"status": "404"})
        metrics = collector.get_metrics()
        assert "requests{status=200}" in metrics["counters"]
        assert "requests{status=404}" in metrics["counters"]

    def test_set_gauge(self, collector):
        """set_gauge should set a gauge value."""
        collector.set_gauge("active_sessions", 42.0)
        metrics = collector.get_metrics()
        assert metrics["gauges"]["active_sessions"] == 42.0

    def test_set_gauge_with_labels(self, collector):
        """set_gauge should support labels."""
        collector.set_gauge("memory_bytes", 1024.0, labels={"type": "heap"})
        metrics = collector.get_metrics()
        key = "memory_bytes{type=heap}"
        assert metrics["gauges"][key] == 1024.0

    def test_observe_histogram(self, collector):
        """observe_histogram should record observations."""
        collector.observe_histogram("request_duration", 0.1)
        collector.observe_histogram("request_duration", 0.5)
        metrics = collector.get_metrics()
        hist = metrics["histograms"]["request_duration"]
        assert hist["count"] == 2
        assert hist["sum"] == 0.6
        assert hist["avg"] == 0.3
        assert hist["min"] == 0.1
        assert hist["max"] == 0.5

    def test_observe_histogram_empty(self, collector):
        """An empty histogram should have all zeros."""
        metrics = collector.get_metrics()
        assert len(metrics["histograms"]) == 0

    def test_histogram_limit(self, collector):
        """Histogram should cap observations at 1000 entries."""
        for i in range(1100):
            collector.observe_histogram("many", float(i))
        metrics = collector.get_metrics()
        assert metrics["histograms"]["many"]["count"] == 1000

    def test_reset_clears_all(self, collector):
        """reset should clear counters, gauges, and histograms."""
        collector.increment_counter("test")
        collector.set_gauge("g", 1.0)
        collector.observe_histogram("h", 1.0)
        collector.reset()
        metrics = collector.get_metrics()
        assert len(metrics["counters"]) == 0
        assert len(metrics["gauges"]) == 0
        assert len(metrics["histograms"]) == 0

    def test_uptime_tracks_elapsed_time(self, collector):
        """Uptime should increase as time passes."""
        time.sleep(0.1)
        metrics = collector.get_metrics()
        assert metrics["uptime_seconds"] > 0.05


class TestMetricTrackingFunctions:
    """Verifies global tracking convenience functions."""

    @pytest.fixture(autouse=True)
    def reset_collector(self):
        """Reset the global collector before each test."""
        get_metrics_collector().reset()
        yield

    def test_track_login_attempt_success(self):
        """Tracking a successful login should increment the success counter."""
        track_login_attempt(True, username="admin")
        metrics = get_metrics_collector().get_metrics()
        assert "auth_login_attempts_total{status=success}" in metrics["counters"]

    def test_track_login_attempt_failure(self):
        """Tracking a failed login should increment the failure counter."""
        track_login_attempt(False, username="attacker")
        metrics = get_metrics_collector().get_metrics()
        assert "auth_login_attempts_total{status=failure}" in metrics["counters"]
        # Username is intentionally NOT a metric label to prevent
        # information leakage via /metrics and unbounded cardinality.

    def test_track_rbac_decision(self):
        """RBAC decisions should be tracked with role and action."""
        track_rbac_decision(True, "ADMIN", "launchRun")
        metrics = get_metrics_collector().get_metrics()
        counters = metrics["counters"]
        assert any(
            "auth_rbac_decisions_total" in k and "status=allowed" in k and "role=ADMIN" in k
            for k in counters
        )

    def test_track_session_created(self):
        """Session creation should increment the counter."""
        track_session_created()
        metrics = get_metrics_collector().get_metrics()
        assert "auth_sessions_created_total" in metrics["counters"]

    def test_track_request_duration(self):
        """Request duration should be recorded in the histogram."""
        track_request_duration("/graphql", 0.25)
        metrics = get_metrics_collector().get_metrics()
        assert "auth_request_duration_seconds{endpoint=/graphql}" in metrics["histograms"]


class TestCheckDbConnection:
    """Verifies the database connection check function."""

    def test_no_db_attr_returns_false(self):
        """Backend without db attribute should return False."""
        backend = MagicMock(spec=[])
        assert _check_db_connection(backend) is False

    def test_db_is_none_returns_false(self):
        """Backend with db=None should return False."""
        backend = MagicMock()
        backend.db = None
        assert _check_db_connection(backend) is False

    def test_db_ping_success(self):
        """Successful execute_sql should return True."""
        backend = MagicMock()
        backend.db = MagicMock()
        assert _check_db_connection(backend) is True

    def test_db_ping_exception(self):
        """Failed execute_sql should return False."""
        backend = MagicMock()
        backend.db = MagicMock()
        backend.db.execute_sql.side_effect = Exception("Timeout")
        assert _check_db_connection(backend) is False


class TestGetHealthStatus:
    """Verifies the get_health_status function."""

    def test_includes_timestamp(self):
        """Health response should include a timestamp."""
        health = get_health_status()
        assert "timestamp" in health
        assert "T" in health["timestamp"]

    def test_includes_version(self):
        """Health response should include version."""
        health = get_health_status()
        assert "version" in health

    def test_includes_backend_name(self):
        """Health response should include the current backend name."""
        health = get_health_status()
        assert health["backend"] == "dummy"

    def test_includes_metrics(self):
        """Health response should include metrics summary."""
        health = get_health_status()
        assert "metrics" in health
        assert "uptime_seconds" in health["metrics"]

    def test_database_check_sql_backend(self, monkeypatch):
        """With SQL backend, health should include database check."""
        monkeypatch.setattr(
            "dagster_authkit.utils.config.config.AUTH_BACKEND", "sql"
        )

        backend = MagicMock()
        backend.get_name.return_value = "sql (Peewee)"
        backend.db = MagicMock()

        monkeypatch.setattr(
            "dagster_authkit.api.health.get_backend",
            lambda name, cfg: backend,
        )
        health = get_health_status()
        assert "database" in health.get("checks", {})

    def test_backend_exception_makes_unhealthy(self, monkeypatch):
        """If get_backend raises, status should be unhealthy."""
        monkeypatch.setattr(
            "dagster_authkit.api.health.get_backend",
            lambda name, cfg: (_ for _ in ()).throw(Exception("Backend error")),
        )
        health = get_health_status()
        assert health["status"] == "unhealthy"
        assert "error" in health["checks"]["backend"]


class TestHealthEndpoint:
    """Verifies the health_endpoint async handler."""

    @pytest.fixture
    def mock_request(self):
        """Returns a mock Starlette request."""
        req = MagicMock()
        req.query_params = MagicMock()
        req.query_params.get = MagicMock(return_value="full")
        return req

    @pytest.mark.asyncio
    async def test_liveness(self, mock_request):
        """type=live should return 200 always."""
        mock_request.query_params.get.return_value = "live"
        response = await health_endpoint(mock_request)
        assert response.status_code == 200
        body = json.loads(response.body)
        assert body["alive"] is True

    @pytest.mark.asyncio
    async def test_readiness_dummy_backend(self, mock_request):
        """type=ready with dummy backend should return 200."""
        mock_request.query_params.get.return_value = "ready"
        response = await health_endpoint(mock_request)
        assert response.status_code == 200
        body = json.loads(response.body)
        assert body["ready"] is True

    @pytest.mark.asyncio
    async def test_readiness_db_failure(self, mock_request, monkeypatch):
        """type=ready with failed DB should return 503."""
        monkeypatch.setattr(
            "dagster_authkit.utils.config.config.AUTH_BACKEND", "sql"
        )
        mock_request.query_params.get.return_value = "ready"
        backend = MagicMock()
        backend.db = MagicMock()
        backend.db.execute_sql.side_effect = Exception("DB down")
        monkeypatch.setattr(
            "dagster_authkit.api.health.get_backend",
            lambda name, cfg: backend,
        )
        response = await health_endpoint(mock_request)
        assert response.status_code == 503
        body = json.loads(response.body)
        assert body["ready"] is False

    @pytest.mark.asyncio
    async def test_readiness_backend_exception(self, mock_request, monkeypatch):
        """type=ready with backend error should return 503."""
        mock_request.query_params.get.return_value = "ready"
        monkeypatch.setattr(
            "dagster_authkit.api.health.get_backend",
            lambda name, cfg: (_ for _ in ()).throw(Exception("Init failed")),
        )
        response = await health_endpoint(mock_request)
        assert response.status_code == 503

    @pytest.mark.asyncio
    async def test_full_health(self, mock_request):
        """Default (full) health check should return full status."""
        mock_request.query_params.get.return_value = "full"
        response = await health_endpoint(mock_request)
        assert response.status_code == 200
        body = json.loads(response.body)
        assert "status" in body
        assert "checks" in body

    @pytest.mark.asyncio
    async def test_full_health_unhealthy(self, mock_request, monkeypatch):
        """Full health check with backend error should return 503."""
        mock_request.query_params.get.return_value = "full"
        monkeypatch.setattr(
            "dagster_authkit.api.health.get_backend",
            lambda name, cfg: (_ for _ in ()).throw(Exception("Broken")),
        )
        response = await health_endpoint(mock_request)
        assert response.status_code == 503


class TestMetricsEndpoint:
    """Verifies the metrics_endpoint async handler."""

    @pytest.mark.asyncio
    async def test_returns_json_with_counters(self):
        """Metrics endpoint should return JSON with counters."""
        req = MagicMock()
        response = await metrics_endpoint(req)
        assert response.status_code == 200
        body = json.loads(response.body)
        assert "counters" in body
        assert "gauges" in body
        assert "histograms" in body
        assert "uptime_seconds" in body
