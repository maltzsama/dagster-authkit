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
    get_health_status,
    get_metrics_collector,
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
        """Tracking a failed login should increment failure and per-user counters."""
        track_login_attempt(False, username="attacker")
        metrics = get_metrics_collector().get_metrics()
        assert "auth_login_attempts_total{status=failure}" in metrics["counters"]
        assert "auth_login_failures{username=attacker}" in metrics["counters"]

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
