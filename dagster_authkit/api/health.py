"""
Health Checks and Metrics Module

Endpoints for monitoring and observability.
"""

import logging
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict

from starlette.responses import JSONResponse

from dagster_authkit.core.registry import get_backend
from dagster_authkit.utils.config import config

logger = logging.getLogger(__name__)


class MetricsCollector:
    """
    Simple in-memory metrics collector.

    For distributed production, replace with Prometheus/StatsD.

    Tracks:
    - Counters (with optional labels)
    - Gauges
    - Histograms (capped at 1000 observations per label combination)

    Usage::

        collector = MetricsCollector()
        collector.increment_counter("requests", {"status": "200"})
        metrics = collector.get_metrics()
    """

    def __init__(self):
        """Initialise empty counters, gauges, histograms, and capture start time."""
        self._lock = threading.Lock()
        self._counters = defaultdict(int)
        self._gauges = defaultdict(float)
        self._histograms = defaultdict(list)
        self._start_time = time.time()

    def increment_counter(self, name: str, labels: Dict[str, str] = None, value: int = 1):
        """Increments counter."""
        with self._lock:
            key = self._make_key(name, labels)
            self._counters[key] += value

    def set_gauge(self, name: str, value: float, labels: Dict[str, str] = None):
        """Sets gauge value."""
        with self._lock:
            key = self._make_key(name, labels)
            self._gauges[key] = value

    def observe_histogram(self, name: str, value: float, labels: Dict[str, str] = None):
        """Adds observation to histogram."""
        with self._lock:
            key = self._make_key(name, labels)
            self._histograms[key].append(value)
            # Limit history to last 1000 observations
            if len(self._histograms[key]) > 1000:
                self._histograms[key] = self._histograms[key][-1000:]

    def _make_key(self, name: str, labels: Dict[str, str] = None) -> str:
        """Creates unique key for metric."""
        if not labels:
            return name
        label_str = ",".join(f"{k}={v}" for k, v in sorted(labels.items()))
        return f"{name}{{{label_str}}}"

    def get_metrics(self) -> Dict[str, Any]:
        """Returns all metrics."""
        with self._lock:
            return {
                "counters": dict(self._counters),
                "gauges": dict(self._gauges),
                "histograms": {
                    k: {
                        "count": len(v),
                        "sum": sum(v),
                        "avg": sum(v) / len(v) if v else 0,
                        "min": min(v) if v else 0,
                        "max": max(v) if v else 0,
                    }
                    for k, v in self._histograms.items()
                },
                "uptime_seconds": time.time() - self._start_time,
            }

    def reset(self):
        """Resets all metrics."""
        with self._lock:
            self._counters.clear()
            self._gauges.clear()
            self._histograms.clear()


# Global singleton
_metrics = MetricsCollector()


def get_metrics_collector() -> MetricsCollector:
    """Returns the global metrics collector."""
    return _metrics


def track_login_attempt(success: bool, username: str = None):
    """Tracks login attempt.
    Note: username is NOT used as a metric label to prevent:
    - Information leakage via the public /metrics endpoint
    - Unbounded label cardinality (DoS via memory exhaustion)
    """
    status = "success" if success else "failure"
    _metrics.increment_counter("auth_login_attempts_total", {"status": status})


def track_request_duration(endpoint: str, duration: float):
    """Tracks request duration."""
    _metrics.observe_histogram("auth_request_duration_seconds", duration, {"endpoint": endpoint})


def track_session_created():
    """Tracks session creation."""
    _metrics.increment_counter("auth_sessions_created_total")


def track_rbac_decision(allowed: bool, role: str):
    """Tracks RBAC decision.
    Note: action is intentionally omitted from metric labels to prevent
    unbounded label cardinality (memory DoS via arbitrary mutation names).
    """
    status = "allowed" if allowed else "denied"
    _metrics.increment_counter(
        "auth_rbac_decisions_total", {"status": status, "role": role}
    )


def _check_db_connection(backend) -> bool:
    """Execute a lightweight query to verify the database is reachable."""
    if not hasattr(backend, "db") or backend.db is None:
        return False
    try:
        backend.db.execute_sql("SELECT 1")
        return True
    except Exception as e:
        logger.error(f"Health check DB ping failed: {e}")
        return False


def get_health_status() -> Dict[str, Any]:
    """
    Returns system health status.

    Returns:
        Dict with status and details
    """

    health = {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "0.4.0",
        "backend": config.AUTH_BACKEND,
        "checks": {},
    }

    try:
        backend = get_backend(config.AUTH_BACKEND, config.__dict__)
        health["checks"]["backend"] = {"status": "ok", "name": backend.get_name()}

        # Check 2: Database (SQL backends)
        if config.AUTH_BACKEND in ("sql", "sqlite"):
            if _check_db_connection(backend):
                health["checks"]["database"] = {
                    "status": "ok",
                    "engine": type(backend.db).__name__,
                }
            else:
                health["status"] = "unhealthy"
                health["checks"]["database"] = {"status": "error", "error": "Database ping failed"}

    except Exception as e:
        health["status"] = "unhealthy"
        health["checks"]["backend"] = {"status": "error", "error": str(e)}

    # Check 3: Metrics
    metrics = _metrics.get_metrics()
    health["metrics"] = {
        "uptime_seconds": metrics["uptime_seconds"],
        "login_attempts": sum(
            v for k, v in metrics["counters"].items() if "auth_login_attempts_total" in k
        ),
    }

    return health


async def health_endpoint(request):
    """
    Unified health check endpoint.

    Serves as:
    - Load balancer health check (HTTP 200 = healthy)
    - Kubernetes liveness probe (``?type=live``)
    - Kubernetes readiness probe (``?type=ready``, tests DB connectivity)
    - Full health check (default, includes backend + DB status + metrics)

    Query params:
        ``type=live``  — Liveness: always returns 200 if the process is alive.
        ``type=ready`` — Readiness: tests backend and database connectivity.
        (default)      — Full health check with details and metrics summary.

    Returns:
        ``JSONResponse`` with appropriate status code (200 or 503).
    """
    check_type = request.query_params.get("type", "full")

    if check_type == "live":
        # Liveness: Is process alive?
        return JSONResponse({"alive": True}, status_code=200)

    elif check_type == "ready":
        # Readiness: Can serve traffic?
        try:
            backend = get_backend(config.AUTH_BACKEND, config.__dict__)
            if config.AUTH_BACKEND in ("sql", "sqlite"):
                if not _check_db_connection(backend):
                    return JSONResponse(
                        {"ready": False, "error": "Database unreachable"}, status_code=503
                    )
            return JSONResponse({"ready": True}, status_code=200)
        except Exception as e:
            return JSONResponse({"ready": False, "error": str(e)}, status_code=503)

    else:
        # Full health check
        health = get_health_status()
        status_code = 200 if health["status"] != "unhealthy" else 503
        return JSONResponse(health, status_code=status_code)


async def metrics_endpoint(request):
    """
    Metrics endpoint for observability.

    Returns basic in-memory metrics as JSON:
    - Counters (login attempts, RBAC decisions)
    - Gauges
    - Histograms (request duration with min/max/avg)
    - Uptime in seconds

    Note:
        In production, restrict access to this endpoint via IP allowlist
        or admin token. For distributed deployments, replace with Prometheus/StatsD.

    Returns:
        ``JSONResponse`` with all collected metrics.
    """
    metrics = _metrics.get_metrics()
    return JSONResponse(metrics)
