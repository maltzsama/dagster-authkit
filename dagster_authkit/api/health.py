"""
Health Checks and Metrics Module

Endpoints for monitoring and observability.
"""

import logging
import threading
import time
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict

logger = logging.getLogger(__name__)


class MetricsCollector:
    """
    Simple in-memory metrics collector.

    For distributed production, replace with Prometheus/StatsD.
    """

    def __init__(self):
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
    """Tracks login attempt."""
    status = "success" if success else "failure"
    _metrics.increment_counter("auth_login_attempts_total", {"status": status})

    if not success and username:
        # Track failures per user (last 100)
        _metrics.increment_counter("auth_login_failures", {"username": username})


def track_request_duration(endpoint: str, duration: float):
    """Tracks request duration."""
    _metrics.observe_histogram("auth_request_duration_seconds", duration, {"endpoint": endpoint})


def track_session_created():
    """Tracks session creation."""
    _metrics.increment_counter("auth_sessions_created_total")


def track_rbac_decision(allowed: bool, role: str, action: str):
    """Tracks RBAC decision."""
    status = "allowed" if allowed else "denied"
    _metrics.increment_counter(
        "auth_rbac_decisions_total", {"status": status, "role": role, "action": action}
    )


def get_health_status() -> Dict[str, Any]:
    """
    Returns system health status.

    Returns:
        Dict with status and details
    """
    from .config import config

    health = {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "0.2.0",
        "backend": config.AUTH_BACKEND,
        "checks": {},
    }

    # Check 1: Backend accessibility
    try:
        from .registry import get_backend

        backend = get_backend(config.AUTH_BACKEND, config.__dict__)
        health["checks"]["backend"] = {"status": "ok", "name": backend.get_name()}
    except Exception as e:
        health["status"] = "degraded"
        health["checks"]["backend"] = {"status": "error", "error": str(e)}

    # Check 2: Database (if SQLite)
    if config.AUTH_BACKEND == "sqlite":
        try:
            import sqlite3

            db_path = config.__dict__.get("DAGSTER_AUTH_DB", "./dagster_auth.db")
            conn = sqlite3.connect(db_path, timeout=5.0)
            conn.execute("SELECT 1")
            conn.close()
            health["checks"]["database"] = {"status": "ok"}
        except Exception as e:
            health["status"] = "unhealthy"
            health["checks"]["database"] = {"status": "error", "error": str(e)}

    # Check 3: Metrics
    metrics = _metrics.get_metrics()
    health["metrics"] = {
        "uptime_seconds": metrics["uptime_seconds"],
        "login_attempts": sum(
            v for k, v in metrics["counters"].items() if "auth_login_attempts_total" in k
        ),
    }

    return health


def create_health_routes(routes):
    """
    Adds health check routes to the router.

    Only 2 endpoints:
    - /auth/health: Unified health check (for load balancers AND K8s probes)
    - /auth/metrics: Optional metrics (for observability)

    Args:
        routes: Starlette Routes object
    """
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    async def health_endpoint(request):
        """
        Unified health check endpoint.

        Serves for:
        - Load balancers (HTTP 200 = healthy)
        - Kubernetes liveness probe
        - Kubernetes readiness probe

        Query params:
        - ?type=live: Liveness check (always returns 200 if process alive)
        - ?type=ready: Readiness check (checks backend)
        - (default): Full health check with details
        """
        check_type = request.query_params.get("type", "full")

        if check_type == "live":
            # Liveness: Is process alive?
            return JSONResponse({"alive": True}, status_code=200)

        elif check_type == "ready":
            # Readiness: Can serve traffic?
            try:
                from .config import config
                from .registry import get_backend

                backend = get_backend(config.AUTH_BACKEND, config.__dict__)
                return JSONResponse({"ready": True}, status_code=200)
            except Exception as e:
                return JSONResponse({"ready": False, "error": str(e)}, status_code=503)

        else:
            # Full health check
            health = get_health_status()

            status_code = 200
            if health["status"] == "degraded":
                status_code = 200  # Still serving traffic
            elif health["status"] == "unhealthy":
                status_code = 503  # Service unavailable

            return JSONResponse(health, status_code=status_code)

    async def metrics_endpoint(request):
        """
        Metrics endpoint (optional - for observability).

        Returns basic metrics in JSON:
        - Counters (login attempts, etc.)
        - Gauges
        - Histograms
        - Uptime
        """
        metrics = _metrics.get_metrics()
        return JSONResponse(metrics)

    # Adds only 2 routes
    routes.routes.extend(
        [
            Route("/auth/health", health_endpoint, methods=["GET"]),
            Route("/auth/metrics", metrics_endpoint, methods=["GET"]),
        ]
    )

    logger.info("Health check routes registered: /auth/health (unified), /auth/metrics")
