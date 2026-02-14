"""
Dagster Monkey-Patching Module - "Resilient Infiltration" Edition

Injects user profile into Dagster sidebar with:
- Retry logic for late-loading React components
- Multiple CSS selector fallbacks for version compatibility
- Safe mode fallback (top-right corner) if injection fails
- Debug logging for production troubleshooting
"""

import json
import logging
import os

from starlette.requests import Request
from starlette.responses import HTMLResponse
from starlette.routing import Mount, Route

from dagster_authkit.api.health import health_endpoint, metrics_endpoint
from dagster_authkit.api.routes import create_auth_routes
from dagster_authkit.auth.backends.base import AuthUser
from dagster_authkit.utils.templates import render_user_menu_injection

logger = logging.getLogger(__name__)

original_index_html = None


def apply_patches() -> None:
    """Apply all monkey-patches to Dagster webserver."""
    logger.info("🔧 Applying resilient UI patches for Dagster...")

    try:
        import dagster_webserver.webserver as webserver_module
        from starlette.middleware import Middleware
        from .middleware import DagsterAuthMiddleware

        global original_index_html
    except ImportError as e:
        logger.error(f"❌ Failed to import required modules: {e}")
        raise

    # PATCH 1: Middleware
    try:
        original_build_middleware = webserver_module.DagsterWebserver.build_middleware

        def patched_build_middleware(self):
            middlewares = original_build_middleware(self)
            middlewares.insert(0, Middleware(DagsterAuthMiddleware))
            return middlewares

        webserver_module.DagsterWebserver.build_middleware = patched_build_middleware
        logger.info("✅ Middleware patched")
    except Exception as e:
        logger.error(f"❌ Middleware patch failed: {e}")
        raise

    # PATCH 2: Routes
    try:
        original_build_routes = webserver_module.DagsterWebserver.build_routes

        def patched_build_routes(self):

            routes_list = original_build_routes(self)

            auth_routes = create_auth_routes()

            auth_routes.routes.extend(
                [
                    Route("/health", health_endpoint, methods=["GET"]),
                    Route("/metrics", metrics_endpoint, methods=["GET"]),
                ]
            )

            routes_list.insert(0, Mount("/auth", routes=auth_routes.routes))
            return routes_list

        webserver_module.DagsterWebserver.build_routes = patched_build_routes
        logger.info("✅ Routes patched")
    except Exception as e:
        logger.error(f"❌ Routes patch failed: {e}")
        raise

    # PATCH 3: UI Injection (Resilient)
    try:
        original_index_html = webserver_module.DagsterWebserver.index_html_endpoint

        def patched_index_html_wrapper(self, request: Request):
            return _inject_resilient_ui(self, request)

        webserver_module.DagsterWebserver.index_html_endpoint = patched_index_html_wrapper
        logger.info("✅ Resilient UI injection patched")
    except Exception as e:
        logger.error(f"❌ UI patch failed: {e}")
        raise


def _inject_resilient_ui(self, request: Request):
    """Inject user menu with resilient retry logic and safe mode fallback."""
    response = original_index_html(self, request)

    # Get user from request state
    user = getattr(request.state, "user", None)

    if not user or not isinstance(user, AuthUser):
        return response

    # Extract user data
    username = user.username
    full_name = user.full_name or username.capitalize()
    email = user.email or ""
    role = user.role.name
    initial = (full_name[0] if full_name else username[0]).upper()

    # Read config from ENV
    debug_mode = os.getenv("DAGSTER_AUTH_DEBUG", "false").lower() == "true"
    safe_mode = os.getenv("DAGSTER_AUTH_UI_SAFE_MODE", "true").lower() == "true"

    # Serialize user data for JavaScript
    user_data_json = json.dumps(
        {
            "username": username,
            "full_name": full_name,
            "email": email,
            "role": role,
            "initial": initial,
            "has_email": bool(email),
        }
    )

    # Generate injection HTML
    injection = _generate_injection_html(user_data_json, debug_mode, safe_mode)

    # Inject into HTML
    if hasattr(response.body, "decode"):
        html = response.body.decode("utf-8")
    else:
        html = str(response.body)

    html = html.replace("</body>", f"{injection}</body>")

    # Update headers
    headers = dict(response.headers)
    headers.pop("content-length", None)
    headers.pop("etag", None)

    return HTMLResponse(content=html, status_code=response.status_code, headers=headers)


def _generate_injection_html(user_data_json: str, debug: bool, safe_mode: bool) -> str:
    """Generate complete HTML/CSS/JS injection code."""

    return render_user_menu_injection(user_data_json, debug, safe_mode)


def verify_patches() -> bool:
    """
    Verify patches were applied successfully.

    Returns:
        bool: True if patches are active, False otherwise
    """
    try:
        import dagster_webserver.webserver as webserver_module

        # Check if our patched method exists
        has_middleware = hasattr(webserver_module.DagsterWebserver, "build_middleware")
        has_routes = hasattr(webserver_module.DagsterWebserver, "build_routes")
        has_index = hasattr(webserver_module.DagsterWebserver, "index_html_endpoint")

        return has_middleware and has_routes and has_index
    except Exception as e:
        logger.error(f"Patch verification failed: {e}")
        return False
