"""
Dagster Monkey-Patching Module

Injects user profile into Dagster sidebar with:

- Async/sync detection for cross-version Dagster compatibility
- Resilient injection that falls back to vanilla Dagster on failure
- Multiple CSS selector fallbacks for version compatibility
- Safe mode fallback (top-right corner) if client-side injection fails
- Idempotent patch application (safe to call multiple times)
"""

import inspect
import json
import logging
from typing import Optional

from starlette.requests import Request
from starlette.responses import HTMLResponse
from starlette.routing import Mount, Route

from dagster_authkit.api.health import health_endpoint, metrics_endpoint
from dagster_authkit.api.routes import create_auth_routes
from dagster_authkit.auth.backends.base import AuthUser
from dagster_authkit.utils.config import config
from dagster_authkit.utils.templates import render_user_menu_injection

logger = logging.getLogger(__name__)

original_index_html = None


def apply_patches() -> None:
    """Apply all monkey-patches to Dagster webserver. Idempotent."""
    import dagster_webserver.webserver as webserver_module
    from starlette.middleware import Middleware
    from .middleware import DagsterAuthMiddleware

    if getattr(webserver_module.DagsterWebserver, "_authkit_patched", False):
        logger.warning("Patches already applied, skipping")
        return

    logger.info("Applying resilient UI patches for Dagster...")

    global original_index_html

    # PATCH 1: Middleware
    try:
        original_build_middleware = webserver_module.DagsterWebserver.build_middleware

        def patched_build_middleware(self):
            middlewares = original_build_middleware(self)
            middlewares.insert(0, Middleware(DagsterAuthMiddleware))
            return middlewares

        webserver_module.DagsterWebserver.build_middleware = patched_build_middleware
        logger.info("Middleware patched")
    except Exception as e:
        logger.error(f"Middleware patch failed: {e}")
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
        logger.info("Routes patched")
    except Exception as e:
        logger.error(f"Routes patch failed: {e}")
        raise

    # PATCH 3: UI Injection (async-aware, resilient)
    try:
        original_index_html = webserver_module.DagsterWebserver.index_html_endpoint

        if inspect.iscoroutinefunction(original_index_html):

            async def patched_index_html(self, request: Request):
                return await _inject_resilient_ui(self, request)

        else:

            def patched_index_html(self, request: Request):
                return _inject_resilient_ui(self, request)

        webserver_module.DagsterWebserver.index_html_endpoint = patched_index_html
        logger.info("Resilient UI injection patched")
    except Exception as e:
        logger.error(f"UI patch failed: {e}")
        raise

    # Mark as patched to prevent re-application
    webserver_module.DagsterWebserver._authkit_patched = True


async def _inject_resilient_ui(self, request: Request) -> HTMLResponse:
    """Inject user menu with resilient fallback to vanilla Dagster.

    If ANYTHING goes wrong during injection, the original Dagster HTML
    is served untouched — the user gets Dagster without the profile menu,
    but the application remains functional.
    """
    try:
        if inspect.iscoroutinefunction(original_index_html):
            response = await original_index_html(self, request)
        else:
            response = original_index_html(self, request)
    except Exception as e:
        logger.error(f"Failed to get index HTML: {e}", exc_info=True)
        raise

    user = getattr(request.state, "user", None)

    if not user or not isinstance(user, AuthUser):
        if user is not None and not isinstance(user, AuthUser):
            logger.debug(f"request.state.user is not an AuthUser: {type(user)}")
        return response

    try:
        username = user.username
        full_name = user.full_name or username.capitalize()
        email = user.email or ""
        role = user.role.name
        initial = (full_name[0] if full_name else username[0]).upper()

        user_data_json = (
            json.dumps(
                {
                    "username": username,
                    "full_name": full_name,
                    "email": email,
                    "role": role,
                    "initial": initial,
                    "has_email": bool(email),
                }
            )
            # Prevent XSS via </script> in user data (e.g., LDAP full_name)
            .replace("<", "\\u003c").replace(">", "\\u003e")
        )

        injection = render_user_menu_injection(
            user_data_json,
            debug=config.UI_DEBUG,
            safe_mode=config.UI_SAFE_MODE,
        )

        body = getattr(response, "body", None)
        if body is None:
            logger.warning("Response has no .body attribute; cannot inject UI")
            return response

        if hasattr(body, "decode"):
            html = body.decode("utf-8")
        else:
            logger.warning("Response body is not decodable; cannot inject UI")
            return response

        if "</body>" not in html:
            logger.warning("No </body> tag found in HTML; cannot inject UI")
            return response

        html = html.replace("</body>", f"{injection}</body>", 1)

        headers = dict(response.headers)
        headers.pop("content-length", None)
        headers.pop("content-encoding", None)
        headers.pop("etag", None)

        return HTMLResponse(
            content=html,
            status_code=response.status_code,
            headers=headers,
        )

    except Exception as e:
        logger.error(
            f"UI injection failed, serving vanilla Dagster: {e}",
            exc_info=True,
        )
        return response


def verify_patches() -> bool:
    """
    Verify patches were applied successfully using the sentinel we set
    during apply_patches(). Returns False if patches are not active.
    """
    try:
        import dagster_webserver.webserver as webserver_module

        return getattr(webserver_module.DagsterWebserver, "_authkit_patched", False)
    except Exception as e:
        logger.error(f"Patch verification failed: {e}")
        return False
