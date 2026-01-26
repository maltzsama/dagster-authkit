"""
Authentication Middleware - Enterprise RBAC Version
Refined for Dagster+ hierarchy: Viewer < Launcher < Editor < Admin.
Includes schema-compliant GraphQL error reporting (PythonError extensions).
"""

import json
import logging
import re
from typing import Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

from dagster_authkit.auth.security import SecurityHardening
from dagster_authkit.auth.session import validate_session
from dagster_authkit.utils.audit import log_access_control
from dagster_authkit.utils.config import config

logger = logging.getLogger(__name__)


class DagsterAuthMiddleware(BaseHTTPMiddleware):
    PUBLIC_PATHS = {"/auth/login", "/auth/logout", "/auth/process", "/auth/health", "/auth/metrics"}
    ADMIN_PATHS_PREFIXES = ("/admin", "/settings", "/config")
    WRITE_METHODS = {"POST", "PUT", "DELETE", "PATCH"}

    # Official Dagster+ Hierarchical Levels
    ROLE_LEVELS = {"viewer": 10, "launcher": 20, "editor": 30, "admin": 40}

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        method = request.method

        if self._is_public_path(path):
            response = await call_next(request)
            return SecurityHardening.set_security_headers(response)

        user_data = self._get_authenticated_user(request)
        if not user_data:
            return RedirectResponse(url=f"/auth/login?next={path}", status_code=302)

        username = user_data.get("username", "unknown")
        roles = user_data.get("roles", ["viewer"])

        # ========================================
        # GRAPHQL RBAC (The "Launcher" Logic)
        # ========================================
        if path == "/graphql" and method == "POST":
            body = await request.body()
            graphql_data = self._parse_json(body)
            query = graphql_data.get("query", "")

            if self._is_mutation(query):
                field_name = self._extract_graphql_field_name(query)
                user_max_level = max([self.ROLE_LEVELS.get(r.lower(), 10) for r in roles])

                # 1. Define Execution vs Configuration operations
                # Based on Dagster+ Official Permissions
                execution_ops = {"launchRun", "terminateRun", "reexecuteRun", "cancelRun"}

                # Determine required level
                if field_name in execution_ops:
                    required_level = self.ROLE_LEVELS["launcher"]  # 20
                    required_role = "launcher"
                else:
                    required_level = self.ROLE_LEVELS["editor"]  # 30
                    required_role = "editor"

                # 2. Block if user level is insufficient
                if user_max_level < required_level:
                    return self._generate_dagster_error_response(
                        username, roles, field_name, required_role
                    )

            # Re-inject body for the Dagster webserver process
            async def receive():
                return {"type": "http.request", "body": body}

            request = Request(request.scope, receive=receive)

        else:
            # REST RBAC
            allowed, reason = self._check_rest_rbac(path, method, roles)
            if not allowed:
                return self._forbidden_html_response(username, roles, path, method, reason)

        request.state.user = user_data
        response = await call_next(request)
        return SecurityHardening.set_security_headers(response)

    def _is_public_path(self, path: str) -> bool:
        return path in self.PUBLIC_PATHS or path.startswith(("/auth/", "/static/"))

    def _get_authenticated_user(self, request: Request) -> Optional[dict]:
        token = request.cookies.get(config.SESSION_COOKIE_NAME)
        return validate_session(token) if token else None

    def _parse_json(self, body: bytes) -> dict:
        try:
            return json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}

    def _is_mutation(self, query: str) -> bool:
        # Check first 100 chars to avoid regex on massive queries
        return "mutation" in query.lower()[:100]

    def _extract_graphql_field_name(self, query: str) -> str:
        """
        Extracts the first field inside the mutation block.
        mutation X { launchRun(...) } -> 'launchRun'
        """
        match = re.search(r"mutation[^{]*\{\s*(\w+)", query)
        return match.group(1) if match else "unknown"

    def _generate_dagster_error_response(self, username, roles, field_name, required_role):
        """
        Returns a PythonError extension payload.
        This allows Dagster UI to show the error in its native inspector.
        """
        log_access_control(
            username,
            "POST",
            "/graphql",
            False,
            roles=roles,
            reason=f"REQUIRES_{required_role.upper()}",
        )

        msg = f"Permission Denied: User '{username}' requires '{required_role}' role for operation '{field_name}'."

        response_payload = {
            "data": {
                field_name: {
                    "__typename": "PythonError",
                    "message": msg,
                    "stack": [
                        f'  File "dagster_authkit/core/middleware.py", line 110, in check_rbac\n',
                        f'    raise PermissionError("Insufficient permissions: {required_role} level required")\n',
                    ],
                    "cls_name": "PermissionError",
                    "cause": None,
                    "context": None,
                }
            },
            "errors": [
                {
                    "message": msg,
                    "path": [field_name],
                    "extensions": {
                        "code": "FORBIDDEN",
                        "errorInfo": {"message": msg, "stack": [], "cls_name": "PermissionError"},
                    },
                }
            ],
        }

        return Response(
            content=json.dumps(response_payload), status_code=200, media_type="application/json"
        )

    def _check_rest_rbac(self, path, method, roles):
        user_max_level = max([self.ROLE_LEVELS.get(r.lower(), 10) for r in roles])

        # Admin restricted paths
        if any(path.startswith(p) for p in self.ADMIN_PATHS_PREFIXES):
            if user_max_level < self.ROLE_LEVELS["admin"]:
                return False, "ADMIN_REQUIRED"

        # General write protection
        if method in self.WRITE_METHODS:
            if user_max_level < self.ROLE_LEVELS["editor"]:
                return False, "EDITOR_REQUIRED"

        return True, ""

    def _forbidden_html_response(self, username, roles, path, method, reason):
        html = f"""
        <html>
            <body style='font-family:sans-serif; background-color: #0f111a; color: white; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0;'>
                <div style='text-align: center; border: 1px solid #333; padding: 40px; border-radius: 12px; background: #1a1d29;'>
                    <h1 style='color: #ff6b6b;'>🔒 403 Forbidden</h1>
                    <p style='color: #888;'>User <strong>{username}</strong> does not have permission to {method} on {path}.</p>
                    <p style='font-size: 12px; color: #555;'>Reason: {reason}</p>
                    <a href='/' style='color: #667eea; text-decoration: none;'>Return to Dashboard</a>
                </div>
            </body>
        </html>
        """
        return Response(content=html, status_code=403, media_type="text/html")
