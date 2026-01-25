"""
Authentication Middleware - The "Indestructible" Version

Fixed: Correctly maps GraphQL field names to prevent "Webserver crash" errors.
Injects PythonError extensions to support Dagster's native error inspector.
"""

import json
import logging
import re
from typing import Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

from dagster_authkit.utils.audit import log_access_control
from dagster_authkit.utils.config import config
from dagster_authkit.auth.security import SecurityHardening
from dagster_authkit.auth.session import validate_session

logger = logging.getLogger(__name__)


class DagsterAuthMiddleware(BaseHTTPMiddleware):
    PUBLIC_PATHS = {"/auth/login", "/auth/logout", "/auth/process", "/auth/health", "/auth/metrics"}
    ADMIN_PATHS_PREFIXES = ("/admin", "/settings", "/config")
    WRITE_METHODS = {"POST", "PUT", "DELETE", "PATCH"}

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
        roles = user_data.get("roles", [])

        # ========================================
        # GRAPHQL RBAC - THE FIX
        # ========================================
        if path == "/graphql" and method == "POST":
            body = await request.body()
            graphql_data = self._parse_json(body)
            query = graphql_data.get("query", "")

            # 1. Detect if it is a mutation
            if self._is_mutation(query):
                if not ("editor" in roles or "admin" in roles):
                    # 2. Extract the ACTUAL field name (e.g., 'launchRun', not 'LaunchRun')
                    field_name = self._extract_graphql_field_name(query)
                    return self._generate_dagster_error_response(username, roles, field_name)

            # Re-inject body for Dagster
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
        except:
            return {}

    def _is_mutation(self, query: str) -> bool:
        return "mutation" in query.lower()[:100]

    def _extract_graphql_field_name(self, query: str) -> str:
        """
        Extracts the first field inside the mutation block.
        Example: mutation X { launchRun(...) } -> returns 'launchRun'
        """
        # Procura a primeira palavra após o primeiro abre-chaves da mutation
        match = re.search(r"mutation[^{]*\{\s*(\w+)", query)
        if match:
            return match.group(1)
        return "unknown"

    def _generate_dagster_error_response(self, username, roles, field_name):
        """
        Creates a schema-compliant response that satisfies Apollo and Dagster UI.
        """
        log_access_control(username, "POST", "/graphql", False, roles=roles, reason="RBAC_DENIED")

        msg = f"Permission Denied: User '{username}' requires 'editor' role for mutations."

        # Injeta a estrutura PythonError com as extensões que vimos no AppError.tsx
        response_payload = {
            "data": {
                field_name: {
                    "__typename": "PythonError",
                    "message": msg,
                    "stack": [
                        '  File "auth_middleware.py", line 105, in check_rbac\n    raise PermissionError("Insufficient roles")\n'
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
        if "admin" in roles:
            return True, ""
        if any(path.startswith(p) for p in self.ADMIN_PATHS_PREFIXES):
            return False, "ADMIN_REQUIRED"
        if method in self.WRITE_METHODS and "editor" not in roles:
            return False, "EDITOR_REQUIRED"
        return True, ""

    def _forbidden_html_response(self, username, roles, path, method, reason):
        html = f"<html><body style='font-family:sans-serif;'><h1>🔒 403 Forbidden</h1><p>{reason}</p></body></html>"
        return Response(content=html, status_code=403, media_type="text/html")
