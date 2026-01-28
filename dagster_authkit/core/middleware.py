"""
Authentication Middleware - Community RBAC Version
"""

import json
import logging
import re
from typing import Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

from dagster_authkit.auth.backends.base import Role, AuthUser, RolePermissions
from dagster_authkit.auth.security import SecurityHardening
from dagster_authkit.auth.session import sessions
from dagster_authkit.utils.audit import log_access_control
from dagster_authkit.utils.config import config

from dagster_authkit.api.health import health_endpoint, metrics_endpoint

logger = logging.getLogger(__name__)


class DagsterAuthMiddleware(BaseHTTPMiddleware):
    # --- Configuration ---
    PUBLIC_PATHS: frozenset[str] = frozenset(
        {
            "/auth/login",
            "/auth/logout",
            "/auth/process",
            "/auth/health",
            "/auth/metrics",
        }
    )

    PUBLIC_PREFIXES: tuple[str, ...] = (
        "/auth/",
        "/static/",
    )

    WRITE_METHODS: frozenset[str] = frozenset({"POST", "PUT", "DELETE", "PATCH"})

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        method = request.method

        if path == "/auth/health":
            return await health_endpoint(request)

        if path == "/auth/metrics":
            return await metrics_endpoint(request)

        if self._is_public_path(path):
            response = await call_next(request)
            return SecurityHardening.set_security_headers(response)

        # 1. Validation via v1.0 Manager
        user = self._get_authenticated_user(request)
        if not user:
            # Better UX: 401 for APIs, 302 for humans
            if path == "/graphql" or request.headers.get("x-requested-with") == "XMLHttpRequest":
                return Response(content="Unauthorized", status_code=401)
            return RedirectResponse(url=f"/auth/login?next={path}", status_code=302)

        # 2. GraphQL Mutation RBAC
        if path == "/graphql" and method == "POST":
            body = await request.body()
            graphql_data = self._parse_json(body)
            queries = graphql_data if isinstance(graphql_data, list) else [graphql_data]

            for g_item in queries:
                query_str = g_item.get("query", "")
                if self._is_mutation(query_str):
                    mutation_name = self._extract_graphql_field_name(query_str)
                    required_role = RolePermissions.get_required_role(mutation_name)

                    if required_role and not user.can(required_role):
                        self._log_denied(user, mutation_name, required_role)
                        return self._generate_dagster_error_response(
                            user, mutation_name, required_role
                        )

            async def receive():
                return {"type": "http.request", "body": body}

            request = Request(request.scope, receive=receive)

        # 3. REST RBAC
        elif method in self.WRITE_METHODS and not user.can(Role.EDITOR):
            self._log_denied(user, f"REST_{method}_{path}", Role.EDITOR)
            return self._forbidden_html_response(user, path, method, "REQUIRES_EDITOR")

        request.state.user = user
        response = await call_next(request)
        return SecurityHardening.set_security_headers(response)

    # --- Helper Methods ---

    def _get_authenticated_user(self, request: Request) -> Optional[AuthUser]:
        token = request.cookies.get(config.SESSION_COOKIE_NAME)
        if not token:
            return None

        # v1.0 CALL: Using the sessions singleton validate method
        user_data = sessions.validate(token)
        if not user_data:
            return None

        try:
            return AuthUser.from_dict(user_data)
        except Exception as e:
            logger.error(f"User deserialization failed: {e}")
            return None

    def _is_public_path(self, path: str) -> bool:
        return path in self.PUBLIC_PATHS or any(path.startswith(p) for p in self.PUBLIC_PREFIXES)

    @staticmethod
    def _is_mutation(query: str) -> bool:
        return "mutation" in query.lower()[:100]

    @staticmethod
    def _extract_graphql_field_name(query: str) -> str:
        """v1.0 Robust Regex: Handles comments, aliases, and formatting."""
        clean_query = re.sub(r"#.*", "", query)
        pattern = r"mutation[^{]*\{\s*(?:[\w\d_]+\s*:\s*)?([\w\d_]+)"
        match = re.search(pattern, clean_query, re.IGNORECASE | re.DOTALL)
        return match.group(1) if match else "unknown"

    @staticmethod
    def _log_denied(user, action, role):
        logger.warning(f"RBAC DENIED: {user.username} (role: {user.role.name}) tried {action}")
        log_access_control(
            user.username, "POST", "/graphql", False, [user.role.name], f"REQUIRES_{role.name}"
        )

    @staticmethod
    def _parse_json(body: bytes) -> dict:
        try:
            return json.loads(body.decode("utf-8"))
        except:
            return {}

    @staticmethod
    def _generate_dagster_error_response(user, mutation, role) -> Response:
        payload = {
            "data": {
                mutation: {
                    "__typename": "PythonError",
                    "message": f"🔒 Access Denied: {role.name} role required",
                    "stack": [
                        f"Action: {mutation}\n",
                        f"User: {user.username} (role: {user.role.name})\n",
                        f"Required: {role.name}\n",
                    ],
                    "cls_name": "AccessControlError",
                }
            },
            "errors": [{"message": f"Access Denied: {role.name} required", "path": [mutation]}],
        }
        return Response(content=json.dumps(payload), status_code=200, media_type="application/json")

    @staticmethod
    def _forbidden_html_response(user: AuthUser, path: str, method: str, reason: str) -> Response:
        """Generate HTML 403 response."""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>403 Forbidden</title>
            <style>
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
                    background-color: #0f111a;
                    color: white;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    margin: 0;
                }}
                .container {{
                    text-align: center;
                    border: 1px solid #333;
                    padding: 40px;
                    border-radius: 12px;
                    background: #1a1d29;
                    max-width: 500px;
                }}
                h1 {{ color: #ff6b6b; margin: 0 0 20px 0; }}
                .info {{ color: #888; margin: 10px 0; }}
                .detail {{ font-size: 12px; color: #555; margin-top: 20px; }}
                a {{ color: #667eea; text-decoration: none; margin-top: 20px; display: inline-block; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🔒 403 Forbidden</h1>
                <p class="info">
                    User <strong>{user.username}</strong> (role: <strong>{user.role.name}</strong>)
                    cannot <strong>{method}</strong> on <strong>{path}</strong>.
                </p>
                <p class="detail">Reason: {reason}</p>
                <a href="/">← Return to Dashboard</a>
            </div>
        </body>
        </html>
        """
        return Response(content=html, status_code=403, media_type="text/html")
