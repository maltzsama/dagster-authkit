"""
Authentication Middleware - Community RBAC Version

Implements Dagster+ role hierarchy: VIEWER < LAUNCHER < EDITOR < ADMIN.
Includes GraphQL mutation detection and schema-compliant error responses.
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
from dagster_authkit.auth.session import validate_session
from dagster_authkit.utils.audit import log_access_control
from dagster_authkit.utils.config import config

logger = logging.getLogger(__name__)


class DagsterAuthMiddleware(BaseHTTPMiddleware):
    """
    Authentication and RBAC middleware for Dagster.

    Access Control Rules:
    1. Public paths (/auth/*) - No authentication required
    2. GraphQL (/graphql) - Mutation-level RBAC based on operation
    3. REST endpoints:
       - Write operations (POST/PUT/DELETE/PATCH) - Requires EDITOR role
       - Read operations (GET) - Requires VIEWER role (authenticated)

    Role Hierarchy: VIEWER(10) < LAUNCHER(20) < EDITOR(30) < ADMIN(40)
    """

    # ========================================
    # Configuration
    # ========================================

    # Public endpoints (no authentication required)
    PUBLIC_PATHS: frozenset[str] = frozenset({
        "/auth/login",
        "/auth/logout",
        "/auth/process",
        "/auth/health",
        "/auth/metrics",
    })

    PUBLIC_PREFIXES: tuple[str, ...] = (
        "/auth/",
        "/static/",
    )

    # Write operations (require EDITOR role for REST)
    WRITE_METHODS: frozenset[str] = frozenset({
        "POST",
        "PUT",
        "DELETE",
        "PATCH",
    })

    # ========================================
    # Main Dispatch
    # ========================================

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        method = request.method

        # 1. Public paths - skip authentication
        if self._is_public_path(path):
            response = await call_next(request)
            return SecurityHardening.set_security_headers(response)

        # 2. Require authentication
        user = self._get_authenticated_user(request)
        if not user:
            return RedirectResponse(url=f"/auth/login?next={path}", status_code=302)

        # 3. GraphQL - mutation-level RBAC
        if path == "/graphql" and method == "POST":
            body = await request.body()
            graphql_data = self._parse_json(body)
            query = graphql_data.get("query", "")

            if self._is_mutation(query):
                mutation_name = self._extract_graphql_field_name(query)
                required_role = RolePermissions.get_required_role(mutation_name)

                if required_role:
                    if not user.can(required_role):
                        logger.warning(
                            f"RBAC BLOCK: {user.username} (role={user.role.name}) "
                            f"attempted {mutation_name} (requires {required_role.name})"
                        )

                        log_access_control(
                            user.username,
                            "POST",
                            "/graphql",
                            False,
                            roles=[user.role.name],
                            reason=f"REQUIRES_{required_role.name}",
                        )

                        return self._generate_dagster_error_response(
                            user, mutation_name, required_role
                        )
                    else:
                        log_access_control(
                            user.username,
                            "POST",
                            "/graphql",
                            True,
                            roles=[user.role.name],
                            reason=f"MUTATION_{mutation_name}",
                        )

            # Re-inject body for downstream consumption
            async def receive():
                return {"type": "http.request", "body": body}

            request = Request(request.scope, receive=receive)

        # 4. REST - simple method-based RBAC
        else:
            if method in self.WRITE_METHODS and not user.can(Role.EDITOR):
                log_access_control(
                    user.username,
                    method,
                    path,
                    False,
                    roles=[user.role.name],
                    reason="REQUIRES_EDITOR",
                )
                return self._forbidden_html_response(
                    user, path, method, "REQUIRES_EDITOR"
                )

        # 5. Attach user to request state
        request.state.user = user

        # 6. Continue to Dagster
        response = await call_next(request)
        return SecurityHardening.set_security_headers(response)

    # ========================================
    # Authentication
    # ========================================

    def _is_public_path(self, path: str) -> bool:
        """Check if path requires no authentication."""
        if path in self.PUBLIC_PATHS:
            return True
        return any(path.startswith(prefix) for prefix in self.PUBLIC_PREFIXES)

    def _get_authenticated_user(self, request: Request) -> Optional[AuthUser]:
        """
        Validate session and return AuthUser.

        Returns:
            AuthUser if authenticated, None otherwise
        """
        token = request.cookies.get(config.SESSION_COOKIE_NAME)
        if not token:
            return None

        user_data = validate_session(token)
        if not user_data:
            return None

        try:
            return AuthUser.from_dict(user_data)
        except Exception as e:
            logger.error(f"Failed to deserialize user from session: {e}")
            return None

    # ========================================
    # GraphQL RBAC
    # ========================================

    def _parse_json(self, body: bytes) -> dict:
        """Parse JSON body safely."""
        try:
            return json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}

    def _is_mutation(self, query: str) -> bool:
        """Check if GraphQL query is a mutation."""
        return "mutation" in query.lower()[:100]

    def _extract_graphql_field_name(self, query: str) -> str:
        """
        Extract mutation name from GraphQL query.

        Examples:
            mutation { launchRun(...) } → "launchRun"
            mutation StartRun { launchRun(...) } → "launchRun"
        """
        match = re.search(r"mutation[^{]*\{\s*(\w+)", query)
        return match.group(1) if match else "unknown"

    def _generate_dagster_error_response(
        self, user: AuthUser, mutation_name: str, required_role: Role
    ) -> Response:
        """
        Generate Dagster-native error response (PythonError format).

        This ensures the error appears in Dagster UI's native inspector.
        """
        msg = (
            f"Permission Denied: User '{user.username}' (role: {user.role.name}) "
            f"requires '{required_role.name}' role for operation '{mutation_name}'."
        )

        response_payload = {
            "data": {
                mutation_name: {
                    "__typename": "PythonError",
                    "message": f"🔒 Access Denied: {required_role.name} role required",
                    "stack": [
                        f"Action: {mutation_name}\n",
                        f"User: {user.username} (current role: {user.role.name})\n",
                        f"Required role: {required_role.name}\n",
                        f"\nTo request access, contact your platform engineering team.\n",
                    ],
                    "cls_name": "AccessControlError",
                    "cause": None,
                    "context": None,
                }
            },
            "errors": [
                {
                    "message": f"Access Denied: {required_role.name} role required",  # ← Mais específico
                    "path": [mutation_name],
                    "extensions": {
                        "code": "FORBIDDEN",
                        "requiredRole": required_role.name,  # ← Extra metadata útil
                        "userRole": user.role.name,
                    },
                }
            ],
        }

        return Response(
            content=json.dumps(response_payload),
            status_code=200,  # GraphQL returns 200 even for errors
            media_type="application/json",
        )

    # ========================================
    # REST RBAC
    # ========================================

    def _forbidden_html_response(
        self, user: AuthUser, path: str, method: str, reason: str
    ) -> Response:
        """Generate HTML 403 Forbidden page."""
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
                h1 {{
                    color: #ff6b6b;
                    margin: 0 0 20px 0;
                }}
                .info {{
                    color: #888;
                    margin: 10px 0;
                }}
                .detail {{
                    font-size: 12px;
                    color: #555;
                    margin-top: 20px;
                }}
                a {{
                    color: #667eea;
                    text-decoration: none;
                    margin-top: 20px;
                    display: inline-block;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🔒 403 Forbidden</h1>
                <p class="info">
                    User <strong>{user.username}</strong> (role: <strong>{user.role.name}</strong>)
                    does not have permission to <strong>{method}</strong> on <strong>{path}</strong>.
                </p>
                <p class="detail">Reason: {reason}</p>
                <a href="/">← Return to Dashboard</a>
            </div>
        </body>
        </html>
        """
        return Response(content=html, status_code=403, media_type="text/html")
