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

from dagster_authkit.auth.backends.base import Role, AuthUser
from dagster_authkit.auth.security import SecurityHardening
from dagster_authkit.auth.session import validate_session
from dagster_authkit.utils.audit import log_access_control
from dagster_authkit.utils.config import config

logger = logging.getLogger(__name__)


class DagsterAuthMiddleware(BaseHTTPMiddleware):
    """
    Authentication and RBAC middleware for Dagster.

    Features:
    - Session validation (signed cookies)
    - GraphQL mutation detection
    - Role-based access control (4 levels)
    - Audit logging
    - Dagster-native error responses
    """

    PUBLIC_PATHS = {"/auth/login", "/auth/logout", "/auth/process", "/auth/health", "/auth/metrics"}

    ADMIN_PATHS_PREFIXES = ("/admin", "/settings", "/config")
    WRITE_METHODS = {"POST", "PUT", "DELETE", "PATCH"}

    # GraphQL mutation → required role mapping
    # GraphQL mutation → required role mapping
    MUTATION_ROLE_MAP = {
        # ===== LAUNCHER (20) - Execution Operations =====
        "launchRun": Role.LAUNCHER,
        "launchPipelineExecution": Role.LAUNCHER,
        "launchRunReexecution": Role.LAUNCHER,
        "launchPipelineReexecution": Role.LAUNCHER,
        "terminateRun": Role.LAUNCHER,
        "terminatePipelineExecution": Role.LAUNCHER,
        "terminateRuns": Role.LAUNCHER,
        "deleteRun": Role.LAUNCHER,
        "deletePipelineRun": Role.LAUNCHER,

        # ===== EDITOR (30) - Configuration & Management =====
        # Schedules
        "startSchedule": Role.EDITOR,
        "stopRunningSchedule": Role.EDITOR,
        "resetSchedule": Role.EDITOR,
        "scheduleDryRun": Role.EDITOR,

        # Sensors
        "startSensor": Role.EDITOR,
        "stopSensor": Role.EDITOR,
        "resetSensor": Role.EDITOR,
        "setSensorCursor": Role.EDITOR,
        "sensorDryRun": Role.EDITOR,

        # Assets
        "wipeAssets": Role.EDITOR,
        "reportRunlessAssetEvents": Role.EDITOR,
        "setAutoMaterializePaused": Role.EDITOR,

        # Backfills
        "launchPartitionBackfill": Role.EDITOR,
        "launchBackfill": Role.EDITOR,
        "cancelPartitionBackfill": Role.EDITOR,
        "resumePartitionBackfill": Role.EDITOR,
        "reexecutePartitionBackfill": Role.EDITOR,

        # Partitions
        "addDynamicPartition": Role.EDITOR,
        "deleteDynamicPartitions": Role.EDITOR,

        # Multiple runs
        "launchMultipleRuns": Role.EDITOR,

        # Concurrency
        "setConcurrencyLimit": Role.EDITOR,
        "deleteConcurrencyLimit": Role.EDITOR,
        "freeConcurrencySlotsForRun": Role.EDITOR,
        "freeConcurrencySlots": Role.EDITOR,

        # ===== ADMIN (40) - System Operations =====
        "reloadRepositoryLocation": Role.ADMIN,
        "reloadWorkspace": Role.ADMIN,
        "shutdownRepositoryLocation": Role.ADMIN,

        # ===== NO CHECK (Analytics/UI state) =====
        # "logTelemetry"
        # "setNuxSeen"
    }

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        method = request.method

        # 1. Skip authentication for public paths
        if self._is_public_path(path):
            response = await call_next(request)
            return SecurityHardening.set_security_headers(response)

        # 2. Authenticate user
        user = self._get_authenticated_user(request)
        if not user:
            return RedirectResponse(url=f"/auth/login?next={path}", status_code=302)

        # 3. GraphQL RBAC
        if path == "/graphql" and method == "POST":
            body = await request.body()
            graphql_data = self._parse_json(body)
            query = graphql_data.get("query", "")

            if self._is_mutation(query):
                mutation_name = self._extract_graphql_field_name(query)
                required_role = self.MUTATION_ROLE_MAP.get(mutation_name)

                if required_role:
                    # Check if user has sufficient permissions
                    if not user.can(required_role):
                        logger.warning(
                            f"RBAC BLOCK: {user.username} (role={user.role.name}) "
                            f"attempted {mutation_name} (requires {required_role.name})"
                        )

                        # Audit log
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
                        # Log successful access
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

        # 4. REST RBAC (for non-GraphQL paths)
        else:
            allowed, reason = self._check_rest_rbac(path, method, user)
            if not allowed:
                log_access_control(
                    user.username, method, path, False, roles=[user.role.name], reason=reason
                )
                return self._forbidden_html_response(user, path, method, reason)

        # 5. Attach user to request state
        request.state.user = user

        # 6. Continue to Dagster
        response = await call_next(request)
        return SecurityHardening.set_security_headers(response)

    # ========================================
    # AUTHENTICATION
    # ========================================

    def _is_public_path(self, path: str) -> bool:
        """Check if path is public (no auth required)."""
        return path in self.PUBLIC_PATHS or path.startswith(("/auth/", "/static/"))

    def _get_authenticated_user(self, request: Request) -> Optional[AuthUser]:
        """
        Validate session and return AuthUser.

        Returns:
            AuthUser if authenticated, None otherwise
        """
        token = request.cookies.get(config.SESSION_COOKIE_NAME)
        if not token:
            return None

        # Validate session (returns dict)
        user_data = validate_session(token)
        if not user_data:
            return None

        # Convert dict → AuthUser
        try:
            return AuthUser.from_dict(user_data)
        except Exception as e:
            logger.error(f"Failed to deserialize user from session: {e}")
            return None

    # ========================================
    # GRAPHQL RBAC
    # ========================================

    def _parse_json(self, body: bytes) -> dict:
        """Parse JSON body safely."""
        try:
            return json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}

    def _is_mutation(self, query: str) -> bool:
        """Check if GraphQL query is a mutation."""
        # Check first 100 chars for performance
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
                    "message": msg,
                    "stack": [
                        '  File "dagster_authkit/core/middleware.py", line 145, in dispatch\n',
                        f'    raise PermissionError("Insufficient permissions: {required_role.name} required")\n',
                    ],
                    "cls_name": "PermissionError",
                    "cause": None,
                    "context": None,
                }
            },
            "errors": [
                {
                    "message": msg,
                    "path": [mutation_name],
                    "extensions": {
                        "code": "FORBIDDEN",
                        "errorInfo": {"message": msg, "stack": [], "cls_name": "PermissionError"},
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

    def _check_rest_rbac(self, path: str, method: str, user: AuthUser) -> tuple:
        """
        Check REST RBAC rules.

        Returns:
            (allowed: bool, reason: str)
        """
        # Admin-only paths
        if any(path.startswith(prefix) for prefix in self.ADMIN_PATHS_PREFIXES):
            if not user.can(Role.ADMIN):
                return False, "ADMIN_REQUIRED"

        # Write operations require EDITOR
        if method in self.WRITE_METHODS:
            if not user.can(Role.EDITOR):
                return False, "EDITOR_REQUIRED"

        return True, ""

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
