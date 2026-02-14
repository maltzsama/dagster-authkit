# dagster_authkit/core/middleware.py
"""
Authentication Middleware - Community RBAC Version
NOW with Proxy Auth support (Authelia)
"""

import json
import logging
from typing import Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

from dagster_authkit.api.health import health_endpoint, metrics_endpoint, track_rbac_decision
from dagster_authkit.auth.backends.base import Role, AuthUser, RolePermissions
from dagster_authkit.auth.security import SecurityHardening
from dagster_authkit.auth.session import sessions
from dagster_authkit.core.graphql_analyzer import GraphQLMutationAnalyzer
from dagster_authkit.core.registry import get_backend
from dagster_authkit.utils.audit import log_access_control
from dagster_authkit.utils.config import config
from dagster_authkit.utils.templates import render_403_page

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

    def __init__(self, app):
        super().__init__(app)

        self.is_proxy_mode = config.AUTH_BACKEND == "proxy"

        if self.is_proxy_mode:
            self.proxy_backend = get_backend("proxy", config.__dict__)
            logger.info("🔒 Middleware: PROXY MODE enabled (Authelia forward auth)")
        else:
            self.proxy_backend = None
            logger.info(f"🔒 Middleware: SESSION MODE (backend={config.AUTH_BACKEND})")

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        method = request.method

        if path == "/auth/health":
            return await health_endpoint(request)

        if path == "/auth/metrics":
            return await metrics_endpoint(request)

        if self.is_proxy_mode and path in ["/auth/login", "/auth/process"]:
            return Response(
                content="This endpoint is disabled in proxy auth mode. Authentication is handled by Authelia.",
                status_code=404,
            )

        if self._is_public_path(path) and not self.is_proxy_mode:
            response = await call_next(request)
            return SecurityHardening.set_security_headers(response)

        # PROXY or SESSION
        if self.is_proxy_mode:
            user = self._get_user_from_proxy(request)
            if not user:
                return Response(
                    content="Unauthorized: Missing authentication headers from proxy",
                    status_code=401,
                )
        else:
            user = self._get_authenticated_user(request)
            if not user:
                # Better UX: 401 for APIs, 302 for humans
                if (
                    path == "/graphql"
                    or request.headers.get("x-requested-with") == "XMLHttpRequest"
                ):
                    return Response(content="Unauthorized", status_code=401)
                return RedirectResponse(url=f"/auth/login?next={path}", status_code=302)

        # RBAC: GraphQL Mutations
        if path == "/graphql" and method == "POST":
            body = await request.body()
            graphql_data = self._parse_json(body)
            queries = graphql_data if isinstance(graphql_data, list) else [graphql_data]

            for g_item in queries:
                query_str = g_item.get("query", "")
                mutation_names = GraphQLMutationAnalyzer.extract_mutation_names(query_str)

                if not mutation_names:
                    continue

                for mutation_name in mutation_names:
                    required_role = RolePermissions.get_required_role(mutation_name)

                    if required_role and not user.can(required_role):
                        self._log_denied(user, mutation_name, required_role)

                        track_rbac_decision(
                            allowed=False, role=user.role.name, action=mutation_name
                        )

                        return self._generate_dagster_error_response(
                            user, mutation_name, required_role
                        )

                    if required_role:
                        track_rbac_decision(allowed=True, role=user.role.name, action=mutation_name)

            async def receive():
                return {"type": "http.request", "body": body}

            request = Request(request.scope, receive=receive)

        # REST RBAC
        elif method in self.WRITE_METHODS and not user.can(Role.EDITOR):
            self._log_denied(user, f"REST_{method}_{path}", Role.EDITOR)
            return self._forbidden_html_response(user, path, method, "REQUIRES_EDITOR")

        request.state.user = user
        response = await call_next(request)
        return SecurityHardening.set_security_headers(response)

    def _get_user_from_proxy(self, request: Request) -> Optional[AuthUser]:
        """
        Extrai user dos headers do Authelia (modo proxy).
        """
        if not self.proxy_backend:
            return None

        # Converte Starlette headers pra dict
        headers_dict = dict(request.headers)

        # Usa o backend proxy pra parsear
        user = self.proxy_backend.get_user_from_headers(headers_dict)

        if user:
            logger.debug(f"✅ Proxy auth: {user.username} ({user.role.name})")
        else:
            logger.warning("❌ Proxy auth: Failed to extract user from headers")

        return user

    # Helper Methods
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
        html = render_403_page(user, path, method, reason)
        return Response(content=html, status_code=403, media_type="text/html")
