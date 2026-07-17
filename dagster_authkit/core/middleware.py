"""
Authentication Middleware — Pure ASGI (not BaseHTTPMiddleware).

Why pure ASGI:

- BaseHTTPMiddleware only handles scope["type"] == "http", so WebSocket
  connections (Dagster GraphQL subscriptions at /graphql) bypass auth entirely.

- Pure ASGI intercepts both HTTP and WebSocket scopes.

- Also solves the CORS ordering problem: as a pure ASGI middleware we sit at the
  right layer regardless of insert position.
"""

import json
import logging
from typing import Optional

from starlette.datastructures import State
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.types import ASGIApp, Receive, Scope, Send

from dagster_authkit.api.health import health_endpoint, metrics_endpoint, track_rbac_decision
from dagster_authkit.auth.backends.base import Role, AuthUser, RolePermissions
from dagster_authkit.auth.security import SecurityHardening
from dagster_authkit.auth.session import sessions
from dagster_authkit.core.graphql_analyzer import GraphQLMutationAnalyzer, _SENTINEL_UNPARSEABLE
from dagster_authkit.core.registry import get_backend
from dagster_authkit.utils.audit import log_access_control
from dagster_authkit.utils.config import config
from dagster_authkit.utils.templates import render_403_page

logger = logging.getLogger(__name__)

_WS_CLOSE_UNAUTHORIZED = 4001


class DagsterAuthMiddleware:
    """
    Pure ASGI authentication middleware.

    Handles both HTTP and WebSocket connections. WebSocket GraphQL
    subscriptions at /graphql are authenticated via session cookie.
    """

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

    def __init__(self, app: ASGIApp):
        """
        Initialise the authentication middleware.

        Args:
            app: Inner ASGI application (the Dagster webserver).
        """
        self.app = app

        self.is_proxy_mode = config.AUTH_BACKEND == "proxy"

        if self.is_proxy_mode:
            self.proxy_backend = get_backend("proxy", config.__dict__)
            logger.info("Middleware: PROXY MODE enabled (Authelia forward auth)")
        else:
            self.proxy_backend = None
            logger.info(f"Middleware: SESSION MODE (backend={config.AUTH_BACKEND})")

        self._unknown_mutation_role = Role[config.DAGSTER_AUTH_UNKNOWN_MUTATION_ROLE]

        # Minimum role for non-GraphQL write requests (POST/PUT/DELETE/PATCH).
        # Defaults to EDITOR since REST writes are typically administrative.
        # GraphQL mutations use their own per-mutation RBAC via RolePermissions.
        self._rest_write_role = Role[getattr(config, "DAGSTER_AUTH_REST_WRITE_ROLE", "EDITOR")]

    # ================================================================
    # ASGI entry point
    # ================================================================

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """
        ASGI entry point. Routes HTTP and WebSocket connections to the
        appropriate handler.

        Args:
            scope:   ASGI connection scope.
            receive: ASGI receive callable.
            send:    ASGI send callable.
        """
        if scope["type"] == "websocket":
            await self._handle_websocket(scope, receive, send)
        elif scope["type"] == "http":
            await self._handle_http(scope, receive, send)
        else:
            await self.app(scope, receive, send)

    # ================================================================
    # WebSocket handling
    # ================================================================

    async def _handle_websocket(self, scope: Scope, receive: Receive, send: Send) -> None:
        path = scope.get("path", "/")

        if self._is_public_path(path):
            await self.app(scope, receive, send)
            return

        if self.is_proxy_mode:
            user = self._get_user_from_ws_scope(scope)
        else:
            user = self._get_authenticated_user_from_scope(scope)

        if not user:
            logger.warning(f"WebSocket auth failed for {path}")
            await send(
                {
                    "type": "websocket.close",
                    "code": _WS_CLOSE_UNAUTHORIZED,
                    "reason": "Unauthorized",
                }
            )
            return

        logger.debug(f"WebSocket authenticated: {user.username} on {path}")
        await self.app(scope, receive, send)

    # ================================================================
    # HTTP handling
    # ================================================================

    async def _handle_http(self, scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive)
        path = request.url.path
        method = request.method

        if method == "OPTIONS":
            await self.app(scope, receive, send)
            return

        if path == "/auth/health":
            response = await health_endpoint(request)
            await response(scope, receive, send)
            return

        if path == "/auth/metrics":
            response = await metrics_endpoint(request)
            await response(scope, receive, send)
            return

        if self.is_proxy_mode and path in ["/auth/login", "/auth/process"]:
            response = Response(
                content="This endpoint is disabled in proxy auth mode. "
                "Authentication is handled by Authelia.",
                status_code=404,
            )
            await response(scope, receive, send)
            return

        if self._is_public_path(path) and not self.is_proxy_mode:
            await self._passthrough(scope, receive, send)
            return

        # --- Authentication ---
        if self.is_proxy_mode:
            if not self._is_request_from_trusted_proxy(request):
                response = Response(
                    content="Unauthorized: Request did not come from a trusted proxy",
                    status_code=403,
                )
                await response(scope, receive, send)
                return

            user = self._get_user_from_proxy(request)
            if not user:
                response = Response(
                    content="Unauthorized: Missing authentication headers from proxy",
                    status_code=401,
                )
                await response(scope, receive, send)
                return
        else:
            user = self._get_authenticated_user(request)
            if not user:
                if (
                    path == "/graphql"
                    or request.headers.get("x-requested-with") == "XMLHttpRequest"
                ):
                    response = Response(content="Unauthorized", status_code=401)
                else:
                    response = RedirectResponse(url=f"/auth/login?next={path}", status_code=302)
                await response(scope, receive, send)
                return

        # --- RBAC: GraphQL HTTP mutations ---
        downstream_receive = receive

        if path == "/graphql" and method == "POST":
            body = await request.body()
            graphql_data = self._parse_json(body)
            queries = self._normalize_graphql_items(graphql_data)

            for g_item in queries:
                query_str = g_item.get("query", "")
                operation_name = g_item.get("operationName") or None

                # Single parse: extract_mutation_names returns sentinel for invalid queries
                mutation_names = GraphQLMutationAnalyzer.extract_mutation_names(
                    query_str, operation_name=operation_name
                )

                if _SENTINEL_UNPARSEABLE in mutation_names:
                    logger.warning(f"Rejected unparseable GraphQL query from {user.username}")
                    response = Response(
                        content='{"errors":[{"message":"Invalid GraphQL query"}]}',
                        status_code=400,
                        media_type="application/json",
                    )
                    await response(scope, receive, send)
                    return

                if not mutation_names:
                    continue

                for mutation_name in mutation_names:
                    required_role = RolePermissions.get_required_role(
                        mutation_name,
                        default_role=self._unknown_mutation_role,
                    )

                    if required_role and not user.can(required_role):
                        self._log_denied(user, mutation_name, required_role)
                        track_rbac_decision(False, user.role.name, mutation_name)
                        response = self._generate_dagster_error_response(
                            user, mutation_name, required_role
                        )
                        await response(scope, receive, send)
                        return

                    if required_role:
                        track_rbac_decision(True, user.role.name, mutation_name)

            # Rebuild receive with consumed body so downstream can read it
            async def _receive():
                return {"type": "http.request", "body": body, "more_body": False}

            downstream_receive = _receive

        elif method in self.WRITE_METHODS and not user.can(self._rest_write_role):
            self._log_denied(
                user,
                f"REST {method} {path}",
                self._rest_write_role,
                method=method,
                path=path,
            )
            response = self._forbidden_html_response(
                user, path, method, f"REQUIRES_{self._rest_write_role.name}"
            )
            await response(scope, receive, send)
            return

        # Store user in scope for downstream handlers (e.g., UI injection).
        # Use a Starlette State object (not a plain dict) so that attribute
        # access via request.state.user works correctly in Starlette 1.3.1+,
        # where request.state returns scope["state"] directly.
        scope = dict(scope)
        existing_state = scope.get("state")
        if not isinstance(existing_state, State):
            new_state = State()
            if isinstance(existing_state, dict):
                for k, v in existing_state.items():
                    setattr(new_state, k, v)
            scope["state"] = new_state
        scope["state"].user = user

        await self._passthrough(scope, downstream_receive, send)

    async def _passthrough(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Pass the request to the inner app, injecting security headers on the response."""

        async def _send(message):
            if message["type"] == "http.response.start":
                headers = dict(
                    (k.decode("latin-1"), v.decode("latin-1"))
                    for k, v in message.get("headers", [])
                )
                headers.update(SecurityHardening.get_security_headers())
                message["headers"] = [
                    (k.encode("latin-1"), v.encode("latin-1")) for k, v in headers.items()
                ]
            await send(message)

        await self.app(scope, receive, _send)

    # ================================================================
    # User extraction (HTTP)
    # ================================================================

    def _get_user_from_proxy(self, request: Request) -> Optional[AuthUser]:
        if not self.proxy_backend:
            return None
        headers_dict = dict(request.headers)
        user = self.proxy_backend.get_user_from_headers(headers_dict)
        if user:
            logger.debug(f"Proxy auth: {user.username} ({user.role.name})")
        else:
            logger.warning("Proxy auth: Failed to extract user from headers")
        return user

    def _get_authenticated_user(self, request: Request) -> Optional[AuthUser]:
        token = request.cookies.get(config.SESSION_COOKIE_NAME)
        if not token:
            return None
        user_data = sessions.validate(token)
        if not user_data:
            return None
        try:
            return AuthUser.from_dict(user_data)
        except Exception as e:
            logger.error(f"User deserialization failed: {e}")
            return None

    # ================================================================
    # User extraction (WebSocket scope)
    # ================================================================

    def _get_user_from_ws_scope(self, scope: Scope) -> Optional[AuthUser]:
        if not self.proxy_backend:
            return None
        headers = self._scope_headers_to_dict(scope)
        return self.proxy_backend.get_user_from_headers(headers)

    def _get_authenticated_user_from_scope(self, scope: Scope) -> Optional[AuthUser]:
        headers = self._scope_headers_to_dict(scope)
        cookie_header = headers.get("cookie", "")
        if not cookie_header:
            return None
        cookies = self._parse_cookie_header(cookie_header)
        token = cookies.get(config.SESSION_COOKIE_NAME)
        if not token:
            return None
        user_data = sessions.validate(token)
        if not user_data:
            return None
        try:
            return AuthUser.from_dict(user_data)
        except Exception as e:
            logger.error(f"User deserialization failed: {e}")
            return None

    @staticmethod
    def _scope_headers_to_dict(scope: Scope) -> dict[str, str]:
        result = {}
        for key, value in scope.get("headers", []):
            result[key.decode("latin-1").lower()] = value.decode("latin-1")
        return result

    @staticmethod
    def _parse_cookie_header(header: str) -> dict[str, str]:
        cookies = {}
        for item in header.split(";"):
            item = item.strip()
            if "=" in item:
                key, _, value = item.partition("=")
                cookies[key.strip()] = value.strip()
        return cookies

    # ================================================================
    # Shared helpers
    # ================================================================

    def _is_public_path(self, path: str) -> bool:
        return path in self.PUBLIC_PATHS or any(path.startswith(p) for p in self.PUBLIC_PREFIXES)

    def _is_request_from_trusted_proxy(self, request: Request) -> bool:
        trusted = config.DAGSTER_AUTH_PROXY_TRUSTED_IPS
        if not trusted:
            # No IPs configured -- config validation prevents this unless
            # TRUST_ALL is explicitly set (opt-in to the insecure default).
            return config.DAGSTER_AUTH_PROXY_TRUST_ALL
        client_ip = request.client.host if request.client else None
        if client_ip is None:
            logger.warning("Cannot determine client IP for proxy trust check")
            return False
        is_trusted = client_ip in trusted
        if not is_trusted:
            logger.warning(
                f"Rejected proxy auth from untrusted IP: {client_ip} "
                f"(trusted: {sorted(trusted)})"
            )
        return is_trusted

    @staticmethod
    def _log_denied(user, action, role, method="POST", path="/graphql"):
        logger.warning(f"RBAC DENIED: {user.username} (role: {user.role.name}) tried {action}")
        log_access_control(
            user.username, method, path, False, [user.role.name], f"REQUIRES_{role.name}"
        )

    @staticmethod
    def _parse_json(body: bytes) -> dict:
        try:
            return json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}

    @staticmethod
    def _normalize_graphql_items(data) -> list[dict]:
        """Ensure each GraphQL request item is a dict. Rejects non-dict payloads."""
        items = data if isinstance(data, list) else [data]
        result = []
        for item in items:
            if not isinstance(item, dict):
                logger.warning(f"Rejected non-dict GraphQL payload item: {type(item)}")
                return []
            result.append(item)
        return result

    @staticmethod
    def _generate_dagster_error_response(user, mutation, role) -> Response:
        payload = {
            "data": {
                mutation: {
                    "__typename": "PythonError",
                    "message": f"Access Denied: {role.name} role required",
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
