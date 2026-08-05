"""
Unit tests for dagster_authkit/core/middleware.py

Covers:
- WebSocket authentication (public path, failure, success)
- HTTP routing (health, metrics, public paths, auth redirect, API 401)
- GraphQL RBAC (mutation allowed, denied, unparseable, invalid batch)
- REST write RBAC (allowed, denied)
- Proxy mode (disabled endpoints, trusted proxy, untrusted proxy)
- Helper methods (_parse_json, _normalize_graphql_items, etc.)
- Security headers injection via _inject_headers_send
- _passthrough with track_request_duration
"""

import json
from unittest.mock import MagicMock, patch

import pytest

from dagster_authkit.auth.backends.base import AuthUser, Role
from dagster_authkit.auth.security import SecurityHardening
from dagster_authkit.core.graphql_analyzer import GraphQLMutationAnalyzer, _SENTINEL_UNPARSEABLE
from dagster_authkit.core.middleware import DagsterAuthMiddleware
from dagster_authkit.utils.config import config


def _get_header_dict(headers):
    return {
        k.decode("latin-1"): v.decode("latin-1")
        for k, v in (headers or [])
    }


# ---------------------------------------------------------------------------
# WebSocket Authentication
# ---------------------------------------------------------------------------


class TestWebSocket:
    """WebSocket authentication via _handle_websocket."""

    @pytest.mark.asyncio
    async def test_public_path_passthrough(self):
        """Public /auth/ paths should pass through without authentication."""
        from dagster_authkit.core.middleware import DagsterAuthMiddleware

        app_called = False

        async def mock_app(scope, receive, send):
            nonlocal app_called
            app_called = True

        middleware = DagsterAuthMiddleware(mock_app)

        scope = {
            "type": "websocket",
            "path": "/auth/login",
            "headers": [],
            "query_string": b"",
        }

        await middleware._handle_websocket(scope, None, None)
        assert app_called

    @pytest.mark.asyncio
    async def test_auth_failure_closes_connection(self):
        """Unauthenticated WS connections should receive close code 4001."""
        from dagster_authkit.core.middleware import DagsterAuthMiddleware

        app_called = False
        sent_message = None

        async def mock_app(scope, receive, send):
            nonlocal app_called
            app_called = True

        async def send_fn(message):
            nonlocal sent_message
            sent_message = message

        middleware = DagsterAuthMiddleware(mock_app)

        scope = {
            "type": "websocket",
            "path": "/graphql",
            "headers": [],
            "query_string": b"",
        }

        await middleware._handle_websocket(scope, None, send_fn)

        assert not app_called
        assert sent_message is not None
        assert sent_message["type"] == "websocket.close"
        assert sent_message["code"] == 4001

    @pytest.mark.asyncio
    async def test_auth_success_session_mode(self):
        """Authenticated WS connection should pass through."""
        from dagster_authkit.core.middleware import DagsterAuthMiddleware
        from dagster_authkit.auth.session import sessions

        app_called = False

        async def mock_app(scope, receive, send):
            nonlocal app_called
            app_called = True

        middleware = DagsterAuthMiddleware(mock_app)

        scope = {
            "type": "websocket",
            "path": "/graphql",
            "headers": [(b"cookie", b"dagster_session=valid-token")],
            "query_string": b"",
        }

        with patch.object(sessions, "validate", return_value={"username": "admin", "role": 40}):
            await middleware._handle_websocket(scope, None, None)

        assert app_called

    @pytest.mark.asyncio
    async def test_auth_success_proxy_mode(self):
        """Authenticated WS in proxy mode should pass through."""
        from dagster_authkit.core.middleware import DagsterAuthMiddleware

        app_called = False

        async def mock_app(scope, receive, send):
            nonlocal app_called
            app_called = True

        mock_backend = MagicMock()
        mock_backend.get_user_from_headers.return_value = AuthUser(
            username="john", role=Role.ADMIN, email="john@c.com"
        )

        with (
            patch.object(config, "AUTH_BACKEND", "proxy"),
            patch.object(config, "DAGSTER_AUTH_PROXY_TRUSTED_IPS", frozenset()),
            patch.object(config, "DAGSTER_AUTH_PROXY_TRUST_ALL", True),
            patch("dagster_authkit.core.middleware.get_backend", return_value=mock_backend),
        ):
            mw = DagsterAuthMiddleware(mock_app)

            scope = {
                "type": "websocket",
                "path": "/graphql",
                "headers": [(b"remote-user", b"john")],
                "query_string": b"",
            }

            await mw._handle_websocket(scope, None, None)

        assert app_called


# ---------------------------------------------------------------------------
# HTTP Routing
# ---------------------------------------------------------------------------


class TestHTTPRouting:
    """HTTP request routing decisions."""

    @pytest.mark.asyncio
    async def test_options_passthrough(self):
        """OPTIONS requests should pass through without any auth."""
        from dagster_authkit.core.middleware import DagsterAuthMiddleware

        app_called = False

        async def mock_app(scope, receive, send):
            nonlocal app_called
            app_called = True

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        middleware = DagsterAuthMiddleware(mock_app)

        scope = {
            "type": "http",
            "method": "OPTIONS",
            "path": "/graphql",
            "headers": [],
            "query_string": b"",
            "server": ("localhost", 3000),
            "client": ("127.0.0.1", 12345),
        }

        await middleware._handle_http(scope, receive, None)
        assert app_called

    @pytest.mark.asyncio
    async def test_health_endpoint_routed(self):
        """/auth/health should be handled by health_endpoint."""
        from starlette.responses import JSONResponse
        from dagster_authkit.core.middleware import DagsterAuthMiddleware

        health_called = False

        async def mock_health(request):
            nonlocal health_called
            health_called = True
            return JSONResponse({"status": "ok"})

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def noop_send(message):
            pass

        with patch("dagster_authkit.core.middleware.health_endpoint", mock_health):
            middleware = DagsterAuthMiddleware(MagicMock())

            scope = {
                "type": "http",
                "method": "GET",
                "path": "/auth/health",
                "headers": [],
                "query_string": b"",
                "server": ("localhost", 3000),
                "client": ("127.0.0.1", 12345),
            }

            await middleware._handle_http(scope, receive, noop_send)

        assert health_called

    @pytest.mark.asyncio
    async def test_metrics_endpoint_routed(self):
        """/auth/metrics should be handled by metrics_endpoint."""
        from starlette.responses import JSONResponse
        from dagster_authkit.core.middleware import DagsterAuthMiddleware

        metrics_called = False

        async def mock_metrics(request):
            nonlocal metrics_called
            metrics_called = True
            return JSONResponse({"counters": {}})

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def noop_send(message):
            pass

        with patch("dagster_authkit.core.middleware.metrics_endpoint", mock_metrics):
            middleware = DagsterAuthMiddleware(MagicMock())

            scope = {
                "type": "http",
                "method": "GET",
                "path": "/auth/metrics",
                "headers": [],
                "query_string": b"",
                "server": ("localhost", 3000),
                "client": ("127.0.0.1", 12345),
            }

            await middleware._handle_http(scope, receive, noop_send)

        assert metrics_called

    @pytest.mark.asyncio
    async def test_public_path_passthrough(self):
        """Public paths (/auth/login, /auth/logout, /auth/process) skip auth."""
        from dagster_authkit.core.middleware import DagsterAuthMiddleware

        for path in ("/auth/login", "/auth/logout", "/auth/process"):
            app_called = False

            async def mock_app(scope, receive, send):
                nonlocal app_called
                app_called = True

            async def receive():
                return {"type": "http.request", "body": b"", "more_body": False}

            middleware = DagsterAuthMiddleware(mock_app)

            scope = {
                "type": "http",
                "method": "GET",
                "path": path,
                "headers": [],
                "query_string": b"",
                "server": ("localhost", 3000),
                "client": ("127.0.0.1", 12345),
            }

            await middleware._handle_http(scope, receive, None)
            assert app_called, f"Expected passthrough for {path}"

    @pytest.mark.asyncio
    async def test_unauthenticated_graphql_returns_401(self):
        """Unauthenticated POST /graphql should return 401."""
        from dagster_authkit.core.middleware import DagsterAuthMiddleware

        sent_messages = []

        async def mock_app(scope, receive, send):
            pass

        async def send_fn(message):
            sent_messages.append(message)

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        middleware = DagsterAuthMiddleware(mock_app)

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/graphql",
            "headers": [],
            "query_string": b"",
            "server": ("localhost", 3000),
            "client": ("127.0.0.1", 12345),
        }

        await middleware._handle_http(scope, receive, send_fn)

        assert len(sent_messages) >= 1
        start_msg = sent_messages[0]
        assert start_msg["type"] == "http.response.start"
        assert start_msg["status"] == 401

    @pytest.mark.asyncio
    async def test_unauthenticated_xhr_returns_401(self):
        """Unauthenticated XMLHttpRequest should return 401."""
        from dagster_authkit.core.middleware import DagsterAuthMiddleware

        sent_messages = []

        async def mock_app(scope, receive, send):
            pass

        async def send_fn(message):
            sent_messages.append(message)

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        middleware = DagsterAuthMiddleware(mock_app)

        scope = {
            "type": "http",
            "method": "GET",
            "path": "/some/api",
            "headers": [(b"x-requested-with", b"XMLHttpRequest")],
            "query_string": b"",
            "server": ("localhost", 3000),
            "client": ("127.0.0.1", 12345),
        }

        await middleware._handle_http(scope, receive, send_fn)

        assert len(sent_messages) >= 1
        start_msg = sent_messages[0]
        assert start_msg["status"] == 401

    @pytest.mark.asyncio
    async def test_unauthenticated_html_redirects_to_login(self):
        """Unauthenticated regular requests should redirect to /auth/login."""
        from dagster_authkit.core.middleware import DagsterAuthMiddleware

        sent_messages = []

        async def mock_app(scope, receive, send):
            pass

        async def send_fn(message):
            sent_messages.append(message)

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        middleware = DagsterAuthMiddleware(mock_app)

        scope = {
            "type": "http",
            "method": "GET",
            "path": "/some/page",
            "headers": [],
            "query_string": b"",
            "server": ("localhost", 3000),
            "client": ("127.0.0.1", 12345),
        }

        await middleware._handle_http(scope, receive, send_fn)

        assert len(sent_messages) >= 1
        start_msg = sent_messages[0]
        assert start_msg["status"] == 302

    @pytest.mark.asyncio
    async def test_authenticated_user_stored_in_scope(self):
        """Authenticated user should be stored in scope state."""
        from dagster_authkit.core.middleware import DagsterAuthMiddleware
        from dagster_authkit.auth.session import sessions
        from starlette.datastructures import State

        captured_scope = None

        async def mock_app(scope, receive, send):
            nonlocal captured_scope
            captured_scope = scope

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        middleware = DagsterAuthMiddleware(mock_app)

        scope = {
            "type": "http",
            "method": "GET",
            "path": "/workspace",
            "headers": [(b"cookie", b"dagster_session=valid-token")],
            "query_string": b"",
            "server": ("localhost", 3000),
            "client": ("127.0.0.1", 12345),
        }

        with patch.object(sessions, "validate", return_value={"username": "admin", "role": 40}):
            await middleware._handle_http(scope, receive, None)

        assert captured_scope is not None
        state = captured_scope["state"]
        assert isinstance(state, State)
        assert state.user.username == "admin"
        assert state.user.role == Role.ADMIN

    @pytest.mark.asyncio
    async def test_preserves_existing_scope_state(self):
        """Existing scope state dict should be merged into the State object."""
        from dagster_authkit.core.middleware import DagsterAuthMiddleware
        from dagster_authkit.auth.session import sessions
        from starlette.datastructures import State

        captured_scope = None

        async def mock_app(scope, receive, send):
            nonlocal captured_scope
            captured_scope = scope

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        middleware = DagsterAuthMiddleware(mock_app)

        scope = {
            "type": "http",
            "method": "GET",
            "path": "/workspace",
            "headers": [(b"cookie", b"dagster_session=valid-token")],
            "query_string": b"",
            "server": ("localhost", 3000),
            "client": ("127.0.0.1", 12345),
            "state": {"existing_key": "existing_value"},
        }

        with patch.object(sessions, "validate", return_value={"username": "admin", "role": 40}):
            await middleware._handle_http(scope, receive, None)

        assert captured_scope is not None
        state = captured_scope["state"]
        assert isinstance(state, State)
        assert state.existing_key == "existing_value"
        assert state.user.username == "admin"


# ---------------------------------------------------------------------------
# GraphQL RBAC
# ---------------------------------------------------------------------------


class TestGraphQLRBAC:
    """GraphQL mutation RBAC enforcement."""

    @pytest.mark.asyncio
    async def test_allowed_mutation_passes(self):
        """Mutations allowed by user's role should pass through."""
        from dagster_authkit.core.middleware import DagsterAuthMiddleware
        from dagster_authkit.auth.session import sessions

        app_called = False

        async def mock_app(scope, receive, send):
            nonlocal app_called
            app_called = True

        body = json.dumps({"query": "mutation { logTelemetry(input: {}) }"}).encode("utf-8")

        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}

        middleware = DagsterAuthMiddleware(mock_app)

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/graphql",
            "headers": [(b"cookie", b"dagster_session=valid-token")],
            "query_string": b"",
            "server": ("localhost", 3000),
            "client": ("127.0.0.1", 12345),
        }

        with (
            patch.object(sessions, "validate", return_value={"username": "viewer", "role": 10}),
            patch.object(
                GraphQLMutationAnalyzer,
                "extract_mutation_names",
                return_value={"logTelemetry"},
            ),
        ):
            await middleware._handle_http(scope, receive, None)

        assert app_called

    @pytest.mark.asyncio
    async def test_denied_mutation_blocked(self):
        """Mutations denied by user's role should return error response."""
        from dagster_authkit.core.middleware import DagsterAuthMiddleware
        from dagster_authkit.auth.session import sessions

        app_called = False

        async def mock_app(scope, receive, send):
            nonlocal app_called
            app_called = True

        sent_messages = []

        async def send_fn(message):
            sent_messages.append(message)

        body = json.dumps({"query": "mutation { launchPipelineExecution(input: {}) }"}).encode(
            "utf-8"
        )

        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}

        middleware = DagsterAuthMiddleware(mock_app)

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/graphql",
            "headers": [(b"cookie", b"dagster_session=valid-token")],
            "query_string": b"",
            "server": ("localhost", 3000),
            "client": ("127.0.0.1", 12345),
        }

        with (
            patch.object(sessions, "validate", return_value={"username": "viewer", "role": 10}),
            patch.object(
                GraphQLMutationAnalyzer,
                "extract_mutation_names",
                return_value={"launchPipelineExecution"},
            ),
        ):
            await middleware._handle_http(scope, receive, send_fn)

        assert not app_called
        assert len(sent_messages) >= 1
        assert sent_messages[0]["status"] == 200

    @pytest.mark.asyncio
    async def test_unparseable_query_blocked(self):
        """Unparseable GraphQL queries should return 400."""
        from dagster_authkit.core.middleware import DagsterAuthMiddleware
        from dagster_authkit.auth.session import sessions

        app_called = False

        async def mock_app(scope, receive, send):
            nonlocal app_called
            app_called = True

        sent_messages = []

        async def send_fn(message):
            sent_messages.append(message)

        body = json.dumps({"query": "mutation { invalid }"}).encode("utf-8")

        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}

        middleware = DagsterAuthMiddleware(mock_app)

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/graphql",
            "headers": [(b"cookie", b"dagster_session=valid-token")],
            "query_string": b"",
            "server": ("localhost", 3000),
            "client": ("127.0.0.1", 12345),
        }

        with (
            patch.object(sessions, "validate", return_value={"username": "admin", "role": 40}),
            patch.object(
                GraphQLMutationAnalyzer,
                "extract_mutation_names",
                return_value={_SENTINEL_UNPARSEABLE},
            ),
        ):
            await middleware._handle_http(scope, receive, send_fn)

        assert not app_called
        assert sent_messages[0]["status"] == 400

    @pytest.mark.asyncio
    async def test_empty_batch_passthrough(self):
        """Query with no mutations should pass through."""
        from dagster_authkit.core.middleware import DagsterAuthMiddleware
        from dagster_authkit.auth.session import sessions

        app_called = False

        async def mock_app(scope, receive, send):
            nonlocal app_called
            app_called = True

        body = json.dumps({"query": "{ pipelines { name } }"}).encode("utf-8")

        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}

        middleware = DagsterAuthMiddleware(mock_app)

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/graphql",
            "headers": [(b"cookie", b"dagster_session=valid-token")],
            "query_string": b"",
            "server": ("localhost", 3000),
            "client": ("127.0.0.1", 12345),
        }

        with (
            patch.object(sessions, "validate", return_value={"username": "viewer", "role": 10}),
            patch.object(GraphQLMutationAnalyzer, "extract_mutation_names", return_value=set()),
        ):
            await middleware._handle_http(scope, receive, None)

        assert app_called

    @pytest.mark.asyncio
    async def test_invalid_batch_returns_400(self):
        """Non-dict GraphQL batch item should return 400."""
        from dagster_authkit.core.middleware import DagsterAuthMiddleware
        from dagster_authkit.auth.session import sessions

        app_called = False
        sent_messages = []

        async def mock_app(scope, receive, send):
            nonlocal app_called
            app_called = True

        async def send_fn(message):
            sent_messages.append(message)

        body = json.dumps([{"query": "mutation { a }"}, 42]).encode("utf-8")

        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}

        middleware = DagsterAuthMiddleware(mock_app)

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/graphql",
            "headers": [(b"cookie", b"dagster_session=valid-token")],
            "query_string": b"",
            "server": ("localhost", 3000),
            "client": ("127.0.0.1", 12345),
        }

        with patch.object(sessions, "validate", return_value={"username": "viewer", "role": 10}):
            await middleware._handle_http(scope, receive, send_fn)

        assert not app_called
        assert sent_messages[0]["status"] == 400


# ---------------------------------------------------------------------------
# REST RBAC
# ---------------------------------------------------------------------------


class TestRESTRBAC:
    """REST write RBAC enforcement."""

    @pytest.mark.asyncio
    async def test_viewer_write_blocked(self):
        """VIEWER should be blocked from POST/PUT/DELETE/PATCH to non-GraphQL paths."""
        from dagster_authkit.core.middleware import DagsterAuthMiddleware
        from dagster_authkit.auth.session import sessions

        for method in ("POST", "PUT", "DELETE", "PATCH"):
            app_called = False
            sent_messages = []

            async def mock_app(scope, receive, send):
                nonlocal app_called
                app_called = True

            async def send_fn(message):
                sent_messages.append(message)

            async def receive():
                return {"type": "http.request", "body": b"", "more_body": False}

            middleware = DagsterAuthMiddleware(mock_app)

            scope = {
                "type": "http",
                "method": method,
                "path": "/some/api",
                "headers": [(b"cookie", b"dagster_session=valid-token")],
                "query_string": b"",
                "server": ("localhost", 3000),
                "client": ("127.0.0.1", 12345),
            }

            with patch.object(
                sessions, "validate", return_value={"username": "viewer", "role": 10}
            ):
                await middleware._handle_http(scope, receive, send_fn)

            assert not app_called, f"Expected VIEWER blocked for {method}"
            assert sent_messages[0]["status"] == 403, f"Expected 403 for {method}"

    @pytest.mark.asyncio
    async def test_editor_post_allowed(self):
        """EDITOR should be allowed to POST to non-GraphQL paths."""
        from dagster_authkit.core.middleware import DagsterAuthMiddleware
        from dagster_authkit.auth.session import sessions

        app_called = False

        async def mock_app(scope, receive, send):
            nonlocal app_called
            app_called = True

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        middleware = DagsterAuthMiddleware(mock_app)

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/some/api",
            "headers": [(b"cookie", b"dagster_session=valid-token")],
            "query_string": b"",
            "server": ("localhost", 3000),
            "client": ("127.0.0.1", 12345),
        }

        with patch.object(sessions, "validate", return_value={"username": "editor", "role": 30}):
            await middleware._handle_http(scope, receive, None)

        assert app_called

    @pytest.mark.asyncio
    async def test_launcher_post_blocked(self):
        """LAUNCHER should be blocked from POST to non-GraphQL paths."""
        from dagster_authkit.core.middleware import DagsterAuthMiddleware
        from dagster_authkit.auth.session import sessions

        sent_messages = []

        async def mock_app(scope, receive, send):
            pass

        async def send_fn(message):
            sent_messages.append(message)

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        middleware = DagsterAuthMiddleware(mock_app)

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/some/api",
            "headers": [(b"cookie", b"dagster_session=valid-token")],
            "query_string": b"",
            "server": ("localhost", 3000),
            "client": ("127.0.0.1", 12345),
        }

        with patch.object(sessions, "validate", return_value={"username": "launcher", "role": 20}):
            await middleware._handle_http(scope, receive, send_fn)

        assert sent_messages[0]["status"] == 403


# ---------------------------------------------------------------------------
# Proxy Mode
# ---------------------------------------------------------------------------


class TestProxyMode:
    """Proxy authentication mode."""

    @pytest.fixture
    def proxy_backend(self):
        mock_backend = MagicMock()
        mock_backend.get_user_from_headers.return_value = AuthUser(
            username="john",
            role=Role.ADMIN,
            email="john@c.com",
        )
        return mock_backend

    @pytest.mark.asyncio
    async def test_login_endpoint_disabled(self, proxy_backend):
        """GET /auth/login should return 404 in proxy mode."""
        from dagster_authkit.core.middleware import DagsterAuthMiddleware

        sent_messages = []

        async def mock_app(scope, receive, send):
            pass

        async def send_fn(message):
            sent_messages.append(message)

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        with (
            patch.object(config, "AUTH_BACKEND", "proxy"),
            patch.object(config, "DAGSTER_AUTH_PROXY_TRUSTED_IPS", frozenset({"10.0.0.1"})),
            patch.object(config, "DAGSTER_AUTH_PROXY_TRUST_ALL", False),
            patch("dagster_authkit.core.middleware.get_backend", return_value=proxy_backend),
        ):
            mw = DagsterAuthMiddleware(mock_app)

            scope = {
                "type": "http",
                "method": "GET",
                "path": "/auth/login",
                "headers": [],
                "query_string": b"",
                "server": ("localhost", 3000),
                "client": ("127.0.0.1", 12345),
            }

            await mw._handle_http(scope, receive, send_fn)

        assert sent_messages[0]["status"] == 404

    @pytest.mark.asyncio
    async def test_process_endpoint_disabled(self, proxy_backend):
        """POST /auth/process should return 404 in proxy mode."""
        from dagster_authkit.core.middleware import DagsterAuthMiddleware

        sent_messages = []

        async def mock_app(scope, receive, send):
            pass

        async def send_fn(message):
            sent_messages.append(message)

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        with (
            patch.object(config, "AUTH_BACKEND", "proxy"),
            patch.object(config, "DAGSTER_AUTH_PROXY_TRUSTED_IPS", frozenset({"10.0.0.1"})),
            patch.object(config, "DAGSTER_AUTH_PROXY_TRUST_ALL", False),
            patch("dagster_authkit.core.middleware.get_backend", return_value=proxy_backend),
        ):
            mw = DagsterAuthMiddleware(mock_app)

            scope = {
                "type": "http",
                "method": "POST",
                "path": "/auth/process",
                "headers": [],
                "query_string": b"",
                "server": ("localhost", 3000),
                "client": ("127.0.0.1", 12345),
            }

            await mw._handle_http(scope, receive, send_fn)

        assert sent_messages[0]["status"] == 404

    @pytest.mark.asyncio
    async def test_trusted_proxy_with_headers(self, proxy_backend):
        """Request from trusted proxy with valid headers should pass through."""
        from dagster_authkit.core.middleware import DagsterAuthMiddleware

        app_called = False

        async def mock_app(scope, receive, send):
            nonlocal app_called
            app_called = True

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        with (
            patch.object(config, "AUTH_BACKEND", "proxy"),
            patch.object(config, "DAGSTER_AUTH_PROXY_TRUSTED_IPS", frozenset({"10.0.0.1"})),
            patch.object(config, "DAGSTER_AUTH_PROXY_TRUST_ALL", False),
            patch("dagster_authkit.core.middleware.get_backend", return_value=proxy_backend),
        ):
            mw = DagsterAuthMiddleware(mock_app)

            scope = {
                "type": "http",
                "method": "GET",
                "path": "/workspace",
                "headers": [(b"remote-user", b"john")],
                "query_string": b"",
                "server": ("localhost", 3000),
                "client": ("10.0.0.1", 12345),
            }

            await mw._handle_http(scope, receive, None)

        assert app_called

    @pytest.mark.asyncio
    async def test_untrusted_proxy_returns_403(self, proxy_backend):
        """Request from untrusted IP should return 403."""
        from dagster_authkit.core.middleware import DagsterAuthMiddleware

        sent_messages = []

        async def mock_app(scope, receive, send):
            pass

        async def send_fn(message):
            sent_messages.append(message)

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        with (
            patch.object(config, "AUTH_BACKEND", "proxy"),
            patch.object(config, "DAGSTER_AUTH_PROXY_TRUSTED_IPS", frozenset({"10.0.0.1"})),
            patch.object(config, "DAGSTER_AUTH_PROXY_TRUST_ALL", False),
            patch("dagster_authkit.core.middleware.get_backend", return_value=proxy_backend),
        ):
            mw = DagsterAuthMiddleware(mock_app)

            scope = {
                "type": "http",
                "method": "GET",
                "path": "/workspace",
                "headers": [(b"remote-user", b"john")],
                "query_string": b"",
                "server": ("localhost", 3000),
                "client": ("10.0.0.2", 12345),
            }

            await mw._handle_http(scope, receive, send_fn)

        assert sent_messages[0]["status"] == 403

    @pytest.mark.asyncio
    async def test_proxy_missing_headers_returns_401(self, proxy_backend):
        """Request from trusted proxy without auth headers should return 401."""
        from dagster_authkit.core.middleware import DagsterAuthMiddleware

        proxy_backend.get_user_from_headers.return_value = None
        sent_messages = []

        async def mock_app(scope, receive, send):
            pass

        async def send_fn(message):
            sent_messages.append(message)

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        with (
            patch.object(config, "AUTH_BACKEND", "proxy"),
            patch.object(config, "DAGSTER_AUTH_PROXY_TRUSTED_IPS", frozenset({"10.0.0.1"})),
            patch.object(config, "DAGSTER_AUTH_PROXY_TRUST_ALL", False),
            patch("dagster_authkit.core.middleware.get_backend", return_value=proxy_backend),
        ):
            mw = DagsterAuthMiddleware(mock_app)

            scope = {
                "type": "http",
                "method": "GET",
                "path": "/workspace",
                "headers": [],
                "query_string": b"",
                "server": ("localhost", 3000),
                "client": ("10.0.0.1", 12345),
            }

            await mw._handle_http(scope, receive, send_fn)

        assert sent_messages[0]["status"] == 401

    @pytest.mark.asyncio
    async def test_proxy_trust_all_bypasses_ip_check(self, proxy_backend):
        """TRUST_ALL=true should skip IP check."""
        from dagster_authkit.core.middleware import DagsterAuthMiddleware

        app_called = False

        async def mock_app(scope, receive, send):
            nonlocal app_called
            app_called = True

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        with (
            patch.object(config, "AUTH_BACKEND", "proxy"),
            patch.object(config, "DAGSTER_AUTH_PROXY_TRUSTED_IPS", frozenset()),
            patch.object(config, "DAGSTER_AUTH_PROXY_TRUST_ALL", True),
            patch("dagster_authkit.core.middleware.get_backend", return_value=proxy_backend),
        ):
            mw = DagsterAuthMiddleware(mock_app)

            scope = {
                "type": "http",
                "method": "GET",
                "path": "/workspace",
                "headers": [(b"remote-user", b"john")],
                "query_string": b"",
                "server": ("localhost", 3000),
                "client": ("192.168.1.1", 12345),
            }

            await mw._handle_http(scope, receive, None)

        assert app_called


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class TestHelpers:
    """Helper method unit tests."""

    def test_is_public_path(self):
        from dagster_authkit.core.middleware import DagsterAuthMiddleware

        mw = DagsterAuthMiddleware(MagicMock())
        assert mw._is_public_path("/auth/login") is True
        assert mw._is_public_path("/auth/health") is True
        assert mw._is_public_path("/auth/metrics") is True
        assert mw._is_public_path("/auth/some-random") is True
        assert mw._is_public_path("/static/main.js") is True
        assert mw._is_public_path("/graphql") is False
        assert mw._is_public_path("/workspace") is False
        assert mw._is_public_path("/") is False

    def test_parse_json_valid(self):
        mw = DagsterAuthMiddleware(MagicMock())
        result = mw._parse_json(b'{"key": "value"}')
        assert result == {"key": "value"}

    def test_parse_json_invalid(self):
        mw = DagsterAuthMiddleware(MagicMock())
        result = mw._parse_json(b"not json")
        assert result == {}

    def test_parse_json_utf8_error(self):
        mw = DagsterAuthMiddleware(MagicMock())
        result = mw._parse_json(b"\xff\xfe")
        assert result == {}

    def test_normalize_graphql_items_single_dict(self):
        mw = DagsterAuthMiddleware(MagicMock())
        result = mw._normalize_graphql_items({"query": "mutation { test }"})
        assert result == [{"query": "mutation { test }"}]

    def test_normalize_graphql_items_list(self):
        mw = DagsterAuthMiddleware(MagicMock())
        result = mw._normalize_graphql_items(
            [{"query": "mutation { a }"}, {"query": "mutation { b }"}]
        )
        assert len(result) == 2

    def test_normalize_graphql_items_non_dict_returns_empty(self):
        mw = DagsterAuthMiddleware(MagicMock())
        result = mw._normalize_graphql_items([42, "string"])
        assert result == []

    def test_scope_headers_to_dict(self):
        mw = DagsterAuthMiddleware(MagicMock())
        scope = {
            "headers": [
                (b"host", b"localhost"),
                (b"cookie", b"session=abc"),
                (b"x-custom", b"value"),
            ]
        }
        result = mw._scope_headers_to_dict(scope)
        assert result == {"host": "localhost", "cookie": "session=abc", "x-custom": "value"}

    def test_parse_cookie_header(self):
        mw = DagsterAuthMiddleware(MagicMock())
        result = mw._parse_cookie_header("session=abc; token=xyz; other=value")
        assert result == {"session": "abc", "token": "xyz", "other": "value"}

    def test_parse_cookie_header_empty(self):
        mw = DagsterAuthMiddleware(MagicMock())
        assert mw._parse_cookie_header("") == {}

    def test_parse_cookie_header_no_equals(self):
        mw = DagsterAuthMiddleware(MagicMock())
        assert mw._parse_cookie_header("justtext") == {}

    @pytest.mark.asyncio
    async def test_inject_headers_send(self):
        """_inject_headers_send should add security headers to responses."""
        captured = []

        async def mock_send(message):
            captured.append(message)

        wrapped_send = DagsterAuthMiddleware._inject_headers_send(mock_send)
        await wrapped_send({
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"text/html")],
        })

        headers = _get_header_dict(captured[0].get("headers", []))
        expected = SecurityHardening.get_security_headers()
        for key, value in expected.items():
            assert headers[key] == value

    def test_generate_dagster_error_response(self):
        mw = DagsterAuthMiddleware(MagicMock())
        user = AuthUser(username="viewer", role=Role.VIEWER)
        response = mw._generate_dagster_error_response(user, "launchPipeline", Role.EDITOR)
        assert response.status_code == 200
        data = json.loads(response.body)
        assert "errors" in data
        assert "Access Denied" in data["errors"][0]["message"]

    def test_generate_dagster_error_response_format(self):
        mw = DagsterAuthMiddleware(MagicMock())
        user = AuthUser(username="admin", role=Role.ADMIN)
        response = mw._generate_dagster_error_response(user, "deletePipeline", Role.ADMIN)
        body = json.loads(response.body)
        assert body["data"]["deletePipeline"]["__typename"] == "PythonError"
        assert body["data"]["deletePipeline"]["cls_name"] == "AccessControlError"

    def test_forbidden_html_response(self):
        mw = DagsterAuthMiddleware(MagicMock())
        user = AuthUser(username="viewer", role=Role.VIEWER, email="v@c.com")
        response = mw._forbidden_html_response(user, "/api", "POST", "REQUIRES_EDITOR")
        assert response.status_code == 403
        assert response.media_type == "text/html"

    def test_is_request_from_trusted_proxy_trusted(self):
        with patch.object(config, "DAGSTER_AUTH_PROXY_TRUSTED_IPS", frozenset({"10.0.0.1"})):
            mw = DagsterAuthMiddleware(MagicMock())
            request = MagicMock()
            request.client.host = "10.0.0.1"
            assert mw._is_request_from_trusted_proxy(request) is True

    def test_is_request_from_trusted_proxy_untrusted(self):
        with patch.object(config, "DAGSTER_AUTH_PROXY_TRUSTED_IPS", frozenset({"10.0.0.1"})):
            mw = DagsterAuthMiddleware(MagicMock())
            request = MagicMock()
            request.client.host = "10.0.0.2"
            assert mw._is_request_from_trusted_proxy(request) is False

    def test_is_request_from_trusted_proxy_no_client(self):
        with patch.object(config, "DAGSTER_AUTH_PROXY_TRUSTED_IPS", frozenset({"10.0.0.1"})):
            mw = DagsterAuthMiddleware(MagicMock())
            request = MagicMock()
            request.client = None
            assert mw._is_request_from_trusted_proxy(request) is False

    def test_is_request_from_trusted_proxy_trust_all(self):
        with patch.object(config, "DAGSTER_AUTH_PROXY_TRUSTED_IPS", frozenset()):
            mw = DagsterAuthMiddleware(MagicMock())
            request = MagicMock()
            request.client = None
            with patch.object(config, "DAGSTER_AUTH_PROXY_TRUST_ALL", True):
                assert mw._is_request_from_trusted_proxy(request) is True


# ---------------------------------------------------------------------------
# Tracking / Logging
# ---------------------------------------------------------------------------


class TestTracking:
    """Tracking and logging in middleware."""

    @pytest.mark.asyncio
    async def test_passthrough_tracks_duration(self):
        """_passthrough should call track_request_duration."""
        from dagster_authkit.core.middleware import DagsterAuthMiddleware

        app_called = False

        async def mock_app(scope, receive, send):
            nonlocal app_called
            app_called = True

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        middleware = DagsterAuthMiddleware(mock_app)

        scope = {
            "type": "http",
            "method": "GET",
            "path": "/workspace",
            "headers": [],
            "query_string": b"",
            "server": ("localhost", 3000),
            "client": ("127.0.0.1", 12345),
        }

        with patch("dagster_authkit.core.middleware.track_request_duration") as mock_track:
            await middleware._passthrough(scope, receive, None)

        assert app_called
        mock_track.assert_called_once()
        args = mock_track.call_args[0]
        assert args[0] == "/workspace"
        assert isinstance(args[1], float)

    @pytest.mark.asyncio
    async def test_rbac_allowed_tracks_decision(self):
        """Allowed mutations should call track_rbac_decision with True."""
        from dagster_authkit.core.middleware import DagsterAuthMiddleware
        from dagster_authkit.auth.session import sessions

        async def mock_app(scope, receive, send):
            pass

        body = json.dumps({"query": "mutation { launchPipelineExecution(input: {}) }"}).encode(
            "utf-8"
        )

        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}

        middleware = DagsterAuthMiddleware(mock_app)

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/graphql",
            "headers": [(b"cookie", b"dagster_session=valid-token")],
            "query_string": b"",
            "server": ("localhost", 3000),
            "client": ("127.0.0.1", 12345),
        }

        with (
            patch.object(sessions, "validate", return_value={"username": "admin", "role": 40}),
            patch.object(
                GraphQLMutationAnalyzer,
                "extract_mutation_names",
                return_value={"launchPipelineExecution"},
            ),
            patch("dagster_authkit.core.middleware.track_rbac_decision") as mock_track,
        ):
            await middleware._handle_http(scope, receive, None)

        mock_track.assert_called_once_with(True, "ADMIN")

    @pytest.mark.asyncio
    async def test_rbac_denied_tracks_decision(self):
        """Denied mutations should call track_rbac_decision with False."""
        from dagster_authkit.core.middleware import DagsterAuthMiddleware
        from dagster_authkit.auth.session import sessions
        from dagster_authkit.core.middleware import track_rbac_decision

        async def mock_app(scope, receive, send):
            pass

        sent_messages = []

        async def send_fn(message):
            sent_messages.append(message)

        body = json.dumps({"query": "mutation { launchPipelineExecution(input: {}) }"}).encode(
            "utf-8"
        )

        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}

        middleware = DagsterAuthMiddleware(mock_app)

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/graphql",
            "headers": [(b"cookie", b"dagster_session=valid-token")],
            "query_string": b"",
            "server": ("localhost", 3000),
            "client": ("127.0.0.1", 12345),
        }

        with (
            patch.object(sessions, "validate", return_value={"username": "viewer", "role": 10}),
            patch.object(
                GraphQLMutationAnalyzer,
                "extract_mutation_names",
                return_value={"launchPipelineExecution"},
            ),
            patch("dagster_authkit.core.middleware.track_rbac_decision") as mock_track,
        ):
            await middleware._handle_http(scope, receive, send_fn)

        mock_track.assert_called_once_with(False, "VIEWER")

    @pytest.mark.asyncio
    async def test_rest_denied_logs_access_control(self):
        """Denied REST writes should call log_access_control."""
        from dagster_authkit.core.middleware import DagsterAuthMiddleware
        from dagster_authkit.auth.session import sessions

        async def mock_app(scope, receive, send):
            pass

        sent_messages = []

        async def send_fn(message):
            sent_messages.append(message)

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        middleware = DagsterAuthMiddleware(mock_app)

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/some/api",
            "headers": [(b"cookie", b"dagster_session=valid-token")],
            "query_string": b"",
            "server": ("localhost", 3000),
            "client": ("127.0.0.1", 12345),
        }

        with (
            patch.object(sessions, "validate", return_value={"username": "viewer", "role": 10}),
            patch("dagster_authkit.core.middleware.log_access_control") as mock_log,
        ):
            await middleware._handle_http(scope, receive, send_fn)

        mock_log.assert_called_once()

    @pytest.mark.asyncio
    async def test_rest_denied_returns_html_forbidden(self):
        """Denied REST writes should return 403 with HTML body."""
        from dagster_authkit.core.middleware import DagsterAuthMiddleware
        from dagster_authkit.auth.session import sessions

        sent_messages = []

        async def mock_app(scope, receive, send):
            pass

        async def send_fn(message):
            sent_messages.append(message)

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        middleware = DagsterAuthMiddleware(mock_app)

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/some/api",
            "headers": [(b"cookie", b"dagster_session=valid-token")],
            "query_string": b"",
            "server": ("localhost", 3000),
            "client": ("127.0.0.1", 12345),
        }

        with patch.object(sessions, "validate", return_value={"username": "viewer", "role": 10}):
            await middleware._handle_http(scope, receive, send_fn)

        assert sent_messages[0]["status"] == 403
