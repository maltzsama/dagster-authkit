"""
Unit tests for dagster_authkit/core/patch.py

Covers the three UI injection bugs introduced in dagster-authkit 0.4.0/0.4.1
that affect Dagster 1.13.8 + Starlette 1.3.1:

  Bug 1 - Async wrapper: sync original + async _inject_resilient_ui returned an
           unawaited coroutine, causing HTTP 500 on all page loads.
  Bug 2 - User retrieval: middleware stores user as a plain dict key; getattr
           on a plain dict silently returns None, skipping the menu injection.
  Bug 3 - CSP nonce: Dagster's nonce-based CSP blocked the un-nonced injected
           <script> block, leaving the menu invisible despite being in the DOM.
"""

import asyncio
import json
import re
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.datastructures import State
from starlette.requests import Request
from starlette.responses import HTMLResponse

from dagster_authkit.auth.backends.base import AuthUser, Role

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_MINIMAL_HTML = (
    "<!DOCTYPE html><html><head></head>"
    "<body><div id='root'></div></body></html>"
)

_NONCE_HTML = (
    "<!DOCTYPE html><html><head>"
    '<script nonce="abc123">window.__dagster__={}</script>'
    "</head><body><div id='root'></div></body></html>"
)


def _make_scope(state=None) -> dict:
    """Return a minimal ASGI HTTP scope, optionally with a state value."""
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "query_string": b"",
        "headers": [],
        "server": ("localhost", 3000),
    }
    if state is not None:
        scope["state"] = state
    return scope


def _make_request(state=None, state_value=None) -> Request:
    """Build a Starlette Request with optional state attached to its scope."""
    scope = _make_scope()
    if state_value is not None:
        scope["state"] = state_value
    return Request(scope)


def _html_response(html: str) -> HTMLResponse:
    return HTMLResponse(content=html, status_code=200)


def _make_user() -> AuthUser:
    return AuthUser(
        username="alice",
        role=Role.ADMIN,
        email="alice@example.com",
        full_name="Alice Admin",
    )


# ---------------------------------------------------------------------------
# Bug 1: Async wrapper — sync original must not return unawaited coroutine
# ---------------------------------------------------------------------------

class TestBug1AsyncWrapper:
    """
    Verifies that the patched index_html_endpoint is always async, even when
    the original Dagster implementation is a plain synchronous function.
    """

    def test_patched_index_html_is_always_async(self):
        """apply_patches() must produce an async patched_index_html unconditionally."""
        import inspect
        import dagster_webserver.webserver as webserver_module
        from dagster_authkit.core.patch import apply_patches

        # Reset the sentinel so apply_patches() will run
        webserver_module.DagsterWebserver._authkit_patched = False

        # Temporarily replace index_html_endpoint with a sync function
        original = webserver_module.DagsterWebserver.index_html_endpoint

        def sync_index_html(self, request):  # pragma: no cover
            return HTMLResponse(content=_MINIMAL_HTML)

        webserver_module.DagsterWebserver.index_html_endpoint = sync_index_html

        try:
            with (
                patch("dagster_authkit.core.patch.apply_patches.__wrapped__", create=True),
                patch.object(
                    webserver_module.DagsterWebserver,
                    "build_middleware",
                    return_value=[],
                    create=True,
                ),
                patch.object(
                    webserver_module.DagsterWebserver,
                    "build_routes",
                    return_value=[],
                    create=True,
                ),
            ):
                apply_patches()

            patched = webserver_module.DagsterWebserver.index_html_endpoint
            assert inspect.iscoroutinefunction(patched), (
                "patched_index_html must be async def; a sync wrapper would return "
                "an unawaited coroutine for async _inject_resilient_ui"
            )
        finally:
            # Restore so other tests aren't affected
            webserver_module.DagsterWebserver.index_html_endpoint = original
            webserver_module.DagsterWebserver._authkit_patched = False

    @pytest.mark.asyncio
    async def test_inject_called_with_awaited_response(self):
        """_inject_resilient_ui must await the original even when it is sync."""
        from dagster_authkit.core import patch as patch_module

        user = _make_user()
        request = _make_request()
        request.scope["state"] = State()
        request.scope["state"].user = user

        original_backup = patch_module.original_index_html

        def sync_original(self, req):
            return _html_response(_MINIMAL_HTML)

        patch_module.original_index_html = sync_original
        try:
            response = await patch_module._inject_resilient_ui(None, request)
            assert isinstance(response, HTMLResponse)
            assert response.status_code == 200
        finally:
            patch_module.original_index_html = original_backup


# ---------------------------------------------------------------------------
# Bug 2: User retrieval — plain dict state vs Starlette State object
# ---------------------------------------------------------------------------

class TestBug2UserRetrieval:
    """
    Verifies that _inject_resilient_ui retrieves the authenticated user
    correctly whether scope["state"] is a plain dict (Starlette 1.3.1+
    with the old middleware code) or a Starlette State object (fixed
    middleware code).
    """

    @pytest.mark.asyncio
    async def test_user_retrieved_from_state_object(self):
        """Injection runs when user is stored on a Starlette State object."""
        from dagster_authkit.core import patch as patch_module

        user = _make_user()
        scope = _make_scope()
        state = State()
        state.user = user
        scope["state"] = state

        request = Request(scope)
        original_backup = patch_module.original_index_html
        patch_module.original_index_html = lambda self, req: _html_response(_MINIMAL_HTML)
        try:
            response = await patch_module._inject_resilient_ui(None, request)
        finally:
            patch_module.original_index_html = original_backup

        body = response.body.decode()
        assert "alice" in body.lower() or "Alice" in body, (
            "Expected injected user menu to reference the user"
        )

    @pytest.mark.asyncio
    async def test_user_retrieved_from_plain_dict_state(self):
        """
        Injection must NOT silently skip when scope['state'] is a plain dict
        (the old middleware stored user as scope['state']['user']).
        """
        from dagster_authkit.core import patch as patch_module

        user = _make_user()
        scope = _make_scope()
        scope["state"] = {"user": user}  # plain dict — old middleware behaviour

        request = Request(scope)
        original_backup = patch_module.original_index_html
        patch_module.original_index_html = lambda self, req: _html_response(_MINIMAL_HTML)
        try:
            response = await patch_module._inject_resilient_ui(None, request)
        finally:
            patch_module.original_index_html = original_backup

        body = response.body.decode()
        assert "alice" in body.lower() or "Alice" in body, (
            "getattr on a plain dict silently returns None — injection was skipped "
            "(Bug 2 regression)"
        )

    @pytest.mark.asyncio
    async def test_no_user_returns_vanilla_response(self):
        """When no user is present, the original response is returned unchanged."""
        from dagster_authkit.core import patch as patch_module

        scope = _make_scope()
        request = Request(scope)
        original_html = _MINIMAL_HTML

        original_backup = patch_module.original_index_html
        patch_module.original_index_html = lambda self, req: _html_response(original_html)
        try:
            response = await patch_module._inject_resilient_ui(None, request)
        finally:
            patch_module.original_index_html = original_backup

        assert response.body.decode() == original_html

    @pytest.mark.asyncio
    async def test_wrong_type_in_state_returns_vanilla_response(self):
        """A non-AuthUser value in state must not crash; vanilla HTML is returned."""
        from dagster_authkit.core import patch as patch_module

        scope = _make_scope()
        state = State()
        state.user = {"username": "not-an-authuser"}
        scope["state"] = state

        request = Request(scope)
        original_backup = patch_module.original_index_html
        patch_module.original_index_html = lambda self, req: _html_response(_MINIMAL_HTML)
        try:
            response = await patch_module._inject_resilient_ui(None, request)
        finally:
            patch_module.original_index_html = original_backup

        assert response.body.decode() == _MINIMAL_HTML


# ---------------------------------------------------------------------------
# Bug 3: CSP nonce — injected <script> must carry the page nonce
# ---------------------------------------------------------------------------

class TestBug3CspNonce:
    """
    Verifies that _inject_resilient_ui copies the per-request CSP nonce from
    the existing page HTML onto the injected <script> tag so that nonce-based
    CSP policies do not block it.
    """

    @pytest.mark.asyncio
    async def test_nonce_is_copied_to_injected_script(self):
        """The injected <script> tag must carry the nonce found in the page."""
        from dagster_authkit.core import patch as patch_module

        user = _make_user()
        scope = _make_scope()
        state = State()
        state.user = user
        scope["state"] = state

        request = Request(scope)
        original_backup = patch_module.original_index_html
        patch_module.original_index_html = lambda self, req: _html_response(_NONCE_HTML)
        try:
            response = await patch_module._inject_resilient_ui(None, request)
        finally:
            patch_module.original_index_html = original_backup

        body = response.body.decode()
        injected_section = body.split("</body>")[0].split("<body>")[-1]
        assert injected_section.count('nonce="abc123"') == 1, (
            "Injected <script> must carry nonce='abc123' copied from the page; "
            "without it the browser blocks the script (Bug 3 regression)"
        )

    @pytest.mark.asyncio
    async def test_no_nonce_in_page_leaves_script_unchanged(self):
        """When the page has no nonce, the injected <script> is emitted without one."""
        from dagster_authkit.core import patch as patch_module

        user = _make_user()
        scope = _make_scope()
        state = State()
        state.user = user
        scope["state"] = state

        request = Request(scope)
        original_backup = patch_module.original_index_html
        patch_module.original_index_html = lambda self, req: _html_response(_MINIMAL_HTML)
        try:
            response = await patch_module._inject_resilient_ui(None, request)
        finally:
            patch_module.original_index_html = original_backup

        body = response.body.decode()
        # Should still inject (no crash), just no nonce attribute
        assert "<script>" in body or "<script " in body

    @pytest.mark.asyncio
    async def test_nonce_not_duplicated_on_multiple_scripts(self):
        """
        Only the first <script> injected by authkit should get the nonce —
        prevent double-replacement if the template emits multiple <script> tags.
        """
        from dagster_authkit.core import patch as patch_module

        user = _make_user()
        scope = _make_scope()
        state = State()
        state.user = user
        scope["state"] = state

        request = Request(scope)
        original_backup = patch_module.original_index_html
        patch_module.original_index_html = lambda self, req: _html_response(_NONCE_HTML)
        try:
            response = await patch_module._inject_resilient_ui(None, request)
        finally:
            patch_module.original_index_html = original_backup

        body = response.body.decode()
        # The replacement is count=1, so the nonce appears on exactly one new script
        injected_section = body.split("</body>")[0].split("<body>")[-1]
        nonce_occurrences = injected_section.count('nonce="abc123"')
        # The original page nonce script is in <head>; the injected section
        # should have at most one nonce-stamped script tag.
        assert nonce_occurrences == 1


# ---------------------------------------------------------------------------
# Middleware: State object alignment (root cause of Bug 2)
# ---------------------------------------------------------------------------

class TestMiddlewareStateAlignment:
    """
    Verifies that DagsterAuthMiddleware stores the authenticated user on a
    Starlette State object (not a plain dict) so that request.state.user
    works correctly in downstream handlers.
    """

    @pytest.mark.asyncio
    async def test_user_stored_as_state_attribute(self):
        """
        After the middleware runs, scope['state'] must be a Starlette State
        object and scope['state'].user must be the AuthUser.
        """
        from starlette.datastructures import State
        from dagster_authkit.core.middleware import DagsterAuthMiddleware
        from dagster_authkit.auth.backends.base import AuthUser, Role

        captured_scope: dict = {}

        async def mock_app(scope, receive, send):
            captured_scope.update(scope)

        user = _make_user()
        headers = [
            (b"remote-user", b"alice"),
            (b"remote-groups", b"admins"),
            (b"remote-email", b"alice@example.com"),
            (b"remote-name", b"Alice Admin"),
        ]
        scope = {
            "type": "http",
            "method": "GET",
            "path": "/",
            "query_string": b"",
            "headers": headers,
            "server": ("localhost", 3000),
            "client": ("127.0.0.1", 12345),
        }

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send_fn(message):
            pass

        with (
            patch("dagster_authkit.core.middleware.config") as mock_cfg,
        ):
            mock_cfg.AUTH_BACKEND = "proxy"
            mock_cfg.DAGSTER_AUTH_PROXY_TRUST_ALL = True
            mock_cfg.DAGSTER_AUTH_PROXY_TRUSTED_IPS = None
            mock_cfg.SESSION_COOKIE_NAME = "test_session"
            mock_cfg.DAGSTER_AUTH_UNKNOWN_MUTATION_ROLE = "EDITOR"
            mock_cfg.DAGSTER_AUTH_REST_WRITE_ROLE = "EDITOR"

            # Build a fresh middleware with mocked config
            from unittest.mock import PropertyMock
            middleware2 = DagsterAuthMiddleware.__new__(DagsterAuthMiddleware)
            middleware2.app = mock_app
            middleware2.is_proxy_mode = True
            middleware2._unknown_mutation_role = Role.EDITOR
            middleware2._rest_write_role = Role.EDITOR

            proxy_backend_mock = MagicMock()
            proxy_backend_mock.get_user_from_headers.return_value = user
            middleware2.proxy_backend = proxy_backend_mock

            with patch.object(middleware2, "_is_request_from_trusted_proxy", return_value=True):
                await middleware2(scope, receive, send_fn)

        assert "state" in captured_scope, "scope['state'] must be set by middleware"
        assert isinstance(captured_scope["state"], State), (
            f"scope['state'] must be a Starlette State object, got {type(captured_scope['state'])}; "
            "plain dict breaks request.state.user attribute access (Bug 2 root cause)"
        )
        assert captured_scope["state"].user is user, (
            "scope['state'].user must be the AuthUser instance"
        )


# ---------------------------------------------------------------------------
# RBAC fail-open on malformed GraphQL batch payloads
# ---------------------------------------------------------------------------

class TestGraphQLBatchFailClosed:
    """Verifica que batch malformado retorna 400 em vez de fazer passthrough."""

    @pytest.mark.asyncio
    async def test_non_dict_item_in_batch_returns_400(self):
        from dagster_authkit.core.middleware import DagsterAuthMiddleware
        from dagster_authkit.auth.backends.base import AuthUser, Role

        sent_messages: list = []
        mock_app_called = False

        async def mock_app(scope, receive, send):
            nonlocal mock_app_called
            mock_app_called = True

        body = json.dumps([
            {"query": "mutation { launchRun(input: {}) }"},
            123,
        ]).encode("utf-8")

        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}

        async def send_fn(message):
            sent_messages.append(message)

        user = AuthUser(
            username="viewer",
            role=Role.VIEWER,
            email="viewer@localhost",
            full_name="Viewer User",
        )

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/graphql",
            "query_string": b"",
            "headers": [
                (b"remote-user", b"viewer"),
                (b"remote-groups", b""),
                (b"remote-email", b"viewer@localhost"),
                (b"remote-name", b"Viewer User"),
                (b"content-type", b"application/json"),
            ],
            "server": ("localhost", 3000),
            "client": ("127.0.0.1", 12345),
        }

        with patch("dagster_authkit.core.middleware.config") as mock_cfg:
            mock_cfg.AUTH_BACKEND = "proxy"
            mock_cfg.DAGSTER_AUTH_PROXY_TRUST_ALL = True
            mock_cfg.DAGSTER_AUTH_PROXY_TRUSTED_IPS = None
            mock_cfg.SESSION_COOKIE_NAME = "test_session"
            mock_cfg.DAGSTER_AUTH_UNKNOWN_MUTATION_ROLE = "EDITOR"
            mock_cfg.DAGSTER_AUTH_REST_WRITE_ROLE = "EDITOR"

            middleware = DagsterAuthMiddleware.__new__(DagsterAuthMiddleware)
            middleware.app = mock_app
            middleware.is_proxy_mode = True
            middleware._unknown_mutation_role = Role.EDITOR
            middleware._rest_write_role = Role.EDITOR

            proxy_backend_mock = MagicMock()
            proxy_backend_mock.get_user_from_headers.return_value = user
            middleware.proxy_backend = proxy_backend_mock

            with patch.object(middleware, "_is_request_from_trusted_proxy", return_value=True):
                await middleware(scope, receive, send_fn)

        assert not mock_app_called, (
            "Malformed batch must NOT passthrough to Dagster"
        )

        assert len(sent_messages) >= 2, (
            f"Expected >=2 response messages, got {len(sent_messages)}"
        )
        start_msg = sent_messages[0]
        assert start_msg["type"] == "http.response.start", (
            f"First message should be http.response.start, got {start_msg['type']}"
        )
        assert start_msg["status"] == 400, (
            f"Expected 400 for malformed batch, got {start_msg['status']}"
        )

        body_msg = sent_messages[1]
        error_body = body_msg.get("body", b"")
        assert b"Invalid GraphQL request format" in error_body, (
            "Response must contain error message about invalid format"
        )

    @pytest.mark.asyncio
    async def test_empty_batch_still_passthrough(self):
        """Empty array [] should still passthrough (regression guard)."""
        from dagster_authkit.core.middleware import DagsterAuthMiddleware
        from dagster_authkit.auth.backends.base import AuthUser, Role

        mock_app_called = False

        async def mock_app(scope, receive, send):
            nonlocal mock_app_called
            mock_app_called = True

        body = json.dumps([]).encode("utf-8")

        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}

        async def send_fn(message):
            pass

        user = AuthUser(
            username="admin",
            role=Role.ADMIN,
            email="admin@localhost",
            full_name="System Administrator",
        )

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/graphql",
            "query_string": b"",
            "headers": [
                (b"remote-user", b"admin"),
                (b"remote-groups", b""),
                (b"remote-email", b"admin@localhost"),
                (b"remote-name", b"System Administrator"),
                (b"content-type", b"application/json"),
            ],
            "server": ("localhost", 3000),
            "client": ("127.0.0.1", 12345),
        }

        with patch("dagster_authkit.core.middleware.config") as mock_cfg:
            mock_cfg.AUTH_BACKEND = "proxy"
            mock_cfg.DAGSTER_AUTH_PROXY_TRUST_ALL = True
            mock_cfg.DAGSTER_AUTH_PROXY_TRUSTED_IPS = None
            mock_cfg.SESSION_COOKIE_NAME = "test_session"
            mock_cfg.DAGSTER_AUTH_UNKNOWN_MUTATION_ROLE = "EDITOR"
            mock_cfg.DAGSTER_AUTH_REST_WRITE_ROLE = "EDITOR"

            middleware = DagsterAuthMiddleware.__new__(DagsterAuthMiddleware)
            middleware.app = mock_app
            middleware.is_proxy_mode = True
            middleware._unknown_mutation_role = Role.EDITOR
            middleware._rest_write_role = Role.EDITOR

            proxy_backend_mock = MagicMock()
            proxy_backend_mock.get_user_from_headers.return_value = user
            middleware.proxy_backend = proxy_backend_mock

            with patch.object(middleware, "_is_request_from_trusted_proxy", return_value=True):
                await middleware(scope, receive, send_fn)

        assert mock_app_called, (
            "Empty batch must still passthrough to Dagster"
        )


# ---------------------------------------------------------------------------
# B-01: Security headers on all response paths
# ---------------------------------------------------------------------------

class TestSecurityHeaders:
    """Verifies security headers are injected on all response paths."""

    @staticmethod
    def _get_header_dict(headers):
        return {
            k.decode("latin-1"): v.decode("latin-1")
            for k, v in (headers or [])
        }

    @pytest.mark.asyncio
    async def test_options_response_has_security_headers(self):
        """OPTIONS requests must receive security headers."""
        from dagster_authkit.core.middleware import DagsterAuthMiddleware
        from dagster_authkit.auth.backends.base import Role

        sent_messages = []

        async def mock_app(scope, receive, send):
            await send({
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/html")],
            })
            await send({
                "type": "http.response.body",
                "body": b"ok",
            })

        async def send_fn(message):
            sent_messages.append(message)

        scope = {
            "type": "http",
            "method": "OPTIONS",
            "path": "/graphql",
            "query_string": b"",
            "headers": [],
            "server": ("localhost", 3000),
            "client": ("127.0.0.1", 12345),
        }

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        with patch("dagster_authkit.core.middleware.config") as mock_cfg:
            mock_cfg.AUTH_BACKEND = "dummy"
            mock_cfg.SESSION_COOKIE_NAME = "test_session"
            mock_cfg.DAGSTER_AUTH_UNKNOWN_MUTATION_ROLE = "EDITOR"
            mock_cfg.DAGSTER_AUTH_REST_WRITE_ROLE = "EDITOR"

            middleware = DagsterAuthMiddleware(mock_app)

            await middleware(scope, receive, send_fn)

        assert len(sent_messages) >= 1
        start_msg = sent_messages[0]
        assert start_msg["type"] == "http.response.start"
        headers = self._get_header_dict(start_msg.get("headers", []))
        assert headers.get("X-Content-Type-Options") == "nosniff"
        assert headers.get("X-Frame-Options") == "DENY"

    @pytest.mark.asyncio
    async def test_inject_headers_send_wrapper(self):
        """_inject_headers_send must add security headers to any response."""
        from dagster_authkit.core.middleware import DagsterAuthMiddleware

        captured = []

        async def mock_send(message):
            captured.append(message)

        wrapped_send = DagsterAuthMiddleware._inject_headers_send(mock_send)
        await wrapped_send({
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"text/html")],
        })

        headers = self._get_header_dict(captured[0].get("headers", []))
        assert headers.get("X-Content-Type-Options") == "nosniff"
        assert headers.get("X-Frame-Options") == "DENY"
        assert "Content-Security-Policy" in headers
