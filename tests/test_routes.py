"""
Tests for dagster_authkit/api/routes.py

Covers:
- N-02: CSRF double-submit cookie pattern
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from dagster_authkit.api.routes import _validate_csrf_token, _generate_csrf_token


class TestCsrfDoubleSubmit:
    """Verifica o double-submit cookie pattern (N-02)."""

    def test_validate_matching_token_and_cookie(self):
        """Token e cookie iguais → válido."""
        token = _generate_csrf_token()
        assert _validate_csrf_token(token, cookie=token) is True

    def test_validate_mismatched_token_and_cookie(self):
        """Token e cookie diferentes → inválido."""
        token_a = _generate_csrf_token()
        token_b = _generate_csrf_token()
        assert _validate_csrf_token(token_a, cookie=token_b) is False

    def test_validate_token_without_cookie_skips_check(self):
        """Sem cookie passado, só valida assinatura (backward compat)."""
        token = _generate_csrf_token()
        assert _validate_csrf_token(token) is True

    def test_validate_empty_token(self):
        """Token vazio → inválido."""
        assert _validate_csrf_token("", cookie="x") is False

    def test_validate_expired_token(self):
        """Token expirado → inválido."""
        token = _generate_csrf_token()
        with patch("dagster_authkit.api.routes._CSRF_MAX_AGE", -1):
            assert _validate_csrf_token(token, cookie=token) is False

    def test_validate_tampered_token(self):
        """Token adulterado → inválido."""
        token = _generate_csrf_token() + "x"
        assert _validate_csrf_token(token, cookie=token) is False

    @pytest.mark.asyncio
    async def test_login_page_sets_csrf_cookie(self):
        """GET /auth/login deve setar cookie csrf_token."""
        from dagster_authkit.api.routes import login_page

        request = MagicMock()
        request.query_params.get.return_value = "/"

        response = await login_page(request)

        cookie_headers = response.headers.getlist("set-cookie")
        csrf_cookie = next(
            (h for h in cookie_headers if h.startswith("csrf_token=")), None
        )
        assert csrf_cookie is not None, "Response must set csrf_token cookie"
        assert "HttpOnly" in csrf_cookie
        assert "SameSite=lax" in csrf_cookie or "SameSite=Lax" in csrf_cookie

    @pytest.mark.asyncio
    async def test_login_page_token_matches_cookie(self):
        """Token no form e no cookie devem ser o mesmo valor."""
        from dagster_authkit.api.routes import login_page

        request = MagicMock()
        request.query_params.get.return_value = "/"

        response = await login_page(request)

        cookie_headers = response.headers.getlist("set-cookie")
        csrf_cookie = next(
            (h for h in cookie_headers if h.startswith("csrf_token=")), ""
        )
        cookie_value = csrf_cookie.split(";")[0].split("=", 1)[1]

        body = response.body.decode("utf-8")
        assert f'value="{cookie_value}"' in body, (
            "Form token must match cookie value"
        )

    @pytest.mark.asyncio
    async def test_process_login_rejects_mismatched_cookie(self):
        """Cookie diferente do form → redirect com erro."""
        from dagster_authkit.api.routes import process_login

        form_token = _generate_csrf_token()
        cookie_token = _generate_csrf_token()

        form_data = {
            "username": "admin",
            "password": "admin",
            "csrf_token": form_token,
            "next": "/",
        }

        request = MagicMock()
        request.form = AsyncMock(return_value=form_data)
        request.cookies = {"csrf_token": cookie_token}

        response = await process_login(request)

        assert response.status_code == 302
        assert "error=Invalid+request" in str(response.headers.get("location", ""))

    @pytest.mark.asyncio
    async def test_process_login_accepts_matching_cookie(self):
        """Cookie e form iguais + credenciais válidas → login OK."""
        from dagster_authkit.api.routes import process_login

        token = _generate_csrf_token()
        form_data = {
            "username": "admin",
            "password": "admin",
            "csrf_token": token,
            "next": "/",
        }

        request = MagicMock()
        request.form = AsyncMock(return_value=form_data)
        request.cookies = {"csrf_token": token}
        request.client.host = "127.0.0.1"

        with (
            patch("dagster_authkit.api.routes.get_rate_limiter") as mock_rl,
            patch("dagster_authkit.api.routes.get_backend") as mock_get_backend,
            patch("dagster_authkit.api.routes.sessions") as mock_sessions,
        ):
            mock_limiter = MagicMock()
            mock_limiter.check_and_record.return_value = (False, 1)
            mock_rl.return_value = mock_limiter

            mock_backend = MagicMock()
            mock_backend.authenticate.return_value = MagicMock(
                to_dict=MagicMock(return_value={"username": "admin", "role": "ADMIN"})
            )
            mock_get_backend.return_value = mock_backend

            mock_sessions.create.return_value = "fake-session-token"

            response = await process_login(request)

        assert response.status_code == 302
        location = response.headers.get("location", "")
        assert "error=" not in location.replace("/auth/login?", ""), (
            f"Expected success redirect, got: {location}"
        )
