"""
Authentication Routes

Login/logout endpoints + HTML pages.
Matched with the finalized Peewee SQL Backend and stdout Audit Logging.
"""

import logging
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response
from starlette.routing import Route, Router

from dagster_authkit.auth.rate_limiter import (
    is_rate_limited,
    record_login_attempt,
    reset_rate_limit,
)
from dagster_authkit.auth.security import SecurityHardening
from dagster_authkit.auth.session import sessions
from dagster_authkit.core.registry import get_backend
from dagster_authkit.utils.audit import (
    log_login_attempt,
    log_logout,
    log_rate_limit_violation,
    log_audit_event,
)
from dagster_authkit.utils.config import config
from dagster_authkit.utils.templates import render_login_page


logger = logging.getLogger(__name__)


def _get_client_ip(request: Request) -> str:
    """Helper to get real IP behind K8s Ingress (X-Forwarded-For)."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def login_page(request: Request) -> Response:
    """GET /auth/login - Displays login page."""
    next_url = request.query_params.get("next", "/")
    if not SecurityHardening.validate_redirect_url(next_url):
        next_url = "/"

    error = request.query_params.get("error", "")
    html = render_login_page(next_url, error)

    return HTMLResponse(content=html)


async def process_login(request: Request) -> Response:
    """POST /auth/process - Authenticates and creates session."""
    form = await request.form()
    username = SecurityHardening.sanitize_username(str(form.get("username", "")).strip())
    password = str(form.get("password", ""))
    next_url = str(form.get("next", "/"))

    if not SecurityHardening.validate_redirect_url(next_url):
        next_url = "/"

    client_ip = _get_client_ip(request)

    # 1. Rate Limiting Check
    is_limited, attempts = is_rate_limited(username)
    if is_limited:
        log_login_attempt(username, False, client_ip, f"RATE_LIMIT ({attempts} attempts)")
        log_rate_limit_violation(username, client_ip, attempts)
        return RedirectResponse(
            url=f"/auth/login?next={next_url}&error=Too+many+attempts.", status_code=302
        )

    # 2. Backend Call (Peewee / SQL)
    try:
        backend = get_backend(config.AUTH_BACKEND, config.__dict__)
        user = backend.authenticate(username, password)
    except Exception as e:
        logger.error(f"Auth Backend Error: {e}")
        log_login_attempt(username, False, client_ip, "BACKEND_ERROR")
        return RedirectResponse(
            url=f"/auth/login?next={next_url}&error=System+error.", status_code=302
        )

    # 3. Validation
    if not user:
        record_login_attempt(username)
        log_login_attempt(username, False, client_ip, "INVALID_CREDENTIALS")
        return RedirectResponse(
            url=f"/auth/login?next={next_url}&error=Invalid+credentials.", status_code=302
        )

    # 4. Success & Session Creation
    reset_rate_limit(username)
    log_login_attempt(username, True, client_ip)

    session_token = sessions.create(user.to_dict())

    log_audit_event("SESSION_CREATED", username, session_id=session_token[:16], ip=client_ip)

    response = RedirectResponse(url=next_url, status_code=302)
    response.set_cookie(
        key=config.SESSION_COOKIE_NAME,
        value=session_token,
        max_age=config.SESSION_MAX_AGE,
        httponly=config.SESSION_COOKIE_HTTPONLY,
        secure=config.SESSION_COOKIE_SECURE,
        samesite=config.SESSION_COOKIE_SAMESITE,
    )
    return response


async def logout(request: Request) -> Response:
    """GET /auth/logout - Revokes session."""
    session_token = request.cookies.get(config.SESSION_COOKIE_NAME)
    username = "unknown"

    if session_token:
        user_data = sessions.validate(session_token)
        if user_data:
            username = user_data.get("username", "unknown")
            sessions.revoke(session_token)

    client_ip = _get_client_ip(request)
    log_logout(username, client_ip)

    response = RedirectResponse(url="/auth/login", status_code=302)
    response.delete_cookie(
        key=config.SESSION_COOKIE_NAME,
        httponly=config.SESSION_COOKIE_HTTPONLY,
        secure=config.SESSION_COOKIE_SECURE,
        samesite=config.SESSION_COOKIE_SAMESITE,
    )
    return response


def create_auth_routes() -> Router:
    """
    Creates router with authentication routes.

    Returns:
        Starlette Router with routes /login, /logout, /process
    """
    return Router(
        routes=[
            Route("/login", login_page, methods=["GET"]),
            Route("/process", process_login, methods=["POST"]),
            Route("/logout", logout, methods=["GET"]),
        ]
    )
