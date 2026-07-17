"""
Authentication Routes

Login/logout endpoints + HTML pages.
Matched with the finalized Peewee SQL Backend and stdout Audit Logging.
"""

import hashlib
import hmac
import logging

from itsdangerous import URLSafeTimedSerializer
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response
from starlette.routing import Route, Router

from dagster_authkit.auth.rate_limiter import (
    get_rate_limiter,
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

# Stateless synchronizer token pattern (valid for 1 hour).
# Tokens are signed, not stored server-side — works across K8s pods.
_csrf_serializer = URLSafeTimedSerializer(config.SECRET_KEY)
_CSRF_MAX_AGE = 3600


def _generate_csrf_token() -> str:
    """Generate a signed CSRF token valid for 1 hour."""
    raw = SecurityHardening.generate_csrf_token()
    return _csrf_serializer.dumps({"token": raw})


def _validate_csrf_token(token: str, cookie: str = "") -> bool:
    """Validate a signed CSRF token via double-submit cookie pattern.

    Checks that:
    1. The form token matches the cookie value (double-submit binding).
    2. The token is a valid signed blob and not expired.

    Args:
        token: CSRF token from the form submission.
        cookie: CSRF token from the cookie (double-submit check).

    Returns:
        True if both checks pass.
    """
    if not token:
        return False
    if cookie and not hmac.compare_digest(token, cookie):
        return False
    try:
        _csrf_serializer.loads(token, max_age=_CSRF_MAX_AGE)
        return True
    except Exception:
        return False


def _get_client_ip(request: Request) -> str:
    """Get real client IP, only trusting X-Forwarded-For from known proxies."""
    client_host = request.client.host if request.client else "unknown"

    # Only trust X-Forwarded-For if the connection comes from a trusted proxy.
    # Otherwise, an attacker can spoof the header to bypass IP-based rate limiting.
    if client_host in config.DAGSTER_AUTH_PROXY_TRUSTED_IPS:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return client_host


async def login_page(request: Request) -> Response:
    """GET /auth/login - Displays login page."""
    next_url = request.query_params.get("next", "/")
    if not SecurityHardening.validate_redirect_url(next_url):
        next_url = "/"

    error = request.query_params.get("error", "")

    # Generate signed CSRF token (stateless, works across pods)
    csrf_token = _generate_csrf_token()

    html = render_login_page(next_url, error, csrf_token)

    response = HTMLResponse(content=html)
    response.set_cookie(
        key="csrf_token",
        value=csrf_token,
        max_age=_CSRF_MAX_AGE,
        httponly=True,
        secure=config.SESSION_COOKIE_SECURE,
        samesite="lax",
    )
    return response


async def process_login(request: Request) -> Response:
    """
    POST /auth/process — Authenticates and creates session.

    Multi-step flow:
    1. Validate CSRF token (stateless signed, 1h TTL).
    2. Check rate limits for both username and IP independently.
    3. Authenticate via the configured backend (runs in thread pool).
    4. On success: create session, set cookie, redirect to next_url.
    5. On failure: record attempt, redirect with error.

    Args:
        request: Starlette Request with form fields (username, password,
                 next, csrf_token).

    Returns:
        RedirectResponse (302) to either next_url on success or
        /auth/login with error message on failure.
    """
    form = await request.form()
    username = SecurityHardening.sanitize_username(str(form.get("username", "")).strip())
    password = str(form.get("password", ""))
    next_url = str(form.get("next", "/"))

    if not SecurityHardening.validate_redirect_url(next_url):
        next_url = "/"

    # CSRF validation: double-submit cookie + signed token
    csrf_token = str(form.get("csrf_token", ""))
    csrf_cookie = request.cookies.get("csrf_token", "")
    if not _validate_csrf_token(csrf_token, cookie=csrf_cookie):
        logger.warning("CSRF validation failed for login attempt", exc_info=True)
        return RedirectResponse(
            url=f"/auth/login?next={next_url}&error=Invalid+request.", status_code=302
        )

    client_ip = _get_client_ip(request)
    ip_identifier = f"ip:{client_ip}"
    rl = get_rate_limiter()

    # 1. Rate Limiting Check (username + IP, independent, atomic)
    user_limited, user_attempts = rl.check_and_record(username)
    ip_limited, ip_attempts = rl.check_and_record(ip_identifier)
    if user_limited or ip_limited:
        total = max(user_attempts, ip_attempts)
        log_login_attempt(username, False, client_ip, f"RATE_LIMIT ({total} attempts)")
        log_rate_limit_violation(username, client_ip, total)
        return RedirectResponse(
            url=f"/auth/login?next={next_url}&error=Too+many+attempts.", status_code=302
        )

    # 2. Backend Call (Peewee / SQL / LDAP) — runs in thread pool to avoid
    #    blocking the async event loop (bcrypt ~250ms + DB/LDAP I/O).
    try:
        backend = get_backend(config.AUTH_BACKEND, config.__dict__)
        user = await run_in_threadpool(backend.authenticate, username, password)
    except Exception as e:
        logger.error(f"Auth Backend Error: {e}")
        log_login_attempt(username, False, client_ip, "BACKEND_ERROR")
        return RedirectResponse(
            url=f"/auth/login?next={next_url}&error=System+error.", status_code=302
        )

    # 3. Validation
    if not user:
        # Attempt already recorded by check_and_record above
        log_login_attempt(username, False, client_ip, "INVALID_CREDENTIALS")
        return RedirectResponse(
            url=f"/auth/login?next={next_url}&error=Invalid+credentials.", status_code=302
        )

    # 4. Success & Session Creation
    reset_rate_limit(username)
    reset_rate_limit(ip_identifier)
    log_login_attempt(username, True, client_ip)

    session_token = sessions.create(user.to_dict())

    session_hash = hashlib.sha256(session_token.encode()).hexdigest()[:16]
    log_audit_event("SESSION_CREATED", username, session_id=session_hash, ip=client_ip)

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
    """
    GET /auth/logout - Revokes session.

    Behavior:
    - Proxy mode: Redirects to Authelia logout URL
    - Session mode: Revokes local session cookie
    """
    if config.AUTH_BACKEND == "proxy":
        logout_url = config.DAGSTER_AUTH_PROXY_LOGOUT_URL
        logger.info(f"Proxy mode: Redirecting logout to {logout_url}")
        return RedirectResponse(url=logout_url, status_code=302)

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
    response.delete_cookie(
        key="csrf_token",
        httponly=True,
        secure=config.SESSION_COOKIE_SECURE,
        samesite="lax",
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
