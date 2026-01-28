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

    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Sign in to Dagster</title>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/geist@1.3.0/dist/fonts/geist-sans/style.css">
        <style>
            :root {{
                /* Tokens extraídos do seu lightThemeColors.tsx */
                --bg-default: #ffffff;
                --text-default: #1f2937;
                --text-light: #6b7280;
                --border-default: #d1d5db;
                --accent-primary: #234ad1;
                --accent-primary-hover: #1a39a7;
                --focus-ring: rgba(35, 74, 209, 0.2);
                --error-bg: #fef2f2;
                --error-text: #991b1b;
            }}

            @media (prefers-color-scheme: dark) {{
                :root {{
                    /* Tokens extraídos do seu darkThemeColors.tsx */
                    --bg-default: #111827;
                    --text-default: #ffffff;
                    --text-light: #9ca3af;
                    --border-default: #374151;
                    --accent-primary: #3b82f6;
                    --accent-primary-hover: #60a5fa;
                    --focus-ring: rgba(59, 130, 246, 0.4);
                    --error-bg: #450a0a;
                    --error-text: #fca5a5;
                }}
            }}

            * {{ box-sizing: border-box; }}

            body {{
                margin: 0;
                background-color: var(--bg-default);
                color: var(--text-default);
                font-family: "Geist Sans", -apple-system, system-ui, sans-serif;
                -webkit-font-smoothing: antialiased;
                display: flex;
                align-items: center;
                justify-content: center;
                min-height: 100vh;
            }}

            .login-card {{
                width: 100%;
                max-width: 400px;
                padding: 40px;
                border-radius: 8px;
                /* No Dagster as bordas são sutis e os cards têm sombras leves */
                border: 1px solid var(--border-default);
                box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            }}

            .header {{
                text-align: center;
                margin-bottom: 32px;
            }}

            .logo-svg {{
                width: 48px;
                height: 48px;
                margin-bottom: 16px;
            }}

            h1 {{
                font-size: 20px;
                font-weight: 600;
                margin: 0;
                letter-spacing: -0.02em;
            }}

            .subtitle {{
                font-size: 14px;
                color: var(--text-light);
                margin-top: 8px;
            }}

            .form-group {{
                margin-bottom: 24px;
            }}

            label {{
                display: block;
                font-size: 12px;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.05em;
                margin-bottom: 8px;
                color: var(--text-light);
            }}

            /* Estilo TextInput.tsx - Simulação do BlueprintJS */
            input {{
                width: 100%;
                height: 36px;
                padding: 0 12px;
                font-size: 14px;
                background: transparent;
                color: inherit;
                border: 1px solid var(--border-default);
                border-radius: 4px;
                transition: border-color 0.1s ease-in-out, box-shadow 0.1s ease-in-out;
            }}

            input:focus {{
                outline: none;
                border-color: var(--accent-primary);
                box-shadow: 0 0 0 3px var(--focus-ring);
            }}

            /* Estilo Button.tsx */
            button {{
                width: 100%;
                height: 40px;
                background-color: var(--accent-primary);
                color: #ffffff;
                border: none;
                border-radius: 4px;
                font-size: 14px;
                font-weight: 600;
                cursor: pointer;
                transition: background-color 0.1s;
            }}

            button:hover {{
                background-color: var(--accent-primary-hover);
            }}

            .error-message {{
                background-color: var(--error-bg);
                color: var(--error-text);
                padding: 12px;
                border-radius: 4px;
                font-size: 13px;
                margin-bottom: 24px;
                border: 1px solid var(--error-text);
            }}

            .footer {{
                margin-top: 40px;
                text-align: center;
                font-size: 11px;
                color: var(--text-light);
                text-transform: uppercase;
                letter-spacing: 0.1em;
            }}
        </style>
    </head>
    <body>
        <div class="login-card">
            <div class="header">
                <svg class="logo-svg" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <rect width="48" height="48" rx="8" fill="#234AD1"/>
                    <path d="M12 16H20V24H12V16Z" fill="white"/>
                    <path d="M28 16H36V24H28V16Z" fill="white" fill-opacity="0.7"/>
                    <path d="M12 28H20V36H12V28Z" fill="white" fill-opacity="0.7"/>
                    <path d="M28 28H36V36H28V28Z" fill="white" fill-opacity="0.4"/>
                </svg>
                <h1>Dagster AuthKit</h1>
                <p class="subtitle">Please sign in to continue</p>
            </div>

            {"<div class='error-message'>" + error + "</div>" if error else ""}

            <form method="post" action="/auth/process">
                <input type="hidden" name="next" value="{next_url}">

                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" id="username" name="username" required autofocus>
                </div>

                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" required>
                </div>

                <button type="submit">Sign In</button>
            </form>

            <div class="footer">
                Community-driven Security
            </div>
        </div>
    </body>
    </html>
    """
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
