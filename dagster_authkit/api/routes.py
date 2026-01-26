"""
Authentication Routes

Login/logout endpoints + HTML pages.
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
    get_audit_logger
)
from dagster_authkit.utils.config import config

logger = logging.getLogger(__name__)


async def login_page(request: Request) -> Response:
    """
    GET /auth/login - Displays login page.

    Args:
        request: Starlette Request

    Returns:
        HTML Response with login form
    """
    # Get 'next' parameter for redirect after login
    next_url = request.query_params.get("next", "/")

    # Validate next URL (prevent open redirect)
    if not SecurityHardening.validate_redirect_url(next_url):
        next_url = "/"

    # Get error message (if any)
    error = request.query_params.get("error", "")

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login - Dagster AuthKit</title>
        <style>
            body {{
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                margin: 0;
                padding: 20px;
            }}
            .login-box {{
                background: white;
                padding: 40px;
                border-radius: 10px;
                box-shadow: 0 10px 40px rgba(0,0,0,0.2);
                width: 100%;
                max-width: 400px;
            }}
            h1 {{
                margin: 0 0 10px 0;
                color: #333;
                font-size: 28px;
            }}
            .subtitle {{
                color: #666;
                margin-bottom: 30px;
                font-size: 14px;
            }}
            .form-group {{
                margin-bottom: 20px;
            }}
            label {{
                display: block;
                margin-bottom: 5px;
                color: #555;
                font-weight: 500;
                font-size: 14px;
            }}
            input[type="text"],
            input[type="password"] {{
                width: 100%;
                padding: 12px;
                border: 1px solid #ddd;
                border-radius: 5px;
                font-size: 14px;
                box-sizing: border-box;
            }}
            input[type="text"]:focus,
            input[type="password"]:focus {{
                outline: none;
                border-color: #667eea;
            }}
            button {{
                width: 100%;
                padding: 12px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                border: none;
                border-radius: 5px;
                font-size: 16px;
                font-weight: 600;
                cursor: pointer;
                transition: transform 0.2s;
            }}
            button:hover {{
                transform: translateY(-1px);
            }}
            button:active {{
                transform: translateY(0);
            }}
            .error {{
                background: #fee;
                color: #c33;
                padding: 12px;
                border-radius: 5px;
                margin-bottom: 20px;
                font-size: 14px;
                border-left: 3px solid #c33;
            }}
            .footer {{
                margin-top: 20px;
                text-align: center;
                color: #999;
                font-size: 12px;
            }}
        </style>
    </head>
    <body>
        <div class="login-box">
            <h1>🔐 Dagster Login</h1>
            <p class="subtitle">Enter your credentials to continue</p>
            
            {"<div class='error'>" + error + "</div>" if error else ""}
            
            <form method="post" action="/auth/process">
                <input type="hidden" name="next" value="{next_url}">
                
                <div class="form-group">
                    <label for="username">Username</label>
                    <input 
                        type="text" 
                        id="username" 
                        name="username" 
                        required 
                        autofocus
                        autocomplete="username"
                    >
                </div>
                
                <div class="form-group">
                    <label for="password">Password</label>
                    <input 
                        type="password" 
                        id="password" 
                        name="password" 
                        required
                        autocomplete="current-password"
                    >
                </div>
                
                <button type="submit">Login</button>
            </form>
            
            <div class="footer">
                Powered by <strong>dagster-authkit</strong>
            </div>
        </div>
    </body>
    </html>
    """

    return HTMLResponse(content=html)


async def process_login(request: Request) -> Response:
    """POST /auth/process - Processes login with strict auditing."""
    form = await request.form()
    username = SecurityHardening.sanitize_username(form.get("username", "").strip())
    password = form.get("password", "")
    next_url = form.get("next", "/")

    if not SecurityHardening.validate_redirect_url(next_url):
        next_url = "/"

    client_ip = request.client.host if request.client else None

    # 1. Rate Limiting Check
    is_limited, attempts = is_rate_limited(username)
    if is_limited:
        logger.warning(f"Rate limit exceeded for '{username}' ({attempts} attempts)")
        # RESTORED: Vital for security auditing and Fail2Ban integration
        log_login_attempt(username, False, client_ip, f"RATE_LIMIT ({attempts} attempts)")
        log_rate_limit_violation(username, client_ip, attempts)

        return RedirectResponse(
            url=f"/auth/login?next={next_url}&error=Too+many+failed+attempts.+Try+again+later.",
            status_code=302,
        )

    # 2. Backend Authentication
    try:
        backend = get_backend(config.AUTH_BACKEND, config.__dict__)
        user = backend.authenticate(username, password)
    except Exception as e:
        logger.error(f"Backend error during authentication: {e}")
        log_login_attempt(username, False, client_ip, "BACKEND_ERROR")
        return RedirectResponse(
            url=f"/auth/login?next={next_url}&error=Authentication+system+error.",
            status_code=302
        )

    # 3. Handle Failure
    if not user:
        logger.info(f"Failed login attempt for '{username}'")
        record_login_attempt(username)
        log_login_attempt(username, False, client_ip, "INVALID_CREDENTIALS")
        return RedirectResponse(
            url=f"/auth/login?next={next_url}&error=Invalid+username+or+password.",
            status_code=302
        )

    # 4. Success - Session and Logging
    logger.info(f"Successful login: '{user.username}' (role: {user.role.name})")
    reset_rate_limit(username)
    log_login_attempt(username, True, client_ip)

    # v1.0 Orchestrator call
    session_token = sessions.create(user.to_dict())

    # RESTORED: Session creation audit
    get_audit_logger().session_created(username, session_token[:16])

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
    """GET /auth/logout - Invalidate session and log event."""
    session_token = request.cookies.get(config.SESSION_COOKIE_NAME)
    username = "unknown"

    if session_token:
        # Use v1.0 orchestrator to identify user
        user_data = sessions.validate(session_token)
        if user_data:
            username = user_data.get("username", "unknown")

    client_ip = request.client.host if request.client else None
    log_logout(username, client_ip)
    logger.info(f"User '{username}' logged out")

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
    routes = [
        Route("/login", login_page, methods=["GET"]),
        Route("/process", process_login, methods=["POST"]),
        Route("/logout", logout, methods=["GET"]),
    ]

    router = Router(routes=routes)
    logger.info("Auth routes created: /login, /logout, /process")

    return router
