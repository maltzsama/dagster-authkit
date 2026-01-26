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
        return RedirectResponse(url=f"/auth/login?next={next_url}&error=Too+many+attempts.", status_code=302)

    # 2. Backend Call (Peewee / SQL)
    try:
        backend = get_backend(config.AUTH_BACKEND, config.__dict__)
        user = backend.authenticate(username, password)
    except Exception as e:
        logger.error(f"Auth Backend Error: {e}")
        log_login_attempt(username, False, client_ip, "BACKEND_ERROR")
        return RedirectResponse(url=f"/auth/login?next={next_url}&error=System+error.", status_code=302)

    # 3. Validation
    if not user:
        record_login_attempt(username)
        log_login_attempt(username, False, client_ip, "INVALID_CREDENTIALS")
        return RedirectResponse(url=f"/auth/login?next={next_url}&error=Invalid+credentials.", status_code=302)

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
    return Router(routes=[
        Route("/login", login_page, methods=["GET"]),
        Route("/process", process_login, methods=["POST"]),
        Route("/logout", logout, methods=["GET"]),
    ])
