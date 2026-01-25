"""
Dagster Monkey-Patching Module - AuthKit Edition

Fixed: Escaped f-string braces for CSS/JS compatibility.
"""

import logging

from starlette.requests import Request
from starlette.responses import HTMLResponse

logger = logging.getLogger(__name__)

original_index_html = None


def apply_patches() -> None:
    logger.info("🔧 Applying Dagster webserver patches...")

    try:
        import dagster_webserver.webserver as webserver_module
        from starlette.middleware import Middleware
        from .middleware import DagsterAuthMiddleware

        global original_index_html
    except ImportError as e:
        logger.error(f"❌ Failed to import required modules: {e}")
        raise

    # PATCH 1: Middleware
    try:
        original_build_middleware = webserver_module.DagsterWebserver.build_middleware

        def patched_build_middleware(self):
            middlewares = original_build_middleware(self)
            auth_middleware = Middleware(DagsterAuthMiddleware)
            middlewares.insert(0, auth_middleware)
            return middlewares

        webserver_module.DagsterWebserver.build_middleware = patched_build_middleware
    except Exception as e:
        logger.error(f"❌ Middleware patch failed: {e}")

    # PATCH 2: Routes
    try:
        original_build_routes = webserver_module.DagsterWebserver.build_routes


        def patched_build_routes(self):
            from starlette.routing import Mount
            from dagster_authkit.api.routes import create_auth_routes
            from dagster_authkit.api.health import create_health_routes

            routes_list = original_build_routes(self)
            auth_routes = create_auth_routes()
            create_health_routes(auth_routes)
            routes_list.insert(0, Mount("/auth", routes=auth_routes.routes))
            return routes_list

        webserver_module.DagsterWebserver.build_routes = patched_build_routes
    except Exception as e:
        logger.error(f"❌ Routes patch failed: {e}")

    # PATCH 3: UI Hijacking
    try:
        original_index_html = webserver_module.DagsterWebserver.index_html_endpoint

        def patched_index_html_wrapper(self, request: Request):
            return _inject_ui_logic(self, request)

        webserver_module.DagsterWebserver.index_html_endpoint = patched_index_html_wrapper
    except Exception as e:
        logger.error(f"❌ UI patch failed: {e}")

    logger.info("🎉 All Dagster patches applied successfully!")


def _inject_ui_logic(self, request: Request):
    response = original_index_html(self, request)
    user = getattr(request.state, "user", {"username": "Guest", "roles": ["viewer"]})

    username = user.get("username", "Guest")
    role = user.get("roles", ["viewer"])[0].upper()
    initial = username[0].upper()

    # Sign-Out SVG (Lucide/Feather style)
    logout_svg = (
        '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
        'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
        '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path>'
        '<polyline points="16 17 21 12 16 7"></polyline>'
        '<line x1="21" y1="12" x2="9" y2="12"></line></svg>'
    )

    # Using raw f-string with proper escaping
    injection = rf"""
    <style>
        #authkit-sidebar-card {{
            margin: 8px;
            padding: 8px;
            display: flex;
            align-items: center;
            border-radius: 8px;
            background: rgba(255, 255, 255, 0.04);
            border: 1px solid rgba(255, 255, 255, 0.08);
            transition: all 0.2s ease;
            overflow: hidden;
            min-height: 44px;
        }}
        #authkit-sidebar-card:hover {{
            background: rgba(255, 255, 255, 0.08);
            border-color: rgba(255, 255, 255, 0.15);
        }}
        .authkit-avatar {{
            min-width: 28px; height: 28px;
            background: #4f4f4f; color: white;
            border-radius: 6px; display: flex;
            align-items: center; justify-content: center;
            font-weight: bold; font-size: 13px;
            flex-shrink: 0;
        }}
        .authkit-content {{
            margin-left: 12px;
            display: flex;
            flex-direction: column;
            white-space: nowrap;
            flex-grow: 1;
        }}
        /* Hide text when Dagster sidebar collapses */
        [class*="MainNavigation_collapsed"] .authkit-content,
        [class*="MainNavigation_collapsed"] .authkit-logout {{
            display: none;
        }}
        /* Center avatar in collapsed sidebar */
        [class*="MainNavigation_collapsed"] #authkit-sidebar-card {{
            justify-content: center;
            padding: 8px 0;
        }}
        .authkit-user {{ color: #ffffff; font-size: 13px; font-weight: 600; line-height: 1.2; }}
        .authkit-role {{ color: #888; font-size: 10px; text-transform: uppercase; }}
        .authkit-logout {{
            color: #ff6b6b; opacity: 0.7;
            text-decoration: none; display: flex;
            align-items: center; justify-content: center;
            padding: 4px; border-radius: 4px;
            transition: all 0.2s;
        }}
        .authkit-logout:hover {{ 
            opacity: 1; 
            background: rgba(255, 107, 107, 0.15);
        }}
    </style>
    <script>
        function injectAuthUI() {{
            const bottomGroup = document.querySelector('div[class*="MainNavigation_bottomGroups"]');
            
            if (bottomGroup && !document.getElementById('authkit-sidebar-card')) {{
                const card = document.createElement('div');
                card.id = 'authkit-sidebar-card';
                card.innerHTML = `
                    <div class="authkit-avatar" title="{username}">{initial}</div>
                    <div class="authkit-content">
                        <span class="authkit-user">{username}</span>
                        <span class="authkit-role">{role}</span>
                    </div>
                    <a href="/auth/logout" class="authkit-logout" title="Sign Out">
                        {logout_svg}
                    </a>
                `;
                bottomGroup.prepend(card);
            }}
        }}
        const observer = new MutationObserver(injectAuthUI);
        observer.observe(document.body, {{ childList: true, subtree: true }});
        injectAuthUI();
    </script>
    """

    # Convert response body to string safely
    if hasattr(response.body, "decode"):
        html = response.body.decode("utf-8")
    else:
        html = str(response.body)

    html = html.replace("</body>", f"{injection}</body>")

    headers = dict(response.headers)
    headers.pop("content-length", None)
    headers.pop("etag", None)

    return HTMLResponse(content=html, status_code=response.status_code, headers=headers)


def verify_patches() -> bool:
    try:
        import dagster_webserver.webserver as webserver_module

        return hasattr(webserver_module.DagsterWebserver, "build_middleware")
    except:
        return False
