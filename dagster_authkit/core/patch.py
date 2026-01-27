"""
Dagster Monkey-Patching Module - "Resilient Infiltration" Edition

Injects user profile into Dagster sidebar with:
- Retry logic for late-loading React components
- Multiple CSS selector fallbacks for version compatibility
- Safe mode fallback (top-right corner) if injection fails
- Debug logging for production troubleshooting
"""

import json
import logging
import os

from starlette.requests import Request
from starlette.responses import HTMLResponse

from dagster_authkit.auth.backends.base import AuthUser

logger = logging.getLogger(__name__)

original_index_html = None


def apply_patches() -> None:
    """Apply all monkey-patches to Dagster webserver."""
    logger.info("🔧 Applying resilient UI patches for Dagster...")

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
            middlewares.insert(0, Middleware(DagsterAuthMiddleware))
            return middlewares

        webserver_module.DagsterWebserver.build_middleware = patched_build_middleware
        logger.info("✅ Middleware patched")
    except Exception as e:
        logger.error(f"❌ Middleware patch failed: {e}")
        raise

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
        logger.info("✅ Routes patched")
    except Exception as e:
        logger.error(f"❌ Routes patch failed: {e}")
        raise

    # PATCH 3: UI Injection (Resilient)
    try:
        original_index_html = webserver_module.DagsterWebserver.index_html_endpoint

        def patched_index_html_wrapper(self, request: Request):
            return _inject_resilient_ui(self, request)

        webserver_module.DagsterWebserver.index_html_endpoint = patched_index_html_wrapper
        logger.info("✅ Resilient UI injection patched")
    except Exception as e:
        logger.error(f"❌ UI patch failed: {e}")
        raise


def _inject_resilient_ui(self, request: Request):
    """Inject user menu with resilient retry logic and safe mode fallback."""
    response = original_index_html(self, request)

    # Get user from request state
    user = getattr(request.state, "user", None)

    if not user or not isinstance(user, AuthUser):
        return response

    # Extract user data
    username = user.username
    full_name = user.full_name or username.capitalize()
    email = user.email or ""
    role = user.role.name
    initial = (full_name[0] if full_name else username[0]).upper()

    # Read config from ENV
    debug_mode = os.getenv("DAGSTER_AUTH_DEBUG", "false").lower() == "true"
    safe_mode = os.getenv("DAGSTER_AUTH_UI_SAFE_MODE", "true").lower() == "true"

    # Serialize user data for JavaScript
    user_data_json = json.dumps(
        {
            "username": username,
            "full_name": full_name,
            "email": email,
            "role": role,
            "initial": initial,
            "has_email": bool(email),
        }
    )

    # Generate injection HTML
    injection = _generate_injection_html(user_data_json, debug_mode, safe_mode)

    # Inject into HTML
    if hasattr(response.body, "decode"):
        html = response.body.decode("utf-8")
    else:
        html = str(response.body)

    html = html.replace("</body>", f"{injection}</body>")

    # Update headers
    headers = dict(response.headers)
    headers.pop("content-length", None)
    headers.pop("etag", None)

    return HTMLResponse(content=html, status_code=response.status_code, headers=headers)


def _generate_injection_html(user_data_json: str, debug: bool, safe_mode: bool) -> str:
    """Generate complete HTML/CSS/JS injection code."""

    return f"""
    <!-- Dagster AuthKit - Resilient UI Injection v1.0 -->
    <style>
        /* Geist Sans Typography */
        @import url('https://cdn.jsdelivr.net/npm/geist@1.3.0/dist/fonts/geist-sans/style.css');

        /* User Menu Container */
        #authkit-nav-item {{
            position: relative;
        }}

        /* Avatar Circle (Dagster Blue) */
        .authkit-avatar-circle {{
            width: 18px;
            height: 18px;
            background: #234AD1;
            border-radius: 4px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            color: white;
            font-size: 10px;
            flex-shrink: 0;
            font-family: "Geist Sans", sans-serif;
        }}

        /* Username Label */
        .authkit-label {{
            flex: 1;
            min-width: 0;
            text-align: left;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            font-size: 14px;
            font-family: "Geist Sans", sans-serif;
        }}

        /* Popover (BlueprintJS Style) */
        .authkit-popover {{
            display: none;
            position: fixed;
            bottom: 65px;
            left: 12px;
            width: 240px;
            background: #ffffff;
            border-radius: 8px;
            border: 1px solid #D1D5DB;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.15);
            z-index: 10000;
            font-family: "Geist Sans", sans-serif;
        }}

        /* Dark Mode Support */
        @media (prefers-color-scheme: dark) {{
            .authkit-popover {{
                background: #1a1d29;
                border: 1px solid rgba(255, 255, 255, 0.15);
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.5);
            }}
            .authkit-header {{
                border-bottom: 1px solid rgba(255, 255, 255, 0.1) !important;
            }}
        }}

        .authkit-popover.active {{
            display: block;
        }}

        .authkit-header {{
            padding: 12px 16px;
            border-bottom: 1px solid rgba(0, 0, 0, 0.1);
        }}

        .authkit-item {{
            padding: 10px 16px;
            display: block;
            color: #ef4444;
            text-decoration: none;
            font-size: 14px;
            font-weight: 500;
            transition: background-color 0.2s;
            cursor: pointer;
        }}

        .authkit-item:hover {{
            background-color: rgba(239, 68, 68, 0.05);
        }}

        #authkit-trigger {{
            background: transparent;
            border: none;
            padding: 0;
            width: 100%;
            cursor: pointer;
            color: inherit;
        }}

        .authkit-box-proxy {{
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 8px 12px;
            min-width: 0;
        }}

        /* Safe Mode Fallback (Top-Right Corner) */
        #authkit-safe-mode-menu {{
            position: fixed;
            top: 12px;
            right: 12px;
            z-index: 9999;
            background: #1a1d29;
            border: 1px solid #333;
            border-radius: 8px;
            padding: 8px 12px;
            display: none;
            align-items: center;
            gap: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.3);
            font-family: "Geist Sans", sans-serif;
        }}

        #authkit-safe-mode-menu.active {{
            display: flex;
        }}

        .authkit-safe-avatar {{
            width: 24px;
            height: 24px;
            border-radius: 50%;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: 600;
            font-size: 11px;
        }}

        .authkit-safe-info {{
            color: #e0e0e0;
            font-size: 12px;
            font-weight: 500;
        }}

        .authkit-safe-logout {{
            color: #ff6b6b;
            font-size: 11px;
            text-decoration: none;
            margin-left: 8px;
            padding: 4px 8px;
            border: 1px solid #ff6b6b;
            border-radius: 4px;
        }}

        .authkit-safe-logout:hover {{
            background: rgba(255, 107, 107, 0.1);
        }}
    </style>

    <script>
    (function() {{
        'use strict';

        // Configuration
        const DEBUG = {str(debug).lower()};
        const SAFE_MODE = {str(safe_mode).lower()};
        const MAX_RETRIES = 10;
        const RETRY_INTERVAL = 500; // ms

        let retryCount = 0;

        // User data
        const user = {user_data_json};

        // Logging
        function log(msg, level = 'info') {{
            if (DEBUG) {{
                const prefix = '[DagsterAuthKit]';
                if (level === 'error') {{
                    console.error(`${{prefix}} ❌ ${{msg}}`);
                }} else if (level === 'warn') {{
                    console.warn(`${{prefix}} ⚠️  ${{msg}}`);
                }} else {{
                    console.log(`${{prefix}} ${{msg}}`);
                }}
            }}
        }}

        function error(msg) {{
            console.error(`[DagsterAuthKit] ❌ ${{msg}}`);
        }}

        // Main injection function
        function injectUserMenu() {{
            log('Attempting UI injection... (attempt ' + (retryCount + 1) + '/' + MAX_RETRIES + ')');

            // Try multiple selectors (fallback strategy for version compatibility)
            const selectors = [
                'div[class*="MainNavigation_group"]',   // Dagster 1.12+ (primary)
                'div[class*="NavigationGroup"]',        // Dagster 1.10-1.11 (fallback 1)
                'nav[class*="Navigation"]',              // Generic navigation (fallback 2)
                'div[role="navigation"]',                // Accessibility fallback (fallback 3)
            ];

            let sidebarGroup = null;
            let usedSelector = null;

            for (const selector of selectors) {{
                const elements = document.querySelectorAll(selector);
                if (elements.length > 0) {{
                    // Get last group (bottom of sidebar, where settings usually is)
                    sidebarGroup = elements[elements.length - 1];
                    usedSelector = selector;
                    log(`Found sidebar via selector: ${{selector}}`);
                    break;
                }}
            }}

            // Sidebar not found
            if (!sidebarGroup) {{
                if (retryCount < MAX_RETRIES) {{
                    retryCount++;
                    log(`Sidebar not found, retry ${{retryCount}}/${{MAX_RETRIES}}`, 'warn');
                    setTimeout(injectUserMenu, RETRY_INTERVAL);
                    return;
                }} else {{
                    error('Sidebar not found after ' + MAX_RETRIES + ' retries');
                    if (SAFE_MODE) {{
                        log('Activating safe mode fallback', 'warn');
                        activateSafeMode();
                    }} else {{
                        error('Safe mode disabled - UI injection failed completely');
                    }}
                    return;
                }}
            }}

            // Check if already injected
            if (document.getElementById('authkit-nav-item')) {{
                log('User menu already injected, skipping');
                return;
            }}

            // Find reference elements for class cloning
            const itemContainer = sidebarGroup.querySelector('div[class*="itemContainer"]');
            const itemButton = sidebarGroup.querySelector('button[class*="itemButton"]');

            if (!itemContainer || !itemButton) {{
                error('Cannot find reference elements (itemContainer/itemButton) for styling');
                if (SAFE_MODE) {{
                    log('Activating safe mode fallback', 'warn');
                    activateSafeMode();
                }} else {{
                    error('Safe mode disabled - cannot style user menu');
                }}
                return;
            }}

            // Success - create user menu
            log('✅ Injecting user menu into sidebar');
            createUserMenu(sidebarGroup, itemContainer.className, itemButton.className);
        }}

        // Create native-style user menu
        function createUserMenu(sidebarGroup, containerClass, buttonClass) {{
            const itemContainer = document.createElement('div');
            itemContainer.id = 'authkit-nav-item';
            itemContainer.className = containerClass;

            itemContainer.innerHTML = 
                '<button id="authkit-trigger">' +
                    '<div class="authkit-box-proxy">' +
                        '<div class="authkit-avatar-circle">' + user.initial + '</div>' +
                        '<div class="authkit-label">' + user.full_name + '</div>' +
                    '</div>' +
                '</button>' +
                '<div class="authkit-popover" id="authkit-popover">' +
                    '<div class="authkit-header">' +
                        '<div style="font-weight: 600; color: var(--color-text-default, white);">' + user.full_name + '</div>' +
                        '<div style="font-size: 11px; color: #234AD1; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 700; margin-top: 2px;">' + user.role + '</div>' +
                        (user.has_email ? '<div style="font-size: 12px; color: #888; margin-top: 4px;">' + user.email + '</div>' : '') +
                    '</div>' +
                    '<a href="/auth/logout" class="authkit-item">Sign Out</a>' +
                '</div>';

            // Prepend to sidebar (top of bottom group)
            sidebarGroup.prepend(itemContainer);

            // Clone button class for native styling
            const trigger = document.getElementById('authkit-trigger');
            trigger.className = buttonClass;

            // Clone Box class for collapse behavior
            const boxProxy = itemContainer.querySelector('.authkit-box-proxy');
            const originalBox = sidebarGroup.querySelector('div[class*="Box_"]');
            if (originalBox) {{
                boxProxy.className = originalBox.className + ' authkit-box-proxy';
            }}

            log('✅ User menu created successfully');
            setupEventHandlers();
        }}

        // Safe mode fallback (top-right corner)
        function activateSafeMode() {{
            // Check if already activated
            if (document.getElementById('authkit-safe-mode-menu')) {{
                return;
            }}

            const fallbackMenu = document.createElement('div');
            fallbackMenu.id = 'authkit-safe-mode-menu';
            fallbackMenu.className = 'active';

            fallbackMenu.innerHTML = 
                '<div class="authkit-safe-avatar">' + user.initial + '</div>' +
                '<div class="authkit-safe-info">' + user.username + ' (' + user.role + ')</div>' +
                '<a href="/auth/logout" class="authkit-safe-logout">Sign Out</a>';

            document.body.appendChild(fallbackMenu);
            log('✅ Safe mode fallback activated (top-right corner)');
        }}

        // Event handlers
        function setupEventHandlers() {{
            const trigger = document.getElementById('authkit-trigger');
            const popover = document.getElementById('authkit-popover');

            if (!trigger || !popover) {{
                error('Cannot setup event handlers - elements not found');
                return;
            }}

            // Toggle popover on click
            trigger.onclick = (e) => {{
                e.stopPropagation();
                e.preventDefault();
                popover.classList.toggle('active');
                log('Popover toggled: ' + (popover.classList.contains('active') ? 'open' : 'closed'));
            }};

            // Close popover on outside click
            document.addEventListener('click', (e) => {{
                const container = document.getElementById('authkit-nav-item');
                if (popover && container && !container.contains(e.target)) {{
                    popover.classList.remove('active');
                }}
            }});

            // Close popover on Escape key
            document.addEventListener('keydown', (e) => {{
                if (e.key === 'Escape' && popover) {{
                    popover.classList.remove('active');
                }}
            }});

            log('✅ Event handlers setup complete');
        }}

        // Start injection
        log('DagsterAuthKit UI Injection initializing...');
        log('Config: DEBUG=' + DEBUG + ', SAFE_MODE=' + SAFE_MODE);

        if (document.readyState === 'loading') {{
            document.addEventListener('DOMContentLoaded', injectUserMenu);
        }} else {{
            injectUserMenu();
        }}

        // Also observe DOM changes (React lazy loading)
        const observer = new MutationObserver(injectUserMenu);
        observer.observe(document.body, {{ childList: true, subtree: true }});
    }})();
    </script>
    """


def verify_patches() -> bool:
    """
    Verify patches were applied successfully.

    Returns:
        bool: True if patches are active, False otherwise
    """
    try:
        import dagster_webserver.webserver as webserver_module

        # Check if our patched method exists
        has_middleware = hasattr(webserver_module.DagsterWebserver, "build_middleware")
        has_routes = hasattr(webserver_module.DagsterWebserver, "build_routes")
        has_index = hasattr(webserver_module.DagsterWebserver, "index_html_endpoint")

        return has_middleware and has_routes and has_index
    except Exception as e:
        logger.error(f"Patch verification failed: {e}")
        return False