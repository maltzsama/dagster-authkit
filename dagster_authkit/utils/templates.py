"""
HTML Templates - Centralized UI Components
All HTML/CSS/JS strings for AuthKit interface.
"""


def render_login_page(next_url: str = "/", error: str = "") -> str:
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
    return html


def render_403_page(user, path: str, method: str, reason: str) -> str:
    html = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>403 Forbidden</title>
                <style>
                    body {{
                        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
                        background-color: #0f111a;
                        color: white;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        height: 100vh;
                        margin: 0;
                    }}
                    .container {{
                        text-align: center;
                        border: 1px solid #333;
                        padding: 40px;
                        border-radius: 12px;
                        background: #1a1d29;
                        max-width: 500px;
                    }}
                    h1 {{ color: #ff6b6b; margin: 0 0 20px 0; }}
                    .info {{ color: #888; margin: 10px 0; }}
                    .detail {{ font-size: 12px; color: #555; margin-top: 20px; }}
                    a {{ color: #667eea; text-decoration: none; margin-top: 20px; display: inline-block; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>🔒 403 Forbidden</h1>
                    <p class="info">
                        User <strong>{user.username}</strong> (role: <strong>{user.role.name}</strong>)
                        cannot <strong>{method}</strong> on <strong>{path}</strong>.
                    </p>
                    <p class="detail">Reason: {reason}</p>
                    <a href="/">← Return to Dashboard</a>
                </div>
            </body>
            </html>
            """
    return html


def render_user_menu_injection(user_data_json: str, debug: bool, safe_mode: bool) -> str:
    html = f"""
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
    return html
