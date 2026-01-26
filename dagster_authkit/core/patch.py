"""
Dagster Monkey-Patching Module - "Native Infiltration" Edition

Injects the user profile as a native item within the Dagster utility group,
replicating internal classes and behavior to ensure a perfect visual fit.
"""

import logging
import json
from typing import Callable

from starlette.requests import Request
from starlette.responses import HTMLResponse

logger = logging.getLogger(__name__)

original_index_html = None


def apply_patches() -> None:
    logger.info("🔧 Applying native-mimicry UI patches for Dagster...")

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

    # PATCH 3: UI Hijacking (Infiltration)
    try:
        original_index_html = webserver_module.DagsterWebserver.index_html_endpoint

        def patched_index_html_wrapper(self, request: Request):
            return _inject_ui_logic(self, request)

        webserver_module.DagsterWebserver.index_html_endpoint = patched_index_html_wrapper
    except Exception as e:
        logger.error(f"❌ UI patch failed: {e}")


def _inject_ui_logic(self, request: Request):
    response = original_index_html(self, request)

    # 1. Resgate seguro dos dados
    user = getattr(request.state, "user", {})

    # 2. Lógica de Fallback Robusta no Python
    username = user.get("username") or "guest"
    full_name = user.get("full_name") or username.capitalize()
    email = user.get("email") or ""
    roles = user.get("roles", ["viewer"])
    role_display = roles[0].upper() if roles else "VIEWER"
    initial = (full_name[0] if full_name else username[0]).upper()

    # 3. Serialização limpa para o JS
    user_data_json = json.dumps(
        {
            "full_name": full_name,
            "email": email,
            "role": role_display,
            "initial": initial,
            "has_email": bool(email),
        }
    )

    injection = rf"""
    <style>
        .authkit-popover {{
            display: none;
            position: fixed;
            bottom: 65px;
            left: 12px;
            width: 250px;
            background: #1a1d29;
            border-radius: 8px;
            border: 1px solid rgba(255, 255, 255, 0.15);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.5);
            z-index: 10000;
        }}
        .authkit-popover.active {{
            display: block;
        }}
        .authkit-header {{
            padding: 12px 16px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }}
        .authkit-avatar-circle {{
            width: 20px;
            height: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 600;
            color: white;
            font-size: 10px;
            flex-shrink: 0;
        }}
        .authkit-item {{
            padding: 10px 16px;
            display: block;
            color: #ccc;
            text-decoration: none;
            font-size: 14px;
            transition: background-color 0.2s;
        }}
        .authkit-item:hover {{
            background-color: rgba(255, 255, 255, 0.05);
        }}
    </style>

    <script>
        (function() {{
            const u = {user_data_json};
            
            function infiltrate() {{
                const groups = document.querySelectorAll('div[class*="MainNavigation_group"]');
                const targetGroup = groups[groups.length - 1];
                
                if (!targetGroup || document.getElementById('authkit-nav-item')) return;

                const itemContainer = document.createElement('div');
                itemContainer.id = 'authkit-nav-item';
                
                const sibling = targetGroup.querySelector('div[class*="itemContainer"]');
                if (sibling) itemContainer.className = sibling.className;

                // HTML com concatenação correta (sem template strings problemáticas)
                itemContainer.innerHTML = 
                    '<button id="authkit-trigger" style="background:transparent; border:none; padding:0; width:100%; cursor:pointer; color:inherit;">' +
                        '<div class="authkit-box-proxy" style="display:flex; align-items:center; gap:8px; padding:8px 12px;">' +
                            '<div class="authkit-avatar-circle">' + u.initial + '</div>' +
                            '<div class="authkit-label" style="flex:1; text-align:left; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-size:14px;">' +
                                u.full_name +
                            '</div>' +
                        '</div>' +
                    '</button>' +
                    '<div class="authkit-popover" id="authkit-popover">' +
                        '<div class="authkit-header">' +
                            '<div style="font-weight: 600; color: white;">' + u.full_name + '</div>' +
                            '<div style="font-size: 11px; color: #667eea; text-transform: uppercase; letter-spacing: 0.5px; margin-top: 2px;">' + u.role + '</div>' +
                            (u.has_email ? '<div style="font-size: 12px; color: #888; margin-top: 4px;">' + u.email + '</div>' : '') +
                        '</div>' +
                        '<a href="/auth/logout" class="authkit-item" style="color:#ff6b6b;">Sign Out</a>' +
                    '</div>';

                targetGroup.prepend(itemContainer);

                // Clone de estilos do botão de Settings para manter consistência visual
                const settingsBtn = targetGroup.querySelector('button[class*="itemButton"]');
                if (settingsBtn) {{
                    const trigger = document.getElementById('authkit-trigger');
                    trigger.className = settingsBtn.className;
                    // Copiar classes do container interno para alinhamento perfeito
                    const boxProxy = itemContainer.querySelector('.authkit-box-proxy');
                    const originalBox = settingsBtn.querySelector('div[class*="Box_"]');
                    if (originalBox) {{
                        boxProxy.className = originalBox.className + ' authkit-box-proxy';
                    }}
                }}

                // Event handlers
                const trigger = document.getElementById('authkit-trigger');
                const popover = document.getElementById('authkit-popover');
                
                trigger.addEventListener('click', (e) => {{
                    e.stopPropagation();
                    e.preventDefault();
                    popover.classList.toggle('active');
                }});
                
                // Fechar popover ao clicar fora
                document.addEventListener('click', (e) => {{
                    if (popover && !itemContainer.contains(e.target)) {{
                        popover.classList.remove('active');
                    }}
                }});
                
                // Fechar com Escape key
                document.addEventListener('keydown', (e) => {{
                    if (e.key === 'Escape' && popover) {{
                        popover.classList.remove('active');
                    }}
                }});
                
                // Fechar ao navegar (clicar em links do popover)
                popover.querySelectorAll('a').forEach(link => {{
                    link.addEventListener('click', () => {{
                        popover.classList.remove('active');
                    }});
                }});
            }}

            // Executar quando o DOM estiver pronto
            if (document.readyState === 'loading') {{
                document.addEventListener('DOMContentLoaded', infiltrate);
            }} else {{
                infiltrate();
            }}
            
            // Observar mudanças no DOM (sidebar pode ser carregada dinamicamente)
            const observer = new MutationObserver(infiltrate);
            observer.observe(document.body, {{ childList: true, subtree: true }});
            
            // Fallback: tentar novamente após 500ms se não encontrou
            setTimeout(infiltrate, 500);
        }})();
    </script>
    """

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
