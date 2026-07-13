"""
OAuth Authentication Backend (Placeholder)

This backend is not yet implemented. It is reserved for future use
with OAuth2/OIDC providers (Google, GitHub, Okta, Keycloak, etc.).

To use OAuth authentication, set DAGSTER_AUTH_BACKEND=oauth and configure
the OAuth provider settings via environment variables.
"""

import logging
from typing import Any, Dict, List, Optional

from dagster_authkit.auth.backends.base import AuthBackend, AuthUser, Role

logger = logging.getLogger(__name__)


class OAuthBackend(AuthBackend):
    """
    OAuth2/OIDC authentication backend (NOT YET IMPLEMENTED).

    Reserved for future implementation supporting:
    - Authorization Code flow with PKCE
    - OpenID Connect discovery
    - Multiple providers (Google, GitHub, Okta, Keycloak)
    - JWT token validation
    - Role mapping from claims/groups

    To contribute: https://github.com/maltzsama/dagster-authkit
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        logger.warning(
            "OAuthBackend is not yet implemented. " "OAuth support is planned for a future release."
        )

    def get_name(self) -> str:
        return "oauth"

    def authenticate(self, username: str, password: str) -> Optional[AuthUser]:
        raise NotImplementedError(
            "OAuthBackend does not support password authentication. "
            "OAuth uses browser-based authorization flows."
        )

    def get_user(self, username: str) -> Optional[AuthUser]:
        raise NotImplementedError(
            "OAuthBackend does not support direct user lookup. "
            "User data is obtained from the OAuth provider's userinfo endpoint."
        )
