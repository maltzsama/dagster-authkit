"""
Session Management
Supports Stateless (Signed Cookies) and Stateful (Redis) backends.
"""

import json
import logging
import os
import secrets
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from itsdangerous import URLSafeTimedSerializer

logger = logging.getLogger(__name__)

# --- Interfaces ---

class SessionBackend(ABC):
    @abstractmethod
    def create(self, user_data: Dict[str, Any]) -> str: ...

    @abstractmethod
    def validate(self, token: str) -> Optional[Dict[str, Any]]: ...

    @abstractmethod
    def revoke(self, token: str) -> bool: ...  # O QUE FALTAVA

    @abstractmethod
    def revoke_all(self, username: str) -> int: ...


# --- Implementations ---

class RedisBackend(SessionBackend):
    def __init__(self, redis_url: str, max_age: int):
        import redis
        self.client = redis.from_url(redis_url, decode_responses=True)
        self.max_age = max_age

    def create(self, user_data: Dict[str, Any]) -> str:
        token = secrets.token_urlsafe(32)
        username = user_data["username"]
        # Map token to data
        self.client.setex(f"sess:{token}", self.max_age, json.dumps(user_data))
        # Map user to all their tokens (for global revoke)
        self.client.sadd(f"user_sess:{username}", token)
        return token

    def validate(self, token: str) -> Optional[Dict[str, Any]]:
        data = self.client.get(f"sess:{token}")
        return json.loads(data) if data else None

    def revoke(self, token: str) -> bool:
        """Revokes a single session."""
        data = self.validate(token)
        if data:
            username = data.get("username")
            # Clean up the user's token set
            self.client.srem(f"user_sess:{username}", token)

        return bool(self.client.delete(f"sess:{token}"))

    def revoke_all(self, username: str) -> int:
        key = f"user_sess:{username}"
        tokens = self.client.smembers(key)
        for t in tokens:
            self.client.delete(f"sess:{t}")
        return self.client.delete(key)


class CookieBackend(SessionBackend):
    """Stateless but with versioning for global revocation."""

    def __init__(self, secret_key: str, max_age: int):
        self.serializer = URLSafeTimedSerializer(secret_key)
        self.max_age = max_age
        self._versions: Dict[str, int] = {}

    def create(self, user_data: Dict[str, Any]) -> str:
        v = self._versions.get(user_data["username"], 1)
        return self.serializer.dumps({**user_data, "_v": v})

    def validate(self, token: str) -> Optional[Dict[str, Any]]:
        try:
            data = self.serializer.loads(token, max_age=self.max_age)
            if data.get("_v") != self._versions.get(data.get("username"), 1):
                return None
            return data
        except:
            return None

    def revoke(self, token: str) -> bool:
        """Stateless: nothing to do server-side, browser deletes the cookie."""
        return True

    def revoke_all(self, username: str) -> int:
        self._versions[username] = self._versions.get(username, 1) + 1
        return 1


# --- The Orchestrator ---

class SessionManager:
    def __init__(self):
        from dagster_authkit.utils.config import config

        # Priority to REDIS_URL in config/env
        redis_url = getattr(config, "REDIS_URL", os.getenv("DAGSTER_AUTH_REDIS_URL"))

        if redis_url:
            self.backend = RedisBackend(redis_url, config.SESSION_MAX_AGE)
            logger.info("SessionManager: Using Redis (Stateful)")
        else:
            self.backend = CookieBackend(config.SECRET_KEY, config.SESSION_MAX_AGE)
            logger.info("SessionManager: Using Signed Cookies (Stateless)")

    def create(self, user_data: Dict[str, Any]) -> str:
        return self.backend.create(user_data)

    def validate(self, token: str) -> Optional[Dict[str, Any]]:
        return self.backend.validate(token)

    def revoke(self, token: str) -> bool:
        """Individual session logout bridge."""
        return self.backend.revoke(token)

    def revoke_all(self, username: str) -> int:
        return self.backend.revoke_all(username)


sessions = SessionManager()