"""
Session Management
Supports Stateless (Signed Cookies) and Stateful (Redis) backends.
"""

import json
import logging
import os
import secrets
import time
import threading
from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, Optional

from itsdangerous import URLSafeTimedSerializer

logger = logging.getLogger(__name__)


class SessionBackend(ABC):
    """
    Abstract base class for session storage backends.

    Implementations:
    - ``RedisBackend``: Stateful, multi-pod safe, stores sessions in Redis.
    - ``CookieBackend``: Stateless signed cookies with optional
      DB-backed session versioning for cross-pod revocation.
    """

    @abstractmethod
    def create(self, user_data: Dict[str, Any]) -> str:
        """
        Persist a new session.

        Args:
            user_data: Dict with ``username``, ``role``, ``email``, ``full_name``.

        Returns:
            Opaque session token string to be set as a cookie.
        """
        ...

    @abstractmethod
    def validate(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Validate a session token.

        Args:
            token: Opaque session token (from cookie).

        Returns:
            Original ``user_data`` dict if valid, ``None`` otherwise.
        """
        ...

    @abstractmethod
    def revoke(self, token: str) -> bool:
        """
        Revoke a single session token.

        Args:
            token: Session token to invalidate.

        Returns:
            ``True`` if the token existed and was revoked.
        """
        ...

    @abstractmethod
    def revoke_all(self, username: str) -> int:
        """
        Revoke ALL active sessions for a user.

        Args:
            username: User whose sessions should be terminated.

        Returns:
            Number of sessions revoked.
        """
        ...


class RedisBackend(SessionBackend):
    """
    Redis-based session storage (stateful, multi-pod safe).

    Uses ``SETEX`` for token storage and Redis ``SET`` for per-user
    token indexing, enabling efficient ``revoke_all``.

    Args:
        redis_url: Redis connection URL (``redis://`` or ``rediss://``).
        max_age:   Session TTL in seconds.
    """

    def __init__(self, redis_url: str, max_age: int):
        """Initialise Redis connection."""
        import redis

        self.client = redis.from_url(redis_url, decode_responses=True)
        self.max_age = max_age

    def create(self, user_data: Dict[str, Any]) -> str:
        token = secrets.token_urlsafe(32)
        username = user_data["username"]
        self.client.setex(f"sess:{token}", self.max_age, json.dumps(user_data))
        self.client.sadd(f"user_sess:{username}", token)
        return token

    def validate(self, token: str) -> Optional[Dict[str, Any]]:
        data = self.client.get(f"sess:{token}")
        return json.loads(data) if data else None

    def revoke(self, token: str) -> bool:
        key = f"sess:{token}"
        data_str = self.client.get(key)
        if data_str:
            try:
                data = json.loads(data_str)
                username = data.get("username")
                if username:
                    self.client.srem(f"user_sess:{username}", token)
            except Exception as e:
                logger.warning(f"Failed to parse session data during revoke: {e}")
        deleted = self.client.delete(key)
        return bool(deleted)

    def revoke_all(self, username: str) -> int:
        key = f"user_sess:{username}"
        tokens = self.client.smembers(key)
        for t in tokens:
            self.client.delete(f"sess:{t}")
        return self.client.delete(key)


class CookieBackend(SessionBackend):
    """
    Stateless signed-cookie sessions with optional DB-backed versioning.

    Version resolution is lazy: the first ``create()`` or ``validate()``
    call attempts to resolve a version getter from the SQL backend. If
    successful, ``revoke_all`` becomes multi-pod safe via the database.

    Individual ``revoke()`` is always process-local (best-effort without Redis).

    Args:
        secret_key: HMAC signing secret for cookie serialization.
        max_age:    Session TTL in seconds.
    """

    _VERSION_CACHE_TTL = 10.0  # seconds

    def __init__(self, secret_key: str, max_age: int):
        self.serializer = URLSafeTimedSerializer(secret_key)
        self.max_age = max_age
        self._versions: Dict[str, int] = {}
        self._revoked: Dict[str, float] = {}
        self._version_cache: Dict[str, tuple] = {}
        self._lock = threading.Lock()
        self._version_getter: Optional[Callable] = None
        self._version_getter_resolved: bool = False

    def _resolve_version_getter(self) -> None:
        """Lazily build a DB-backed session version getter based on config.

        No DB probing is done here — the decision is purely config-based.
        Runtime DB errors are handled fail-closed by _current_version().
        """
        if self._version_getter_resolved:
            return
        self._version_getter_resolved = True

        from dagster_authkit.utils.config import config

        if config.AUTH_BACKEND not in ("sql", "sqlite"):
            logger.warning(
                f"CookieBackend: AUTH_BACKEND={config.AUTH_BACKEND} does not "
                "support DB-backed session versioning. "
                "Session revocation is single-pod only."
            )
            return

        try:
            from dagster_authkit.auth.backends.sql import PeeweeAuthBackend

            self._version_getter = PeeweeAuthBackend.get_session_version
            logger.info(
                "CookieBackend: DB-backed session version enabled "
                "(multi-pod safe for revoke_all; individual logout is best-effort)"
            )
        except ImportError as e:
            logger.error(
                f"CookieBackend: Failed to import SQL backend for version getter: {e}. "
                "Session revocation will be single-pod only.",
                exc_info=True,
            )

    def _current_version(self, username: str) -> Optional[int]:
        """Get the current session version for a user.

        Uses DB (with TTL cache) when version_getter is available.
        Falls back to in-memory only when no getter was ever resolved.

        Returns None when DB-backed and the DB call fails — callers must
        reject the session (fail-closed).
        """
        self._resolve_version_getter()

        if self._version_getter is not None:
            now = time.time()
            with self._lock:
                cached = self._version_cache.get(username)
                if cached is not None and (now - cached[1]) < self._VERSION_CACHE_TTL:
                    return cached[0]

            try:
                db_version = self._version_getter(username)
                with self._lock:
                    self._version_cache[username] = (db_version, time.time())
                return db_version
            except Exception as e:
                logger.error(
                    f"DB unavailable for session version of '{username}': {e}. "
                    "Rejecting session (fail-closed).",
                    exc_info=True,
                )
                return None

        return self._versions.get(username, 1)

    def create(self, user_data: Dict[str, Any]) -> str:
        username = user_data["username"]
        v = self._current_version(username)
        if v is None:
            # DB unavailable — issue a cookie with in-memory version.
            # It will be rejected on validate() until the DB recovers,
            # but at least the login succeeds and the user sees a clear error.
            v = self._versions.get(username, 1)
        return self.serializer.dumps({**user_data, "_v": v})

    def validate(self, token: str) -> Optional[Dict[str, Any]]:
        try:
            data = self.serializer.loads(token, max_age=self.max_age)
            username = data.get("username")
            if not username:
                return None

            current_version = self._current_version(username)
            if current_version is None:
                return None
            if data.get("_v") != current_version:
                return None

            with self._lock:
                if token in self._revoked:
                    if time.time() >= self._revoked[token]:
                        del self._revoked[token]
                    else:
                        return None

            return data
        except Exception:
            logger.warning("Session validation failed", exc_info=True)
            return None

    def revoke(self, token: str) -> bool:
        """Revoke a single token (process-local only).

        Without Redis, individual logout only affects the current pod.
        The token remains valid on other pods until it expires naturally.
        For cross-pod individual logout, use RedisBackend."""
        try:
            data = self.serializer.loads(token, max_age=self.max_age)
            expiry = time.time() + self.max_age
        except Exception:
            expiry = time.time() + self.max_age

        with self._lock:
            self._revoked[token] = expiry
        self._prune_expired_revocations()
        return True

    def _prune_expired_revocations(self) -> None:
        now = time.time()
        with self._lock:
            expired = [t for t, exp in self._revoked.items() if now >= exp]
            for t in expired:
                del self._revoked[t]

    def revoke_all(self, username: str) -> int:
        """Invalidate all sessions for a user.

        When DB-backed: raises NotImplementedError. The caller must use
        PeeweeAuthBackend._bump_session_version() which bumps the DB column
        directly. Session propagation delay is up to VERSION_CACHE_TTL (10s).

        When in-memory (single-pod): bumps the local counter immediately.
        """
        self._resolve_version_getter()
        if self._version_getter is not None:
            raise NotImplementedError(
                "CookieBackend.revoke_all() is not supported in DB-backed mode. "
                "Use PeeweeAuthBackend._bump_session_version() to bump the "
                "session_version column in the database directly. Sessions are "
                "invalidated within 10s (cache TTL)."
            )
        self._versions[username] = self._versions.get(username, 1) + 1
        return 1


class SessionManager:
    """
    Facade that auto-selects the session backend based on configuration.

    - If ``DAGSTER_AUTH_REDIS_URL`` is set: uses ``RedisBackend``.
    - Otherwise: uses ``CookieBackend`` (stateless signed cookies with
      optional DB-backed session versioning for SQL backends).

    Usage::

        token = sessions.create(user.to_dict())
        user_data = sessions.validate(token)
        sessions.revoke(token)
    """

    def __init__(self):
        """Initialise and auto-select the session backend."""
        from dagster_authkit.utils.config import config

        redis_url = getattr(config, "REDIS_URL", os.getenv("DAGSTER_AUTH_REDIS_URL"))

        if redis_url:
            self.backend = RedisBackend(redis_url, config.SESSION_MAX_AGE)
            logger.info("SessionManager: Redis (Stateful, multi-pod safe)")
        else:
            self.backend = CookieBackend(config.SECRET_KEY, config.SESSION_MAX_AGE)
            logger.info("SessionManager: Signed Cookies (DB version resolved lazily)")

    def create(self, user_data: Dict[str, Any]) -> str:
        return self.backend.create(user_data)

    def validate(self, token: str) -> Optional[Dict[str, Any]]:
        return self.backend.validate(token)

    def revoke(self, token: str) -> bool:
        return self.backend.revoke(token)

    def revoke_all(self, username: str) -> int:
        return self.backend.revoke_all(username)


sessions = SessionManager()
