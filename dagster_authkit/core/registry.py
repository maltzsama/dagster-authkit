"""
Backend Registry - Plugin Discovery System

Discovers and instantiates backends via entry points (setuptools).
Allows external plugins without modifying core code.
"""

import logging
from importlib.metadata import entry_points
from typing import Any, Dict, Type

from dagster_authkit.auth.backends.base import AuthBackend

logger = logging.getLogger(__name__)


class BackendRegistry:
    """
    Registry for authentication backends.

    Discovers backends automatically via entry points defined
    in 'dagster_auth.backends' in installed packages' pyproject.toml.
    """

    _backends: Dict[str, Type[AuthBackend]] = {}
    _initialized: bool = False

    @classmethod
    def discover_backends(cls) -> None:
        """
        Discovers all registered backends via entry points.

        Entry point format (pyproject.toml):
            [project.entry-points."dagster_auth.backends"]
            dummy = "dagster_authkit.auth.backends.dummy:DummyAuthBackend"
            sqlite = "dagster_authkit.auth.backends.sqlite:SQLiteAuthBackend"
        """
        if cls._initialized:
            return

        logger.info("🔍 Discovering authentication backends...")

        try:
            # Python 3.10+ API
            discovered = entry_points(group="dagster_auth.backends")
        except TypeError:
            # Python 3.9 fallback
            all_eps = entry_points()
            discovered = all_eps.get("dagster_auth.backends", [])

        for entry_point in discovered:
            try:
                backend_class = entry_point.load()

                # Validate it's a proper AuthBackend subclass
                if not issubclass(backend_class, AuthBackend):
                    logger.warning(
                        f"⚠️  Backend '{entry_point.name}' is not a subclass of AuthBackend, skipping"
                    )
                    continue

                cls._backends[entry_point.name] = backend_class
                logger.info(f"✅ Registered backend: {entry_point.name}")

            except Exception as e:
                logger.error(f"❌ Failed to load backend '{entry_point.name}': {e}")

        cls._initialized = True

        if cls._backends:
            logger.info(f"🎉 Backend discovery complete. Available: {list(cls._backends.keys())}")
        else:
            logger.warning("⚠️  No backends discovered! Check entry points configuration.")

    @classmethod
    def get_backend(cls, name: str, config: Dict[str, Any]) -> AuthBackend:
        """
        Instantiates a backend by name.

        Args:
            name: Backend name (sqlite, ldap, oauth, dummy)
            config: Configuration to pass to backend (usually config.__dict__)

        Returns:
            Initialized AuthBackend instance

        Raises:
            ValueError: If backend doesn't exist

        Example:
            >>> from dagster_authkit.core.registry import get_backend
            >>> from dagster_authkit.utils.config import config
            >>> backend = get_backend('sqlite', config.__dict__)
            >>> user = backend.authenticate('admin', 'password123')
        """
        # Ensure backends are discovered
        if not cls._initialized:
            cls.discover_backends()

        # Check if backend exists
        if name not in cls._backends:
            available = ", ".join(cls._backends.keys()) if cls._backends else "none"
            raise ValueError(
                f"❌ Unknown backend: '{name}'. "
                f"Available backends: {available}. "
                f"Check pyproject.toml [project.entry-points] configuration."
            )

        backend_class = cls._backends[name]

        try:
            backend = backend_class(config)
            logger.info(f"✅ Initialized backend: {name} ({backend.get_name()})")
            return backend
        except Exception as e:
            logger.error(f"❌ Failed to initialize backend '{name}': {e}", exc_info=True)
            raise RuntimeError(f"Backend initialization failed: {e}") from e

    @classmethod
    def list_backends(cls) -> list:
        """
        Lists all available backends (discovered via entry points).

        Returns:
            List of backend names

        Example:
            >>> from dagster_authkit.core.registry import list_available_backends
            >>> print(list_available_backends())
            ['dummy', 'sqlite', 'ldap']
        """
        if not cls._initialized:
            cls.discover_backends()

        return sorted(cls._backends.keys())

    @classmethod
    def reset(cls) -> None:
        """
        Resets registry (useful for tests).

        Clears all discovered backends and forces re-discovery
        on next call.
        """
        cls._backends.clear()
        cls._initialized = False
        logger.debug("🔄 Backend registry reset")


# ========================================
# Convenience Functions
# ========================================


def get_backend(name: str, config: Dict[str, Any]) -> AuthBackend:
    """
    Convenience function to get backend.

    Args:
        name: Backend name
        config: Configuration

    Returns:
        AuthBackend instance

    Example:
        >>> backend = get_backend('dummy', {})
        >>> user = backend.authenticate('admin', 'admin')
    """
    return BackendRegistry.get_backend(name, config)


def list_available_backends() -> list:
    """
    Lists all available backends.

    Returns:
        List of names

    Example:
        >>> backends = list_available_backends()
        >>> print(f"Available: {backends}")
    """
    return BackendRegistry.list_backends()