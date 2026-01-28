"""
dagster-authkit

Production-ready authentication and UI orchestration for Dagster OSS.
"""

__version__ = "0.2.0"

from .auth.backends.base import AuthBackend
from .core.registry import get_backend, list_available_backends

# Export public API - All comments in English as requested
from .utils.config import config

# Primary entrypoints for the package
__all__ = [
    "__version__",
    "AuthBackend",
    "get_backend",
    "list_available_backends",
    "config",
]
