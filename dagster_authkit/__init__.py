"""
dagster-authkit

Production-ready authentication and UI orchestration for Dagster OSS.
"""

__version__ = "0.3.0"

# Export public API - All comments in English as requested
from .utils.config import config
from .core.registry import get_backend, list_available_backends
from .auth.backends.base import AuthBackend

# Primary entrypoints for the package
__all__ = [
    "__version__",
    "AuthBackend",
    "get_backend",
    "list_available_backends",
    "config",
]