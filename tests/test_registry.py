"""
Unit tests for core/registry.py

Covers:
- BackendRegistry discovery via entry points
- get_backend instantiation
- list_backends enumeration
- Reset for test isolation
- Unknown backend error handling
"""

import pytest

from dagster_authkit.auth.backends.base import AuthBackend
from dagster_authkit.core.registry import (
    BackendRegistry,
    get_backend,
    list_available_backends,
)


@pytest.fixture(autouse=True)
def reset_registry():
    """Reset the backend registry before each test for isolation."""
    BackendRegistry.reset()
    yield
    BackendRegistry.reset()


class TestBackendRegistry:
    """Verifies the BackendRegistry class."""

    def test_discover_backends_registers_dummy(self):
        """Discovery should find the 'dummy' backend."""
        BackendRegistry.discover_backends()
        backends = BackendRegistry.list_backends()
        assert "dummy" in backends

    def test_discover_backends_registers_sql(self):
        """Discovery should find the 'sql' backend."""
        BackendRegistry.discover_backends()
        backends = BackendRegistry.list_backends()
        assert "sql" in backends

    def test_discover_is_idempotent(self):
        """Calling discover multiple times should not duplicate backends."""
        BackendRegistry.discover_backends()
        first = BackendRegistry.list_backends()
        BackendRegistry.discover_backends()
        second = BackendRegistry.list_backends()
        assert first == second

    def test_get_backend_dummy(self):
        """get_backend should instantiate a DummyAuthBackend."""
        backend = BackendRegistry.get_backend("dummy", {})
        assert backend is not None
        assert backend.get_name() == "dummy"

    def test_get_backend_unknown_raises(self):
        """Requesting an unknown backend should raise ValueError."""
        with pytest.raises(ValueError, match="Unknown backend"):
            BackendRegistry.get_backend("nonexistent", {})

    def test_list_backends_returns_sorted_list(self):
        """list_backends should return a sorted list of backend names."""
        backends = BackendRegistry.list_backends()
        assert isinstance(backends, list)
        assert backends == sorted(backends)

    def test_reset_clears_backends(self):
        """reset should clear internal state, then re-discover on next access."""
        BackendRegistry.discover_backends()
        assert len(BackendRegistry._backends) > 0
        BackendRegistry.reset()
        # After reset, internal state is empty until next discovery
        assert len(BackendRegistry._backends) == 0
        assert BackendRegistry._initialized is False
        # Calling list_backends triggers re-discovery
        assert len(BackendRegistry.list_backends()) > 0


class TestConvenienceFunctions:
    """Verifies module-level convenience functions."""

    def test_get_backend_returns_auth_backend(self):
        """get_backend should return an AuthBackend subclass."""
        backend = get_backend("dummy", {})
        assert isinstance(backend, AuthBackend)

    def test_list_available_backends_includes_dummy(self):
        """list_available_backends should include 'dummy'."""
        backends = list_available_backends()
        assert "dummy" in backends


class TestBackendRegistryEdgeCases:
    """Verifies edge cases in the BackendRegistry."""

    def test_get_backend_caches_instance(self):
        """Multiple calls to get_backend should return the same cached instance."""
        backend1 = BackendRegistry.get_backend("dummy", {})
        backend2 = BackendRegistry.get_backend("dummy", {"OTHER": "config"})
        assert backend1 is backend2

    def test_get_backend_init_failure_raises(self, monkeypatch):
        """If backend initialization fails, should raise RuntimeError."""
        BackendRegistry.discover_backends()

        def raiser(config):
            raise ValueError("Init error")

        monkeypatch.setitem(BackendRegistry._backends, "dummy", raiser)
        # Reset instance cache so it tries to init again
        BackendRegistry._instances.clear()

        with pytest.raises(RuntimeError, match="Backend initialization failed"):
            BackendRegistry.get_backend("dummy", {})

    def test_list_backends_triggers_discovery(self):
        """list_backends should trigger discovery if not yet initialized."""
        BackendRegistry.reset()
        assert not BackendRegistry._initialized
        backends = BackendRegistry.list_backends()
        assert len(backends) > 0
        assert BackendRegistry._initialized

    def test_reset_clears_instances(self):
        """reset should clear cached instances too."""
        BackendRegistry.get_backend("dummy", {})
        assert len(BackendRegistry._instances) > 0
        BackendRegistry.reset()
        assert len(BackendRegistry._instances) == 0
