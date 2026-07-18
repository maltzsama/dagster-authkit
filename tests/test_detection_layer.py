import builtins
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def _mock_starlette_middleware(monkeypatch):
    """Starlette 1.3.1 Middleware has .cls/.args/.kwargs, not .func.
    Mock it so the compatibility check passes (or fails predictably)."""
    import starlette.middleware
    mw_instance = MagicMock()
    mw_instance.func = object()
    monkeypatch.setattr(
        starlette.middleware, "Middleware",
        lambda *args, **kwargs: mw_instance,
    )


from dagster_authkit.core.detection_layer import (
    check_and_exit_if_incompatible,
    get_compatibility_report,
    print_compatibility_warning,
    verify_dagster_api_compatibility,
)


# ── verify_dagster_api_compatibility ──────────────────────────────────────


class TestVerifyCompatibility:
    def test_success(self):
        with (
            patch("dagster_webserver.webserver.DagsterWebserver") as ws_cls,
        ):
            ws_cls.build_middleware = MagicMock()
            ws_cls.build_routes = MagicMock()

            ok, err = verify_dagster_api_compatibility()
        assert ok is True
        assert err is None

    def test_import_error(self, monkeypatch):
        original_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "dagster":
                raise ImportError("No module named dagster")
            return original_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)
        ok, err = verify_dagster_api_compatibility()
        assert ok is False
        assert "Cannot import" in err

    def test_missing_webserver_export(self, monkeypatch):
        import dagster_webserver.webserver
        monkeypatch.delattr(dagster_webserver.webserver, "DagsterWebserver", raising=False)
        ok, err = verify_dagster_api_compatibility()
        assert ok is False
        assert "Missing exports" in err

    def test_missing_method_on_webserver(self, monkeypatch):
        import dagster_webserver.webserver
        from unittest.mock import Mock
        fake_cls = Mock(spec=["build_middleware"])
        fake_cls.build_middleware = MagicMock()
        monkeypatch.setattr(dagster_webserver.webserver, "DagsterWebserver", fake_cls)
        ok, err = verify_dagster_api_compatibility()
        assert ok is False
        assert "Missing methods" in err

    def test_starlette_middleware_failure(self, monkeypatch):
        import starlette.middleware

        def broken_middleware(*args, **kwargs):
            raise RuntimeError("Bad middleware")

        monkeypatch.setattr(starlette.middleware, "Middleware", broken_middleware)

        with (
            patch("dagster_webserver.webserver.DagsterWebserver") as ws_cls,
        ):
            ws_cls.build_middleware = MagicMock()
            ws_cls.build_routes = MagicMock()

            ok, err = verify_dagster_api_compatibility()
            assert ok is False
            assert "Starlette middleware" in err


# ── get_compatibility_report ──────────────────────────────────────────────


class TestGetCompatibilityReport:
    def test_dagster_not_installed(self, monkeypatch):
        original_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "dagster":
                raise ImportError("No module named dagster")
            return original_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)
        report = get_compatibility_report()
        assert "Dagster not installed" in report

    def test_compatible(self):
        with (
            patch("dagster_webserver.webserver.DagsterWebserver") as ws_cls,
        ):
            ws_cls.build_middleware = MagicMock()
            ws_cls.build_routes = MagicMock()

            report = get_compatibility_report()
        assert "COMPATIBLE" in report
        assert "AuthKit should work correctly" in report

    def test_incompatible(self):
        with (
            patch("dagster_webserver.webserver.DagsterWebserver", new=None),
        ):
            report = get_compatibility_report()
        assert "INCOMPATIBLE" in report
        assert "Action Required" in report

    def test_includes_authkit_version(self):
        with (
            patch("dagster_webserver.webserver.DagsterWebserver") as ws_cls,
        ):
            ws_cls.build_middleware = MagicMock()
            ws_cls.build_routes = MagicMock()

            report = get_compatibility_report()
        assert "0.4.0" in report


# ── print_compatibility_warning ───────────────────────────────────────────


class TestPrintCompatibilityWarning:
    def test_compatible_prints_nothing(self, capsys):
        with (
            patch("dagster_webserver.webserver.DagsterWebserver") as ws_cls,
        ):
            ws_cls.build_middleware = MagicMock()
            ws_cls.build_routes = MagicMock()

            print_compatibility_warning()
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_incompatible_prints_warning(self, capsys):
        with (
            patch("dagster_webserver.webserver.DagsterWebserver", new=None),
        ):
            print_compatibility_warning()
        captured = capsys.readouterr()
        assert "COMPATIBILITY WARNING" in captured.out


# ── check_and_exit_if_incompatible ────────────────────────────────────────


class TestCheckAndExitIfIncompatible:
    def test_compatible_does_not_exit(self):
        with (
            patch("dagster_webserver.webserver.DagsterWebserver") as ws_cls,
        ):
            ws_cls.build_middleware = MagicMock()
            ws_cls.build_routes = MagicMock()

            check_and_exit_if_incompatible()

    def test_incompatible_exits(self):
        with (
            patch("dagster_webserver.webserver.DagsterWebserver", new=None),
        ):
            with pytest.raises(SystemExit) as exc:
                check_and_exit_if_incompatible()
        assert exc.value.code == 1
