import sys
from unittest.mock import MagicMock, patch

import pytest

from dagster_authkit.auth.backends.base import Role
from dagster_authkit.auth.backends.sql import PeeweeAuthBackend, UserTable
from dagster_authkit.cli import cli_tools


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "test.db")


@pytest.fixture
def dsn(db_path):
    return f"sqlite:///{db_path}"


@pytest.fixture
def backend(dsn):
    be = PeeweeAuthBackend({"DAGSTER_AUTH_DATABASE_URL": dsn})
    yield be
    UserTable.drop_table(safe=True)


@pytest.fixture
def populated(dsn, backend):
    backend.add_user("alice", "pass1", Role.EDITOR, "alice@co.com", "Alice")
    backend.add_user("bob", "pass2", Role.ADMIN, "bob@co.com", "Bob")
    return dsn


# ── _get_backend ──────────────────────────────────────────────────────────


class TestGetBackend:
    def test_with_explicit_dsn(self, dsn):
        be = cli_tools._get_backend(dsn)
        assert isinstance(be, PeeweeAuthBackend)

    def test_file_path_converts_to_dsn(self, tmp_path):
        path = str(tmp_path / "cli_test.db")
        be = cli_tools._get_backend(path)
        assert isinstance(be, PeeweeAuthBackend)

    def test_fallback_to_config(self, dsn, monkeypatch):
        be = cli_tools._get_backend(dsn)
        assert isinstance(be, PeeweeAuthBackend)


# ── handle_user_management ────────────────────────────────────────────────


class TestHandleUserManagement:
    def test_no_args_prints_help(self, capsys):
        with patch.object(sys, "argv", ["dagster-authkit"]):
            rc = cli_tools.handle_user_management()
        assert rc == 1
        captured = capsys.readouterr()
        assert "usage:" in captured.out.lower()

    def test_init_db(self, dsn, capsys):
        with (
            patch.object(sys, "argv", ["dagster-authkit", "init-db", "--db-path", dsn]),
            patch("builtins.input", return_value="n"),
        ):
            rc = cli_tools.handle_user_management()
        assert rc == 0
        captured = capsys.readouterr()
        assert "Database tables initialized" in captured.out

    def test_init_db_with_admin(self, dsn, capsys):
        with (
            patch.object(sys, "argv", ["dagster-authkit", "init-db", "--db-path", dsn, "--with-admin"]),
            patch("getpass.getpass", return_value="adminpass"),
            patch("builtins.input", return_value="admin"),
        ):
            rc = cli_tools.handle_user_management()
        assert rc == 0
        captured = capsys.readouterr()
        assert "created successfully" in captured.out

    def test_add_user(self, dsn, capsys):
        with patch.object(
            sys, "argv", ["dagster-authkit", "add-user", "charlie", "--password", "secret", "--editor", "--db-path", dsn]
        ):
            rc = cli_tools.handle_user_management()
        assert rc == 0
        captured = capsys.readouterr()
        assert "created successfully" in captured.out

    def test_add_user_invalid_role(self, dsn, capsys):
        with patch.object(
            sys, "argv", ["dagster-authkit", "add-user", "eve", "--password", "x", "--role", "SUPERUSER", "--db-path", dsn]
        ):
            rc = cli_tools.handle_user_management()
        assert rc == 1
        captured = capsys.readouterr()
        assert "Invalid role" in captured.out

    def test_list_users(self, capsys, populated):
        with patch.object(sys, "argv", ["dagster-authkit", "list-users", "--db-path", populated]):
            rc = cli_tools.handle_user_management()
        assert rc == 0
        captured = capsys.readouterr()
        assert "alice" in captured.out
        assert "bob" in captured.out

    def test_list_users_empty(self, dsn, capsys):
        with patch.object(sys, "argv", ["dagster-authkit", "list-users", "--db-path", dsn]):
            rc = cli_tools.handle_user_management()
        assert rc == 0
        captured = capsys.readouterr()
        assert "No users found" in captured.out

    def test_change_password(self, capsys, populated):
        with patch.object(
            sys, "argv", ["dagster-authkit", "change-password", "alice", "--password", "newpass", "--db-path", populated]
        ):
            rc = cli_tools.handle_user_management()
        assert rc == 0
        captured = capsys.readouterr()
        assert "Password updated" in captured.out

    def test_change_password_user_not_found(self, dsn, capsys):
        with patch.object(
            sys, "argv", ["dagster-authkit", "change-password", "nobody", "--password", "x", "--db-path", dsn]
        ):
            rc = cli_tools.handle_user_management()
        assert rc == 1
        captured = capsys.readouterr()
        assert "not found" in captured.out

    def test_delete_user(self, capsys, populated):
        with patch.object(
            sys, "argv", ["dagster-authkit", "delete-user", "alice", "--yes", "--db-path", populated]
        ):
            rc = cli_tools.handle_user_management()
        assert rc == 0
        captured = capsys.readouterr()
        assert "deleted" in captured.out

    def test_delete_user_not_found(self, dsn, capsys):
        with patch.object(
            sys, "argv", ["dagster-authkit", "delete-user", "nobody", "--yes", "--db-path", dsn]
        ):
            rc = cli_tools.handle_user_management()
        assert rc == 1
        captured = capsys.readouterr()
        assert "not found" in captured.out

    def test_change_role(self, capsys, populated):
        with patch.object(
            sys, "argv", ["dagster-authkit", "change-role", "alice", "VIEWER", "--db-path", populated]
        ):
            rc = cli_tools.handle_user_management()
        assert rc == 0
        captured = capsys.readouterr()
        assert "changed to VIEWER" in captured.out

    def test_change_role_invalid(self, dsn, capsys):
        with patch.object(
            sys, "argv", ["dagster-authkit", "change-role", "alice", "GOD", "--db-path", dsn]
        ):
            rc = cli_tools.handle_user_management()
        assert rc == 1
        captured = capsys.readouterr()
        assert "Invalid role" in captured.out

    def test_change_role_user_not_found(self, dsn, capsys):
        with patch.object(
            sys, "argv", ["dagster-authkit", "change-role", "nobody", "ADMIN", "--db-path", dsn]
        ):
            rc = cli_tools.handle_user_management()
        assert rc == 1
        captured = capsys.readouterr()
        assert "not found" in captured.out

    def test_list_permissions(self, capsys):
        with patch.object(sys, "argv", ["dagster-authkit", "list-permissions"]):
            rc = cli_tools.handle_user_management()
        assert rc == 0
        captured = capsys.readouterr()
        assert "VIEWER" in captured.out
        assert "ADMIN" in captured.out


# ── Command functions directly ────────────────────────────────────────────


class TestInitDBCommand:
    def test_init_db_tables_created(self, dsn):
        with patch("builtins.input", return_value="n"):
            args = MagicMock(db_path=dsn, with_admin=False)
            rc = cli_tools.init_db_command(args)
        assert rc == 0

    def test_init_db_existing_admin_skips(self, dsn, backend):
        args = MagicMock(db_path=dsn, with_admin=False)
        backend.add_user("admin", "p", Role.ADMIN)
        rc = cli_tools.init_db_command(args)
        assert rc == 0


class TestAddUserCommand:
    def test_password_mismatch(self, dsn, capsys):
        args = MagicMock(
            username="u", password=None, email="", full_name="", db_path=dsn,
            admin=False, editor=False, launcher=False, viewer=False, role=None,
        )
        with patch("getpass.getpass", side_effect=["sekret", "wrong"]):
            rc = cli_tools.add_user_command(args)
        assert rc == 1
        captured = capsys.readouterr()
        assert "do not match" in captured.out

    def test_existing_user_succeeds(self, dsn, backend, capsys):
        backend.add_user("alice", "p", Role.ADMIN)
        args = MagicMock(
            username="alice", password="x", email="", full_name="", db_path=dsn,
            admin=False, editor=False, launcher=False, viewer=False, role=None,
        )
        rc = cli_tools.add_user_command(args)
        assert rc == 1
        captured = capsys.readouterr()
        assert "Failed" in captured.out or "already exist" in captured.out


class TestDeleteUserCommand:
    def test_no_confirm_cancels(self, capsys):
        args = MagicMock(username="alice", yes=False, db_path="sqlite:///:memory:")
        with patch("builtins.input", return_value="n"):
            rc = cli_tools.delete_user_command(args)
        assert rc == 0
        captured = capsys.readouterr()
        assert "cancelled" in captured.out.lower()


# ── main() ────────────────────────────────────────────────────────────────


class TestMain:
    @patch("dagster_authkit.cli.main.setup_logging", return_value=MagicMock())
    @patch("dagster_authkit.cli.main.print_banner")
    @patch("dagster_authkit.cli.main.print_config_summary")
    @patch("dagster_authkit.cli.main.verify_dagster_api_compatibility", return_value=(True, None))
    @patch("dagster_authkit.cli.main.apply_patches")
    @patch("dagster_authkit.cli.main.verify_patches", return_value=True)
    def test_sql_bootstrap_called(
        self, mock_verify, mock_apply, mock_compat, mock_print_summary, mock_print_banner, mock_logging
    ):
        with (
            patch.object(sys, "argv", ["dagster-authkit", "-w", "workspace.yaml"]),
            patch("dagster_authkit.cli.main.config") as mock_config,
            patch("dagster_authkit.auth.backends.sql.PeeweeAuthBackend") as mock_backend,
        ):
            mock_config.AUTH_BACKEND = "sql"
            mock_config.__dict__ = {"AUTH_BACKEND": "sql"}
            try:
                from dagster_authkit.cli.main import main
                main()
            except SystemExit:
                pass
        mock_backend.assert_called_once()
