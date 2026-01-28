"""
CLI tools for managing users in SQL databases via Peewee.
Supports unified SQL backends (SQLite, PostgreSQL, MySQL).
"""

import argparse
import getpass
import sys
from pathlib import Path
from typing import Optional

from dagster_authkit.auth.backends.base import Role
from dagster_authkit.auth.backends.sql import PeeweeAuthBackend, UserTable
from dagster_authkit.utils.config import config


def _get_backend(db_path: Optional[str] = None) -> PeeweeAuthBackend:
    """
    Helper to instantiate the unified SQL backend.
    Prioritizes provided CLI path, then falls back to DSN or legacy DB path.
    """
    # 1. Use the path provided in the CLI argument if present
    effective_db = db_path or config.DAGSTER_AUTH_DATABASE_URL or config.DAGSTER_AUTH_DB

    # 2. Convert raw file paths to SQLite DSN if necessary
    if "://" not in effective_db:
        dsn = f"sqlite:///{effective_db}"
    else:
        dsn = effective_db

    return PeeweeAuthBackend({"DAGSTER_AUTH_DATABASE_URL": dsn})


def handle_user_management():
    """
    Main entry point for CLI management commands.
    Parses arguments and dispatches to the correct command function.
    """
    parser = argparse.ArgumentParser(
        prog="dagster-authkit", description="Dagster AuthKit - Administrative CLI"
    )
    subparsers = parser.add_subparsers(dest="command", help="Management commands")

    # Register all subcommands
    setup_cli_parser(subparsers)

    args = parser.parse_args()

    if hasattr(args, "func"):
        return args.func(args)
    else:
        parser.print_help()
        return 1


def init_db_command(args):
    """Initialize a new database and create necessary tables."""
    backend = _get_backend(args.db_path)

    # Force table creation
    UserTable._meta.database.create_tables([UserTable])
    print(f"✅ Database tables initialized.")

    # Check if admin already exists (auto-bootstrap might have run)
    if backend.get_user("admin"):
        print("✅ Admin user already exists.")
        return 0

    if args.with_admin or input("\nCreate admin user? (y/N): ").lower() == "y":
        username = input("Username [admin]: ").strip() or "admin"
        password = getpass.getpass("Password: ")

        if backend.add_user(username=username, password=password, role=Role.ADMIN):
            print(f"✅ Admin user '{username}' created successfully (Role: ADMIN)")
        else:
            print(f"❌ Failed to create admin user.")
            return 1
    return 0


def add_user_command(args):
    """Add a new user to the SQL database."""
    backend = _get_backend(args.db_path)

    password = args.password or getpass.getpass("Password: ")
    if not args.password:
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("❌ Passwords do not match.")
            return 1

    # Map flags to Role enum
    role = Role.VIEWER
    if args.admin:
        role = Role.ADMIN
    elif args.editor:
        role = Role.EDITOR
    elif args.launcher:
        role = Role.LAUNCHER
    elif args.role:
        try:
            role = Role[args.role.upper()]
        except KeyError:
            print(f"❌ Invalid role: {args.role}. Use: VIEWER, LAUNCHER, EDITOR, ADMIN")
            return 1

    if backend.add_user(
        username=args.username,
        password=password,
        role=role,
        email=args.email or "",
        full_name=args.full_name or "",
    ):
        print(f"✅ User '{args.username}' created successfully (Role: {role.name})")
        return 0

    print(f"❌ Failed to create user (it may already exist)")
    return 1


def change_password_command(args):
    """Update user password via CLI."""
    backend = _get_backend(args.db_path)

    new_password = args.password or getpass.getpass("New password: ")

    if backend.change_password(args.username, new_password, performed_by="cli"):
        print(f"✅ Password updated for '{args.username}'.")
        print(f"🔒 Security: All active sessions for this user were revoked.")
        return 0

    print(f"❌ User '{args.username}' not found.")
    return 1


def list_users_command(args):
    """List all registered users from the SQL database."""
    _get_backend(args.db_path)  # Just to ensure connection

    users = UserTable.select()
    if not users:
        print("No users found in database.")
        return 0

    print(f"\n{'Username':<20} {'Role':<12} {'Status':<10} {'Full Name':<25}")
    print("-" * 70)

    for u in users:
        # Resolve role name from value
        role_name = (
            Role(u.role_value).name
            if u.role_value in [r.value for r in Role]
            else str(u.role_value)
        )
        status = "Active" if u.is_active else "Disabled"
        print(f"{u.username:<20} {role_name:<12} {status:<10} {u.full_name or 'N/A':<25}")

    print(f"\nTotal: {len(users)} users.")
    return 0


def delete_user_command(args):
    """Permanently delete a user from the database."""
    backend = _get_backend(args.db_path)

    if not args.yes:
        confirm = input(f"Are you sure you want to delete user '{args.username}'? (y/N): ")
        if confirm.lower() != "y":
            print("Operation cancelled.")
            return 0

    if backend.delete_user(args.username):
        print(f"✅ User '{args.username}' deleted.")
        return 0

    print(f"❌ Failed to delete user (not found).")
    return 1


def list_permissions_command(args):
    """List RBAC permissions for each role."""
    from dagster_authkit.auth.backends.base import RolePermissions

    print("\n" + "=" * 60)
    print("  DAGSTER AUTHKIT - RBAC PERMISSIONS MATRIX")
    print("=" * 60)

    for role in [Role.VIEWER, Role.LAUNCHER, Role.EDITOR, Role.ADMIN]:
        perms = RolePermissions.list_permissions(role)
        print(f"\n🔹 {role.name} (Level {role.value})")
        if not perms:
            print("   (Read-only / No mutations)")
        else:
            for p in sorted(perms):
                print(f"   • {p}")
    return 0


def setup_cli_parser(subparsers):
    """Setup CLI argument parsers for all commands."""

    # init-db
    p_init = subparsers.add_parser("init-db", help="Initialize the SQL database")
    p_init.add_argument("--db-path", help="Database path or DSN")
    p_init.add_argument("--with-admin", action="store_true", help="Bootstrap admin user")
    p_init.set_defaults(func=init_db_command)

    # add-user
    p_add = subparsers.add_parser("add-user", help="Add a new user")
    p_add.add_argument("username", help="Username")
    p_add.add_argument("--password", help="Password (will prompt if omitted)")
    p_add.add_argument("--email", help="User email")
    p_add.add_argument("--full-name", help="User's full name")
    p_add.add_argument("--db-path", help="Database path or DSN")

    rg = p_add.add_mutually_exclusive_group()
    rg.add_argument("--admin", action="store_true")
    rg.add_argument("--editor", action="store_true")
    rg.add_argument("--launcher", action="store_true")
    rg.add_argument("--viewer", action="store_true")
    rg.add_argument("--role", help="Specific role name")
    p_add.set_defaults(func=add_user_command)

    # change-password
    p_pass = subparsers.add_parser("change-password", help="Change user password")
    p_pass.add_argument("username", help="Username")
    p_pass.add_argument("--password", help="New password")
    p_pass.add_argument("--db-path", help="Database path or DSN")
    p_pass.set_defaults(func=change_password_command)

    # list-users
    p_list = subparsers.add_parser("list-users", help="List all users")
    p_list.add_argument("--db-path", help="Database path or DSN")
    p_list.set_defaults(func=list_users_command)

    # delete-user
    p_del = subparsers.add_parser("delete-user", help="Delete a user")
    p_del.add_argument("username", help="Username")
    p_del.add_argument("--yes", "-y", action="store_true", help="Skip confirmation")
    p_del.add_argument("--db-path", help="Database path or DSN")
    p_del.set_defaults(func=delete_user_command)

    # list-permissions
    p_perm = subparsers.add_parser("list-permissions", help="View RBAC matrix")
    p_perm.set_defaults(func=list_permissions_command)
