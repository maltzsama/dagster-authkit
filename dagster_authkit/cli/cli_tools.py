"""CLI tools for managing users in SQLite database."""

import argparse
import getpass
from pathlib import Path

from dagster_authkit.auth.backends.sqlite import SQLiteAuthBackend


def handle_user_management():
    """
    Main entry point for CLI management commands.
    Parses arguments and dispatches to the correct command function.
    """
    parser = argparse.ArgumentParser(
        prog="dagster-authkit", description="Dagster AuthKit - Administrative CLI"
    )
    subparsers = parser.add_subparsers(dest="command", help="Management commands")

    # Register subcommands
    setup_cli_parser(subparsers)

    args = parser.parse_args()

    if hasattr(args, "func"):
        return args.func(args)
    else:
        parser.print_help()
        return 1


def init_db_command(args):
    """Initialize a new database."""
    db_path = args.db_path or "./dagster_auth.db"

    if Path(db_path).exists() and not args.force:
        print(f"❌ Database already exists: {db_path}")
        print(f"   Use --force to recreate")
        return 1

    # Create backend (will initialize database)
    backend = SQLiteAuthBackend({"DAGSTER_AUTH_DB": db_path})

    print(f"✅ Database initialized: {db_path}")

    # Offer to create admin user
    if args.with_admin or input("\nCreate admin user? (y/N): ").lower() == "y":
        print("\nCreating admin user...")
        username = input("Username [admin]: ").strip() or "admin"
        password = getpass.getpass("Password: ")
        password_confirm = getpass.getpass("Confirm password: ")

        if password != password_confirm:
            print("❌ Passwords don't match")
            return 1

        email = input("Email (optional): ").strip() or None

        if backend.add_user(
            username=username, password=password, email=email, roles=["admin", "editor", "viewer"]
        ):
            print(f"✅ Admin user '{username}' created successfully")
        else:
            print(f"❌ Failed to create admin user")
            return 1

    return 0


def add_user_command(args):
    """Add a new user."""
    db_path = args.db_path or "./dagster_auth.db"

    if not Path(db_path).exists():
        print(f"❌ Database not found: {db_path}")
        print(f"   Run: dagster-authkit init-db")
        return 1

    backend = SQLiteAuthBackend({"DAGSTER_AUTH_DB": db_path})

    # Get password
    if args.password:
        password = args.password
    else:
        password = getpass.getpass("Password: ")
        password_confirm = getpass.getpass("Confirm password: ")

        if password != password_confirm:
            print("❌ Passwords don't match")
            return 1

    # Parse roles
    roles = []
    if args.admin:
        roles = ["admin", "editor", "viewer"]
    elif args.editor:
        roles = ["editor", "viewer"]
    elif args.viewer:
        roles = ["viewer"]
    elif args.roles:
        roles = args.roles.split(",")
    else:
        roles = ["viewer"]  # Default

    # Add user
    if backend.add_user(
        username=args.username,
        password=password,
        email=args.email,
        display_name=args.display_name,
        roles=roles,
    ):
        print(f"✅ User '{args.username}' created successfully")
        print(f"   Roles: {', '.join(roles)}")
        return 0
    else:
        print(f"❌ Failed to create user")
        return 1


def change_password_command(args):
    """Change user password."""
    db_path = args.db_path or "./dagster_auth.db"

    if not Path(db_path).exists():
        print(f"❌ Database not found: {db_path}")
        return 1

    backend = SQLiteAuthBackend({"DAGSTER_AUTH_DB": db_path})

    # Get new password
    if args.password:
        new_password = args.password
    else:
        new_password = getpass.getpass("New password: ")
        password_confirm = getpass.getpass("Confirm password: ")

        if new_password != password_confirm:
            print("❌ Passwords don't match")
            return 1

    if backend.change_password(args.username, new_password):
        print(f"✅ Password changed for user '{args.username}'")
        return 0
    else:
        print(f"❌ Failed to change password")
        return 1


def list_users_command(args):
    """List all users."""
    db_path = args.db_path or "./dagster_auth.db"

    if not Path(db_path).exists():
        print(f"❌ Database not found: {db_path}")
        return 1

    backend = SQLiteAuthBackend({"DAGSTER_AUTH_DB": db_path})
    users = backend.list_users()

    if not users:
        print("No users found")
        return 0

    print(f"\n{'Username':<15} {'Email':<25} {'Roles':<30} {'Last Login'}")
    print("=" * 90)

    for user in users:
        roles_str = ", ".join(user["roles"])
        last_login = user["last_login"] or "Never"
        print(
            f"{user['username']:<15} "
            f"{user['email'] or 'N/A':<25} "
            f"{roles_str:<30} "
            f"{last_login}"
        )

    print(f"\nTotal: {len(users)} users")
    return 0


def delete_user_command(args):
    """Delete a user."""
    db_path = args.db_path or "./dagster_auth.db"

    if not Path(db_path).exists():
        print(f"❌ Database not found: {db_path}")
        return 1

    backend = SQLiteAuthBackend({"DAGSTER_AUTH_DB": db_path})

    # Confirm deletion
    if not args.yes:
        confirm = input(f"Delete user '{args.username}'? (y/N): ")
        if confirm.lower() != "y":
            print("Cancelled")
            return 0

    if backend.delete_user(args.username):
        print(f"✅ User '{args.username}' deleted")
        return 0
    else:
        print(f"❌ Failed to delete user")
        return 1


def setup_cli_parser(subparsers):
    """Setup CLI argument parsers for user management commands."""

    # init-db command
    init_parser = subparsers.add_parser("init-db", help="Initialize authentication database")
    init_parser.add_argument("--db-path", help="Database path (default: ./dagster_auth.db)")
    init_parser.add_argument("--force", action="store_true", help="Recreate database if exists")
    init_parser.add_argument(
        "--with-admin", action="store_true", help="Create admin user during initialization"
    )
    init_parser.set_defaults(func=init_db_command)

    # add-user command
    add_parser = subparsers.add_parser("add-user", help="Add a new user")
    add_parser.add_argument("username", help="Username")
    add_parser.add_argument("--email", help="Email address")
    add_parser.add_argument("--display-name", help="Display name")
    add_parser.add_argument("--password", help="Password (will prompt if not provided)")
    add_parser.add_argument("--db-path", help="Database path (default: ./dagster_auth.db)")

    # Role shortcuts
    role_group = add_parser.add_mutually_exclusive_group()
    role_group.add_argument("--admin", action="store_true", help="Grant admin role")
    role_group.add_argument("--editor", action="store_true", help="Grant editor role")
    role_group.add_argument("--viewer", action="store_true", help="Grant viewer role")
    role_group.add_argument("--roles", help="Comma-separated list of roles")

    add_parser.set_defaults(func=add_user_command)

    # change-password command
    passwd_parser = subparsers.add_parser("change-password", help="Change user password")
    passwd_parser.add_argument("username", help="Username")
    passwd_parser.add_argument("--password", help="New password (will prompt if not provided)")
    passwd_parser.add_argument("--db-path", help="Database path (default: ./dagster_auth.db)")
    passwd_parser.set_defaults(func=change_password_command)

    # list-users command
    list_parser = subparsers.add_parser("list-users", help="List all users")
    list_parser.add_argument("--db-path", help="Database path (default: ./dagster_auth.db)")
    list_parser.set_defaults(func=list_users_command)

    # delete-user command
    delete_parser = subparsers.add_parser("delete-user", help="Delete a user")
    delete_parser.add_argument("username", help="Username to delete")
    delete_parser.add_argument("--yes", "-y", action="store_true", help="Skip confirmation")
    delete_parser.add_argument("--db-path", help="Database path (default: ./dagster_auth.db)")
    delete_parser.set_defaults(func=delete_user_command)
