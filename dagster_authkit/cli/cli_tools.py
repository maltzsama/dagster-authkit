"""CLI tools for managing users in SQLite database."""

import argparse
import getpass
from pathlib import Path

from dagster_authkit.auth.backends.base import Role
from dagster_authkit.auth.backends.sql import SQLiteAuthBackend


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

    # Delete existing database if --force
    if args.force and Path(db_path).exists():
        Path(db_path).unlink()
        print(f"🗑️  Deleted existing database")

    # Create backend (will initialize database)
    backend = SQLiteAuthBackend({"DAGSTER_AUTH_DB": db_path})

    print(f"✅ Database initialized: {db_path}")

    # Offer to create admin user ONLY if bootstrap didn't create one
    admin_exists = backend.get_user("admin") is not None

    if admin_exists:
        print("\n✅ Admin user already created via DAGSTER_AUTH_ADMIN_PASSWORD")
        return 0

    # No admin yet, offer to create manually
    if args.with_admin or input("\nCreate admin user? (y/N): ").lower() == "y":
        print("\nCreating admin user...")
        username = input("Username [admin]: ").strip() or "admin"
        password = getpass.getpass("Password: ")
        password_confirm = getpass.getpass("Confirm password: ")

        if password != password_confirm:
            print("❌ Passwords don't match")
            return 1

        email = input("Email (optional): ").strip() or ""
        full_name = input("Full name (optional): ").strip() or "Administrator"

        if backend.add_user(
            username=username, password=password, role=Role.ADMIN, email=email, full_name=full_name
        ):
            print(f"✅ Admin user '{username}' created successfully")
            print(f"   Role: ADMIN")
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

    # Parse role (single role, not list)
    if args.admin:
        role = Role.ADMIN
    elif args.editor:
        role = Role.EDITOR
    elif args.launcher:
        role = Role.LAUNCHER
    elif args.viewer:
        role = Role.VIEWER
    elif args.role:
        try:
            role = Role[args.role.upper()]
        except KeyError:
            print(f"❌ Invalid role: {args.role}")
            print(f"   Valid roles: VIEWER, LAUNCHER, EDITOR, ADMIN")
            return 1
    else:
        role = Role.VIEWER  # Default

    # Add user
    if backend.add_user(
        username=args.username,
        password=password,
        role=role,
        email=args.email or "",
        full_name=args.full_name or "",
    ):
        print(f"✅ User '{args.username}' created successfully")
        print(f"   Role: {role.name}")
        return 0
    else:
        print(f"❌ Failed to create user (may already exist)")
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
        print(f"❌ Failed to change password (user not found)")
        return 1


def change_role_command(args):
    """Change user's role."""
    db_path = args.db_path or "./dagster_auth.db"

    if not Path(db_path).exists():
        print(f"❌ Database not found: {db_path}")
        return 1

    backend = SQLiteAuthBackend({"DAGSTER_AUTH_DB": db_path})

    # Parse new role
    try:
        new_role = Role[args.role.upper()]
    except KeyError:
        print(f"❌ Invalid role: {args.role}")
        print(f"   Valid roles: VIEWER, LAUNCHER, EDITOR, ADMIN")
        return 1

    if backend.change_role(args.username, new_role):
        print(f"✅ Role changed for user '{args.username}' to {new_role.name}")
        return 0
    else:
        print(f"❌ Failed to change role (user not found)")
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

    print(f"\n{'Username':<15} {'Role':<10} {'Email':<30} {'Full Name':<25}")
    print("=" * 80)

    for user in users:
        print(
            f"{user.username:<15} "
            f"{user.role.name:<10} "
            f"{user.email or 'N/A':<30} "
            f"{user.full_name or 'N/A':<25}"
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
        print(f"❌ Failed to delete user (user not found)")
        return 1


def list_permissions_command(args):
    """List all mutation permissions by role."""
    from dagster_authkit.auth.backends.base import Role, RolePermissions

    print("\n" + "=" * 70)
    print("  📋  DAGSTER AUTHKIT - RBAC PERMISSIONS")
    print("=" * 70)

    for role in [Role.VIEWER, Role.LAUNCHER, Role.EDITOR, Role.ADMIN]:
        permissions = RolePermissions.list_permissions(role)

        print(f"\n🔹 {role.name} (Level {role.value}) - {len(permissions)} mutations\n")

        if role == Role.VIEWER:
            print("   (Read-only access - no mutations allowed)")
        else:
            for mutation in sorted(permissions):
                print(f"   • {mutation}")

    print("\n" + "=" * 70)
    return 0


def setup_cli_parser(subparsers):
    """Setup CLI argument parsers for user management commands."""

    # ========================================
    # init-db command
    # ========================================
    init_parser = subparsers.add_parser("init-db", help="Initialize authentication database")
    init_parser.add_argument("--db-path", help="Database path (default: ./dagster_auth.db)")
    init_parser.add_argument("--force", action="store_true", help="Recreate database if exists")
    init_parser.add_argument(
        "--with-admin", action="store_true", help="Create admin user during initialization"
    )
    init_parser.set_defaults(func=init_db_command)

    # ========================================
    # add-user command
    # ========================================
    add_parser = subparsers.add_parser("add-user", help="Add a new user")
    add_parser.add_argument("username", help="Username")
    add_parser.add_argument("--email", help="Email address")
    add_parser.add_argument("--full-name", help="Full name")
    add_parser.add_argument("--password", help="Password (will prompt if not provided)")
    add_parser.add_argument("--db-path", help="Database path (default: ./dagster_auth.db)")

    # Role options (mutually exclusive)
    role_group = add_parser.add_mutually_exclusive_group()
    role_group.add_argument("--admin", action="store_true", help="Grant ADMIN role")
    role_group.add_argument("--editor", action="store_true", help="Grant EDITOR role")
    role_group.add_argument("--launcher", action="store_true", help="Grant LAUNCHER role")
    role_group.add_argument("--viewer", action="store_true", help="Grant VIEWER role")
    role_group.add_argument("--role", help="Role name (VIEWER/LAUNCHER/EDITOR/ADMIN)")

    add_parser.set_defaults(func=add_user_command)

    # ========================================
    # change-password command
    # ========================================
    passwd_parser = subparsers.add_parser("change-password", help="Change user password")
    passwd_parser.add_argument("username", help="Username")
    passwd_parser.add_argument("--password", help="New password (will prompt if not provided)")
    passwd_parser.add_argument("--db-path", help="Database path (default: ./dagster_auth.db)")
    passwd_parser.set_defaults(func=change_password_command)

    # ========================================
    # change-role command
    # ========================================
    role_parser = subparsers.add_parser("change-role", help="Change user's role")
    role_parser.add_argument("username", help="Username")
    role_parser.add_argument("role", help="New role (VIEWER/LAUNCHER/EDITOR/ADMIN)")
    role_parser.add_argument("--db-path", help="Database path (default: ./dagster_auth.db)")
    role_parser.set_defaults(func=change_role_command)

    # ========================================
    # list-users command
    # ========================================
    list_parser = subparsers.add_parser("list-users", help="List all users")
    list_parser.add_argument("--db-path", help="Database path (default: ./dagster_auth.db)")
    list_parser.set_defaults(func=list_users_command)

    # ========================================
    # delete-user command
    # ========================================
    delete_parser = subparsers.add_parser("delete-user", help="Delete a user")
    delete_parser.add_argument("username", help="Username to delete")
    delete_parser.add_argument("--yes", "-y", action="store_true", help="Skip confirmation")
    delete_parser.add_argument("--db-path", help="Database path (default: ./dagster_auth.db)")
    delete_parser.set_defaults(func=delete_user_command)

    # ========================================
    # list-permissions command
    # ========================================
    perms_parser = subparsers.add_parser(
        "list-permissions", help="List all RBAC permissions by role"
    )
    perms_parser.set_defaults(func=list_permissions_command)
