"""
Dagster AuthKit CLI Entry Point - v1.0

Main orchestrator that:
1. Intercepts management commands (user, init-db, etc.)
2. Performs environment & compatibility checks.
3. Applies authentication monkey-patches.
4. Delegates execution to the official Dagster webserver CLI.
"""

import sys
import logging
from dagster_authkit.core.detection_layer import verify_dagster_api_compatibility
from dagster_authkit.core.patch import apply_patches, verify_patches
from dagster_authkit.utils.config import config
from dagster_authkit.utils.display import print_banner, print_config_summary
from dagster_authkit.utils.logging import setup_logging

# List of commands that should be handled by our internal management CLI
MANAGEMENT_COMMANDS = [
    "init-db",
    "add-user",
    "list-users",
    "delete-user",
    "change-password",
    "change-role",
    "list-permissions",
]


def main():
    """
    Primary entry point for ``dagster-authkit``.

    Orchestrates the full startup sequence:

    1. Initialise structured logging.
    2. Intercept management commands (add-user, list-users, etc.) and
       delegate to ``cli_tools.handle_user_management()``.
    3. Print startup banner and configuration summary.
    4. Verify Dagster API compatibility (exits on failure).
    5. Apply monkey-patches to DagsterWebserver (middleware, routes, UI).
       Verify patches were applied successfully.
    6. Bootstrap the SQL backend if configured (create tables, admin user).
    7. Delegate normal webserver invocation to Dagster's own CLI
       (``dagster_webserver.cli.main`` or legacy ``dagit.cli.main``).
    8. Trap ``SystemExit`` for user-friendly error messages on missing args.

    This function calls ``sys.exit()``; it does not return normally.
    """
    # 1. Initialize global logging
    logger = setup_logging()

    # 2. Intercept Management Commands
    # If the first argument is one of our tools, we don't start the server.
    if len(sys.argv) > 1 and sys.argv[1] in MANAGEMENT_COMMANDS:
        try:
            from dagster_authkit.cli.cli_tools import handle_user_management

            sys.exit(handle_user_management())
        except Exception as e:
            logger.error(f"❌ Failed to execute management command: {e}")
            sys.exit(1)

    # 3. Server Mode: Startup Display
    print_banner()
    print_config_summary(config.__dict__)

    # 4. Verify Dagster API Compatibility
    # Essential to prevent crashes if Dagster updates their internal API.
    logger.info("Verifying Dagster API compatibility...")
    is_compatible, error = verify_dagster_api_compatibility()
    if not is_compatible:
        logger.error(f"CRITICAL COMPATIBILITY ERROR: {error}")
        print("\n" + "!" * 80)
        print("ERROR: This version of dagster-authkit is not compatible with your Dagster version.")
        print("Please check for updates or report this issue.")
        print("!" * 80 + "\n")
        sys.exit(1)
    logger.info("✅ Dagster API compatibility verified")

    # 5. Apply Security Patches
    # This is where we 'kidnap' the Dagster webserver and inject our Auth.
    logger.info("Applying authentication patches...")
    try:
        apply_patches()
        if not verify_patches():
            logger.critical("Patch verification failed — patches were not applied correctly.")
            sys.exit(1)
    except Exception as e:
        logger.critical(f"Fatal error during patching: {e}", exc_info=True)
        sys.exit(1)

    # 6. Database Bootstrap (SQL Backend)
    # If using SQL (SQLite/Postgres/MySQL), ensure tables and admin exist.
    if config.AUTH_BACKEND in ["sql", "sqlite"]:
        logger.info(f"Bootstrapping SQL backend: {config.AUTH_BACKEND}")
        try:
            from dagster_authkit.auth.backends.sql import PeeweeAuthBackend

            # Instantiating triggers table creation and admin check
            PeeweeAuthBackend(config.__dict__)
            logger.info("✅ SQL Database is ready")
        except Exception as e:
            logger.error(f"Database bootstrap warning: {e}", exc_info=True)
            # We don't exit here as the server might still start with limited functionality

    # 7. Delegate to Official Dagster CLI
    logger.info("Patches active. Delegating to Dagster webserver...")

    dagster_cli_main = None

    try:
        # Try modern path first (Dagster 1.10+)
        from dagster_webserver.cli import main as webserver_main

        dagster_cli_main = webserver_main
        logger.debug("Using 'dagster_webserver.cli'")
    except ImportError:
        try:
            # Fallback for older versions
            from dagit.cli import main as dagit_main

            dagster_cli_main = dagit_main
            logger.debug("Using 'dagit.cli' (legacy)")
        except ImportError:
            logger.error("CRITICAL: Dagster webserver CLI not found!")
            print("\n" + "!" * 60)
            print("Make sure you have Dagster installed:")
            print("    pip install dagster dagster-webserver")
            print("!" * 60 + "\n")
            sys.exit(1)

    # 8. Executing the server
    # We modify sys.argv[0] so Click (the CLI lib Dagster uses)
    # shows the help messages correctly as 'dagster'.
    sys.argv[0] = "dagster-webserver"

    try:
        logger.info("🚀 Launching Dagster webserver process...")
        dagster_cli_main()
    except SystemExit as e:
        if e.code == 2:
            logger.error("❌ Dagster webserver failed: Missing arguments.")
            print("\n" + "!" * 60)
            print("ERROR: You must provide a workspace or a module to load.")
            print("Example: dagster-authkit -m your_package.definitions")
            print("Or use a workspace.yaml in the current directory.")
            print("!" * 60 + "\n")
        sys.exit(e.code)
    except Exception as e:
        logger.critical(f"Unexpected crash: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
