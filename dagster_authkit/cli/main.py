#!/usr/bin/env python3
"""
Dagster AuthKit CLI Entry Point

Main orchestrator for the dagster-authkit package.
Handles user management commands and delegates to Dagster webserver.
"""

import sys

from dagster_authkit.core.detection_layer import verify_dagster_api_compatibility
from dagster_authkit.core.patch import apply_patches
from dagster_authkit.utils.config import config
from dagster_authkit.utils.display import print_banner, print_config_summary
from dagster_authkit.utils.logging import setup_logging


def main():
    """
    Main execution flow:
    1. Initialize system logging
    2. Route to User Management CLI if requested
    3. Perform compatibility checks and patching
    4. Delegate to Dagster webserver CLI
    """

    # 1. Initialize logging
    logger = setup_logging()

    # 2. Intercept User Management commands
    management_commands = [
        "user",  # New: user create/list/delete/change-password/change-role
        "init-db",  # Legacy compatibility
        "add-user",  # Legacy compatibility
        "list-users",  # Legacy compatibility
        "delete-user",  # Legacy compatibility
        "change-password",  # Legacy compatibility
    ]

    if len(sys.argv) > 1 and sys.argv[1] in management_commands:
        try:
            from dagster_authkit.cli.cli_tools import handle_user_management

            return handle_user_management()
        except ImportError as e:
            logger.error(f"Failed to load CLI management tools: {e}")
            sys.exit(1)

    # 3. Webserver Orchestration
    print_banner()
    print_config_summary(config.__dict__)

    # 4. Verify Dagster Compatibility
    logger.info("Verifying Dagster API compatibility...")
    is_compatible, error = verify_dagster_api_compatibility()
    if not is_compatible:
        logger.error(f"CRITICAL COMPATIBILITY ERROR: {error}")
        sys.exit(1)
    logger.info("✅ Dagster API compatibility verified")

    # 5. Apply Monkey-Patches
    logger.info("Applying authentication patches...")
    try:
        apply_patches()
    except Exception as e:
        logger.critical(f"Fatal error during patching: {e}")
        sys.exit(1)

    # 6. Database Bootstrap (if using SQLite)
    if config.AUTH_BACKEND == "sqlite":
        logger.info("Initializing SQLite backend...")
        try:
            from dagster_authkit.auth.backends.sqlite import SQLiteAuthBackend

            # Backend initialization will create DB + admin if needed
            backend = SQLiteAuthBackend(config.__dict__)
            logger.info("✅ Database ready")
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
            # Continue anyway - user might fix it later

    # 7. Delegate to Dagster CLI
    logger.info("Patches active. Delegating to Dagster webserver...")

    dagster_cli_main = None

    try:
        # Modern path (Dagster 1.10+)
        from dagster_webserver.cli import main as webserver_main

        dagster_cli_main = webserver_main
        logger.debug("Using dagster_webserver.cli")
    except ImportError as e:
        logger.warning(f"Could not find 'dagster_webserver.cli': {e}")

        try:
            # Legacy fallback (Dagster < 1.10)
            from dagit.cli import main as dagit_main

            dagster_cli_main = dagit_main
            logger.debug("Using dagit.cli (legacy)")
        except ImportError:
            logger.error("CRITICAL: Dagster webserver CLI not found")
            print("\n" + "!" * 60)
            print("ERROR: Dagster webserver is not installed or not accessible.")
            print("Make sure you are in the correct environment and run:")
            print("    pip install dagster dagster-webserver")
            print("!" * 60 + "\n")
            sys.exit(1)

    # Modify process name for Click compatibility
    sys.argv[0] = "dagster"

    try:
        logger.info("🚀 Launching Dagster webserver...")
        dagster_cli_main()
    except Exception as e:
        logger.critical(f"Unexpected crash in delegated process: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
