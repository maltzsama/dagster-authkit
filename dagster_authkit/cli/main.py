#!/usr/bin/env python3
"""
Dagster AuthKit CLI Entry Point
Main orchestrator for the dagster-authkit package.
"""

import sys

from dagster_authkit.auth.manager import bootstrap_db
from dagster_authkit.core.detection_layer import verify_dagster_api_compatibility
from dagster_authkit.core.patch import apply_patches
from dagster_authkit.utils.config import config
from dagster_authkit.utils.display import print_banner, print_config_summary, show_security_banner
from dagster_authkit.utils.logging import setup_logging


def main():
    """
    Main execution flow:
    1. Initialize system logging.
    2. Route to User Management CLI if requested.
    3. Perform compatibility checks and patching.
    4. Bootstrap database and manage first-run credentials.
    5. Delegate to Dagster webserver CLI.
    """

    # 1. Initialize logging
    logger = setup_logging()

    # 2. Intercept User Management commands
    management_commands = ["add-user", "list-users", "init-db", "delete-user", "change-password"]
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
    logger.info("Dagster API compatibility verified.")

    # 5. Apply Monkey-Patches
    logger.info("Applying authentication patches...")
    try:
        apply_patches()
    except Exception as e:
        logger.critical(f"Fatal error during patching: {e}")
        sys.exit(1)

    # 6. Database and Admin Bootstrap
    logger.info("Ensuring database state...")
    admin_pw = bootstrap_db()
    if admin_pw:
        show_security_banner(admin_pw)

    # 7. Delegate to Dagster CLI with Fallback Protection
    # We try both the modern 'dagster_webserver' and the legacy 'dagit' paths.
    logger.info("Patches active. Delegating to original Dagster CLI.")

    dagster_cli_main = None

    # Check current PYTHONPATH for debugging
    logger.debug(f"Python Path: {sys.path}")

    try:
        # Standard modern path (Dagster 1.10+)
        from dagster_webserver.cli import main as webserver_main

        dagster_cli_main = webserver_main
    except ImportError as e:
        logger.warning(f"Could not find 'dagster_webserver.cli': {e}")
        try:
            # Fallback for older versions
            from dagit.cli import main as dagit_main

            dagster_cli_main = dagit_main
        except ImportError:
            logger.error("CRITICAL: Dagster webserver CLI not found in current environment.")
            print("\n" + "!" * 60)
            print("ERROR: Dagster webserver is not installed or not accessible.")
            print("Make sure you are in the correct environment and run:")
            print("pip install dagster-webserver")
            print("!" * 60 + "\n")
            sys.exit(1)

    # Modify process name to ensure Click/Dagster commands behave correctly
    sys.argv[0] = "dagster-webserver"

    try:
        logger.info("🚀 Launching Dagster core engine...")
        dagster_cli_main()
    except Exception as e:
        logger.critical(f"Unexpected crash in delegated process: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
