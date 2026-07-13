"""
Display Utilities - AuthKit UI for Terminal
"""


def print_banner():
    """
    Prints the Dagster AuthKit startup banner.
    """
    banner = r"""
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║        🔒  DAGSTER AUTHKIT  🔒                             ║
    ║                                                           ║
    ║        Secure Authentication Layer for Dagster OSS        ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    print(banner)


def print_config_summary(config_dict):
    """
    Prints a sanitized summary of the current security configuration.
    """
    print("\n🔧 Current Configuration Summary:")
    print("─────────────────────────────────────────────")
    for key, value in config_dict.items():
        # Mask sensitive keys
        if any(secret in key.upper() for secret in ["PASSWORD", "SECRET", "KEY", "TOKEN"]):
            display_value = "********"
        else:
            display_value = value
        print(f"• {key}: {display_value}")
    print("─────────────────────────────────────────────\n")


def show_security_banner(admin_pw: str):
    """
    Display first-run credentials with a high-visibility border.

    Args:
        admin_pw: Auto-generated admin password to display.
    """
    width = 60
    header = "🚀 FIRST RUN: ADMIN ACCOUNT CREATED"

    print("\n" + "╔" + "═" * (width - 2) + "╗")
    print(f"║ {header:^{width - 4}} ║")
    print("╠" + "═" * (width - 2) + "╣")
    print(f"║  Username: admin" + " " * (width - 20) + "║")
    print(f"║  Password: {admin_pw}" + " " * (width - 13 - len(admin_pw)) + "║")
    print("╠" + "═" * (width - 2) + "╣")
    print(f"║ {'⚠️  SAVE THIS PASSWORD! It will not be shown again.':^{width - 4}} ║")
    print("╚" + "═" * (width - 2) + "╝\n")
