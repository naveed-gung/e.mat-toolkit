"""
E.MAT CLI Theme System
Centralized theming for consistent terminal output
"""

from colorama import Fore, Back, Style, init
import sys

# Initialize colorama
init(autoreset=True)

# Color Scheme (matching design system)
class Colors:
    # Primary colors
    PRIMARY = Fore.CYAN  # Closest to #4a9eff
    PRIMARY_BRIGHT = Fore.LIGHTCYAN_EX
    SUCCESS = Fore.GREEN  # #10b981
    WARNING = Fore.YELLOW  # #f59e0b
    DANGER = Fore.RED  # #ef4444
    ACCENT = Fore.MAGENTA  # #8b5cf6
    
    # Text colors
    TEXT_PRIMARY = Fore.WHITE  # #e5e7eb
    TEXT_SECONDARY = Fore.LIGHTBLACK_EX  # #9ca3af
    TEXT_MUTED = Fore.LIGHTBLACK_EX
    
    # Special
    RESET = Style.RESET_ALL
    BOLD = Style.BRIGHT
    DIM = Style.DIM


# ASCII Art Logo
LOGO = f"""{Colors.PRIMARY}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ███████╗      ███╗   ███╗ █████╗ ████████╗                ║
║   ██╔════╝      ████╗ ████║██╔══██╗╚══██╔══╝                ║
║   █████╗  █████╗██╔████╔██║███████║   ██║                   ║
║   ██╔══╝  ╚════╝██║╚██╔╝██║██╔══██║   ██║                   ║
║   ███████╗      ██║ ╚═╝ ██║██║  ██║   ██║                   ║
║   ╚══════╝      ╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝                   ║
║                                                               ║
║        {Colors.TEXT_SECONDARY}ETHICAL Malware Analysis Toolkit{Colors.PRIMARY}                    ║
║        {Colors.TEXT_MUTED}For Educational & Authorized Research Only{Colors.PRIMARY}            ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
{Colors.RESET}"""

# Branding Footer
BRANDING = f"""
{Colors.TEXT_SECONDARY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{Colors.TEXT_PRIMARY}Created by: {Colors.PRIMARY}Naveed Gung
{Colors.TEXT_PRIMARY}GitHub:     {Colors.PRIMARY}https://github.com/naveed-gung
{Colors.TEXT_PRIMARY}Portfolio:  {Colors.PRIMARY}https://naveed-gung.dev
{Colors.TEXT_SECONDARY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{Colors.RESET}"""


def print_logo():
    """Print the E.MAT logo"""
    print(LOGO)


def print_branding():
    """Print branding footer"""
    print(BRANDING)


def print_header(text, char="═"):
    """Print a styled header"""
    width = 65
    print(f"\n{Colors.PRIMARY}{Colors.BOLD}{char * width}")
    print(f"{text.center(width)}")
    print(f"{char * width}{Colors.RESET}\n")


def print_section(title):
    """Print a section title"""
    print(f"\n{Colors.PRIMARY}{Colors.BOLD}▶ {title}{Colors.RESET}")
    print(f"{Colors.TEXT_SECONDARY}{'─' * 60}{Colors.RESET}")


def print_success(text):
    """Print success message"""
    print(f"{Colors.SUCCESS}✓ {text}{Colors.RESET}")


def print_error(text):
    """Print error message"""
    print(f"{Colors.DANGER}✗ {text}{Colors.RESET}")


def print_warning(text):
    """Print warning message"""
    print(f"{Colors.WARNING}⚠ {text}{Colors.RESET}")


def print_info(text):
    """Print info message"""
    print(f"{Colors.PRIMARY}ℹ {text}{Colors.RESET}")


def print_key_value(key, value, color=Colors.TEXT_PRIMARY):
    """Print key-value pair"""
    print(f"{Colors.TEXT_SECONDARY}{key:.<30} {color}{value}{Colors.RESET}")


def print_progress_bar(current, total, prefix="Progress", length=40):
    """Print a progress bar"""
    percent = current / total
    filled = int(length * percent)
    bar = "█" * filled + "░" * (length - filled)
    
    print(f"\r{Colors.PRIMARY}{prefix}: {Colors.TEXT_PRIMARY}[{bar}] {Colors.PRIMARY}{int(percent * 100)}%{Colors.RESET}", end="")
    
    if current == total:
        print()  # New line when complete


def print_table_header(*columns):
    """Print table header"""
    col_width = 20
    header = " ".join([f"{col:<{col_width}}" for col in columns])
    print(f"\n{Colors.BOLD}{Colors.PRIMARY}{header}{Colors.RESET}")
    print(f"{Colors.TEXT_SECONDARY}{'─' * (col_width * len(columns) + len(columns) - 1)}{Colors.RESET}")


def print_table_row(*values, color=Colors.TEXT_PRIMARY):
    """Print table row"""
    col_width = 20
    row = " ".join([f"{str(val):<{col_width}}" for val in values])
    print(f"{color}{row}{Colors.RESET}")


def print_box(text, style="info"):
    """Print text in a box"""
    width = 65
    
    if style == "success":
        border_color = Colors.SUCCESS
    elif style == "error":
        border_color = Colors.DANGER
    elif style == "warning":
        border_color = Colors.WARNING
    else:
        border_color = Colors.PRIMARY
    
    lines = text.split("\n")
    
    print(f"\n{border_color}╔{'═' * (width - 2)}╗")
    for line in lines:
        padding = width - len(line) - 4
        print(f"║ {Colors.TEXT_PRIMARY}{line}{' ' * padding}{border_color} ║")
    print(f"╚{'═' * (width - 2)}╝{Colors.RESET}\n")


def clear_line():
    """Clear current line"""
    print("\r" + " " * 80 + "\r", end="")


def print_spinner(text, step=0):
    """Print animated spinner"""
    spinners = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    spinner = spinners[step % len(spinners)]
    print(f"\r{Colors.PRIMARY}{spinner} {text}{Colors.RESET}", end="")
    sys.stdout.flush()
