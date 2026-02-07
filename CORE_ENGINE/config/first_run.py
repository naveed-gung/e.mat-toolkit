"""
ETHICAL Malware Analysis Toolkit (E-MAT)
First Run Setup

Interactive setup wizard that:
1. Displays ethical pledge and guidelines
2. Asks user to select preferred component
3. Checks for Docker installation
4. Creates configuration and saves preferences
5. Provides quick start guide
"""

import sys
import os
from pathlib import Path
from typing import Optional

try:
    import docker
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False

from .preferences import PreferencesManager, Component


class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def print_colored(text: str, color: str = Colors.ENDC):
    """Print colored text"""
    print(f"{color}{text}{Colors.ENDC}")


def print_banner():
    """Print E-MAT banner"""
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ETHICAL Malware Analysis Toolkit (E-MAT)                   ║
║   Version 1.0.0                                               ║
║                                                               ║
║   Defense through Education and Transparency                  ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
    """
    print_colored(banner, Colors.CYAN + Colors.BOLD)


def display_ethical_pledge():
    """Display the ethical pledge"""
    print_colored("\n" + "="*65, Colors.YELLOW)
    print_colored("ETHICAL PLEDGE - PLEASE READ CAREFULLY", Colors.YELLOW + Colors.BOLD)
    print_colored("="*65 + "\n", Colors.YELLOW)
    
    pledge = """
This toolkit is designed EXCLUSIVELY for:
  ✓ Educational purposes
  ✓ Authorized security research
  ✓ Improving defensive capabilities
  ✓ Learning cybersecurity concepts

This toolkit must NEVER be used for:
  ✗ Unauthorized access to systems
  ✗ Attacking or compromising systems
  ✗ Malicious purposes
  ✗ Violating laws or regulations

By continuing, you acknowledge that you have read and agree to
abide by the ETHICAL_PLEDGE.md and will use this toolkit
responsibly and legally.

MISUSE MAY RESULT IN CRIMINAL PROSECUTION.
    """
    print(pledge)
    
    print_colored("="*65 + "\n", Colors.YELLOW)


def get_user_consent() -> bool:
    """Get user consent to ethical pledge"""
    while True:
        response = input(f"{Colors.BOLD}Do you agree to use E-MAT ethically and legally? (yes/no): {Colors.ENDC}").strip().lower()
        if response in ['yes', 'y']:
            return True
        elif response in ['no', 'n']:
            print_colored("\nYou must agree to the ethical pledge to use E-MAT.", Colors.RED)
            print_colored("Installation cancelled.\n", Colors.RED)
            return False
        else:
            print_colored("Please answer 'yes' or 'no'.", Colors.YELLOW)


def check_docker() -> bool:
    """Check if Docker is available"""
    if not DOCKER_AVAILABLE:
        return False
    
    try:
        client = docker.from_env()
        client.ping()
        return True
    except Exception:
        return False


def select_component() -> Optional[Component]:
    """Interactive component selection"""
    print_colored("\n" + "="*65, Colors.CYAN)
    print_colored("COMPONENT SELECTION", Colors.CYAN + Colors.BOLD)
    print_colored("="*65 + "\n", Colors.CYAN)
    
    print("E-MAT provides three interfaces for malware analysis:\n")
    
    print_colored("1. CLI (Command-Line Interface)", Colors.GREEN + Colors.BOLD)
    print("   • Fast and scriptable")
    print("   • Perfect for automation and batch processing")
    print("   • Lightweight and efficient")
    print("   • Ideal for: Terminal users, automation, CI/CD pipelines\n")
    
    print_colored("2. Desktop (GUI Application)", Colors.GREEN + Colors.BOLD)
    print("   • Visual and interactive")
    print("   • Hex viewer, string viewer, disassembly view")
    print("   • Drag-and-drop file loading")
    print("   • Ideal for: Interactive analysis, learning, visual exploration\n")
    
    print_colored("3. Server (REST API)", Colors.GREEN + Colors.BOLD)
    print("   • Web service with REST API")
    print("   • Integration with other tools")
    print("   • Background job processing")
    print("   • Ideal for: Automation, integration, multi-user environments\n")
    
    print_colored("="*65 + "\n", Colors.CYAN)
    
    while True:
        choice = input(f"{Colors.BOLD}Select your preferred component (1/2/3): {Colors.ENDC}").strip()
        
        if choice == '1':
            return Component.CLI
        elif choice == '2':
            return Component.DESKTOP
        elif choice == '3':
            return Component.SERVER
        else:
            print_colored("Please enter 1, 2, or 3.", Colors.YELLOW)


def display_quick_start(component: Component, docker_available: bool):
    """Display quick start guide based on selected component"""
    print_colored("\n" + "="*65, Colors.GREEN)
    print_colored("SETUP COMPLETE!", Colors.GREEN + Colors.BOLD)
    print_colored("="*65 + "\n", Colors.GREEN)
    
    print(f"Your preferred component: {Colors.BOLD}{component.value.upper()}{Colors.ENDC}\n")
    
    if not docker_available:
        print_colored("⚠ Docker not detected:", Colors.YELLOW + Colors.BOLD)
        print("  Dynamic analysis features will be unavailable.")
        print("  Install Docker to enable sandboxed execution.\n")
    else:
        print_colored("✓ Docker detected:", Colors.GREEN + Colors.BOLD)
        print("  Dynamic analysis available with --safe-sandbox flag.\n")
    
    print_colored("Quick Start Guide:", Colors.CYAN + Colors.BOLD)
    print_colored("-" * 65, Colors.CYAN)
    
    if component == Component.CLI:
        print(f"\n{Colors.BOLD}Analyze a file (static only):{Colors.ENDC}")
        print("  python -m emat analyze <file>")
        print(f"\n{Colors.BOLD}Analyze with sandboxing (requires Docker):{Colors.ENDC}")
        print("  python -m emat analyze --safe-sandbox <file>")
        print(f"\n{Colors.BOLD}Scan with YARA rules:{Colors.ENDC}")
        print("  python -m emat yara <file> --rules <path>")
        print(f"\n{Colors.BOLD}Compare two files:{Colors.ENDC}")
        print("  python -m emat compare <file1> <file2>")
    
    elif component == Component.DESKTOP:
        print(f"\n{Colors.BOLD}Launch the desktop application:{Colors.ENDC}")
        print("  python -m emat desktop")
        print(f"\n{Colors.BOLD}Features:{Colors.ENDC}")
        print("  • Drag and drop files to analyze")
        print("  • Hex viewer with syntax highlighting")
        print("  • String viewer with filtering")
        print("  • Interactive report viewer")
    
    elif component == Component.SERVER:
        print(f"\n{Colors.BOLD}Start the API server:{Colors.ENDC}")
        print("  python -m emat server --start --port 8080")
        print(f"\n{Colors.BOLD}API Endpoints:{Colors.ENDC}")
        print("  POST /api/v1/analyze/static    - Static analysis")
        print("  POST /api/v1/analyze/dynamic   - Sandboxed analysis")
        print("  GET  /api/v1/report/<task_id>  - Get results")
        print("  POST /api/v1/yara/scan         - YARA scan")
    
    print(f"\n{Colors.BOLD}Change component anytime:{Colors.ENDC}")
    print("  python -m emat config --set-component [cli|desktop|server]")
    
    print(f"\n{Colors.BOLD}Documentation:{Colors.ENDC}")
    print("  • ETHICAL_PLEDGE.md - Ethical guidelines")
    print("  • DOCUMENTATION/02_GETTING_STARTED.md - Detailed guide")
    print("  • DOCUMENTATION/03_SAFETY_PROTOCOLS.md - Safety best practices")
    
    print_colored("\n" + "="*65, Colors.GREEN)
    print_colored("Happy (ethical) analyzing! [#]", Colors.GREEN + Colors.BOLD)
    print_colored("="*65 + "\n", Colors.GREEN)


def run_first_time_setup() -> bool:
    """Run the first-time setup wizard"""
    prefs = PreferencesManager()
    
    # Print banner
    print_banner()
    
    # Display ethical pledge
    display_ethical_pledge()
    
    # Get user consent
    if not get_user_consent():
        return False
    
    # Select component
    component = select_component()
    if not component:
        return False
    
    # Check Docker
    print_colored("\nChecking for Docker installation...", Colors.CYAN)
    docker_available = check_docker()
    
    # Save preferences
    prefs.set_preferred_component(component)
    prefs.set_docker_available(docker_available)
    prefs.mark_first_run_complete()
    
    # Display quick start guide
    display_quick_start(component, docker_available)
    
    return True


if __name__ == "__main__":
    success = run_first_time_setup()
    sys.exit(0 if success else 1)
