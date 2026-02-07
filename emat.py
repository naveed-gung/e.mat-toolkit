#!/usr/bin/env python3
"""
E-MAT - ETHICAL Malware Analysis Toolkit
Smart Launcher with Interactive Interface Selection

Author: Naveed Gung
GitHub: https://github.com/naveed-gung
Portfolio: https://naveed-gung.dev
"""

import sys
import os
import json
import subprocess
import re
from pathlib import Path
from datetime import datetime

# Project root
PROJECT_ROOT = Path(__file__).parent

# Configuration file path
CONFIG_FILE = PROJECT_ROOT / '.emat_config.json'


# ============================================================
# Configuration Management
# ============================================================

def load_config():
    """Load user configuration"""
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            pass
    return {
        'preferred_interface': None,
        'first_run_complete': False,
        'history': [],
        'installed_interfaces': []
    }


def save_config(config):
    """Save user configuration"""
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)


def add_to_history(config, interface, action='launch'):
    """Add entry to usage history"""
    config['history'].append({
        'timestamp': datetime.now().isoformat(),
        'interface': interface,
        'action': action
    })
    # Keep only last 50 entries
    config['history'] = config['history'][-50:]


# ============================================================
# Virtual Environment Management
# ============================================================

def check_venv():
    """Check if running in virtual environment, activate if not"""
    in_venv = hasattr(sys, 'real_prefix') or (
        hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix
    )

    if not in_venv:
        venv_path = PROJECT_ROOT / 'venv'

        if venv_path.exists():
            if os.name == 'nt':
                python_exe = venv_path / 'Scripts' / 'python.exe'
            else:
                python_exe = venv_path / 'bin' / 'python'

            if python_exe.exists():
                print("Virtual environment detected but not active. Re-launching with venv...")
                result = subprocess.run(
                    [str(python_exe)] + sys.argv,
                    cwd=str(PROJECT_ROOT)
                )
                sys.exit(result.returncode)
            else:
                print("WARNING: venv found but python executable missing. Continuing without venv.")
        else:
            print("WARNING: No virtual environment found.")
            print("  Recommended: python -m venv venv")
            print("  Continuing without venv...\n")


# ============================================================
# Dependency Management (reads sections from requirements.txt)
# ============================================================

def parse_requirements_sections():
    """Parse requirements.txt into sections: core, desktop, web"""
    req_file = PROJECT_ROOT / 'requirements.txt'
    if not req_file.exists():
        return {'core': [], 'desktop': [], 'web': []}

    sections = {'core': [], 'desktop': [], 'web': []}
    current_section = 'core'

    with open(req_file, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                # Check for section markers
                if '# [desktop]' in line.lower():
                    current_section = 'desktop'
                elif '# [web]' in line.lower():
                    current_section = 'web'
                elif '# [core]' in line.lower():
                    current_section = 'core'
                continue
            sections[current_section].append(line)

    return sections


def get_packages_for_interface(interface):
    """Get the list of pip packages needed for a given interface"""
    sections = parse_requirements_sections()
    packages = list(sections['core'])  # Always include core

    if interface == 'desktop':
        packages.extend(sections['desktop'])
    elif interface == 'web':
        packages.extend(sections['web'])
    # CLI only needs core

    return packages


def check_dependencies_installed(interface):
    """Check if key dependencies for an interface are installed"""
    try:
        if interface == 'cli':
            import pefile  # noqa: F401
            return True
        elif interface == 'desktop':
            import PyQt6  # noqa: F401
            return True
        elif interface == 'web':
            import flask  # noqa: F401
            return True
    except ImportError:
        return False


def install_dependencies(interface):
    """Install only the packages needed for the selected interface"""
    packages = get_packages_for_interface(interface)

    if not packages:
        print("No packages to install.")
        return True

    print(f"\nInstalling dependencies for {interface.upper()} interface...")
    print(f"  Packages: {len(packages)}\n")

    result = subprocess.run(
        [sys.executable, '-m', 'pip', 'install'] + packages,
        cwd=str(PROJECT_ROOT)
    )

    if result.returncode == 0:
        print(f"\nDependencies installed successfully!\n")
        return True
    else:
        print(f"\nFailed to install dependencies. Check the error above.\n")
        return False


# ============================================================
# UI Helpers
# ============================================================

BANNER = r"""
  ███████╗      ███╗   ███╗ █████╗ ████████╗
  ██╔════╝      ████╗ ████║██╔══██╗╚══██╔══╝
  █████╗  █████╗██╔████╔██║███████║   ██║
  ██╔══╝  ╚════╝██║╚██╔╝██║██╔══██║   ██║
  ███████╗      ██║ ╚═╝ ██║██║  ██║   ██║
  ╚══════╝      ╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝
"""


def show_banner():
    """Display E-MAT banner"""
    print(BANNER)
    print("  ETHICAL Malware Analysis Toolkit")
    print("  GitHub:    https://github.com/naveed-gung")
    print("  Portfolio: https://naveed-gung.dev")
    print("\n" + "=" * 50 + "\n")


def prompt_interface_choice():
    """Prompt user to choose interface"""
    print("Choose your interface:\n")
    print("  [1] CLI      - Command-line interface")
    print("  [2] Desktop  - PyQt6 graphical interface")
    print("  [3] Web      - Flask web interface")
    print()

    while True:
        choice = input("Enter choice (1/2/3): ").strip()
        if choice == '1':
            return 'cli'
        elif choice == '2':
            return 'desktop'
        elif choice == '3':
            return 'web'
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")


def show_history(config):
    """Show recent usage history"""
    history = config.get('history', [])
    if not history:
        print("No usage history yet.\n")
        return
    print("\nRecent history (last 10):")
    for entry in history[-10:]:
        ts = entry.get('timestamp', '?')[:19]
        iface = entry.get('interface', '?').upper()
        action = entry.get('action', '?')
        print(f"  {ts}  {iface:8s}  {action}")
    print()


# ============================================================
# Interface Launchers
# ============================================================

def launch_cli_help():
    """Show CLI help and usage"""
    print("\nE-MAT CLI is ready!\n")
    print("Usage:")
    print("  python emat.py analyze <file>              - Analyze a file")
    print("  python emat.py analyze <file> --json        - JSON output")
    print("  python emat.py compare <file1> <file2>      - Compare two files")
    print("  python emat.py yara <file> --rules <path>   - YARA scan")
    print("  python emat.py collection <f1> <f2> ...     - Batch analysis")
    print("  python emat.py search --hash <hash>         - Search reports")
    print("  python emat.py string <file> --pattern <p>  - String search")
    print("  python emat.py server --start               - Start web server")
    print("  python emat.py desktop                      - Launch desktop GUI")
    print()


def launch_desktop():
    """Launch Desktop GUI"""
    sys.path.insert(0, str(PROJECT_ROOT))
    from DESKTOP_APP.main_window import launch_desktop_app
    launch_desktop_app()


def launch_web(port=5000):
    """Launch Web Server"""
    print(f"Starting web server on http://127.0.0.1:{port}")
    print("Press CTRL+C to quit\n")
    sys.path.insert(0, str(PROJECT_ROOT))
    from WEB_SERVICE.app import start_server
    start_server(port=port)


# ============================================================
# Interactive Launcher
# ============================================================

def interactive_launcher():
    """Interactive launcher with persistent preferences"""
    show_banner()

    config = load_config()

    # Check if user has a saved preference
    if config['preferred_interface'] and config['first_run_complete']:
        interface = config['preferred_interface']
        print(f"Saved preference: {interface.upper()} interface\n")

        choice = input(f"Use {interface.upper()} interface? [Y]es / [N]ew choice / [H]istory: ").strip().lower()

        if choice in ['n', 'new']:
            interface = prompt_interface_choice()
            save_pref = input(f"\nSave {interface.upper()} as new preference? (y/N): ").strip().lower()
            if save_pref in ['y', 'yes']:
                config['preferred_interface'] = interface
        elif choice in ['h', 'history']:
            show_history(config)
            interface = prompt_interface_choice()
            save_pref = input(f"\nSave {interface.upper()} as new preference? (y/N): ").strip().lower()
            if save_pref in ['y', 'yes']:
                config['preferred_interface'] = interface
        # else: use saved preference
    else:
        print("Welcome to E-MAT! Let's get started.\n")
        interface = prompt_interface_choice()

        save_pref = input(f"\nSave {interface.upper()} as preferred interface? (Y/n): ").strip().lower()
        if save_pref not in ['n', 'no']:
            config['preferred_interface'] = interface

        config['first_run_complete'] = True

    # Check and install dependencies if needed
    if not check_dependencies_installed(interface):
        print(f"\nDependencies for {interface.upper()} interface not found.")
        install_choice = input("Install now? (Y/n): ").strip().lower()

        if install_choice not in ['n', 'no']:
            if install_dependencies(interface):
                if interface not in config.get('installed_interfaces', []):
                    config.setdefault('installed_interfaces', []).append(interface)
            else:
                print("Cannot proceed without dependencies.")
                sys.exit(1)
        else:
            print("Cannot proceed without dependencies.")
            sys.exit(1)
    else:
        if interface not in config.get('installed_interfaces', []):
            config.setdefault('installed_interfaces', []).append(interface)

    # Add to history and save config
    add_to_history(config, interface)
    save_config(config)

    # Launch the interface
    if interface == 'cli':
        launch_cli_help()
    elif interface == 'desktop':
        launch_desktop()
    elif interface == 'web':
        launch_web()


# ============================================================
# CLI Argument Mode
# ============================================================

def cli_mode():
    """Handle CLI arguments for direct command execution"""
    import argparse

    sys.path.insert(0, str(PROJECT_ROOT))

    parser = argparse.ArgumentParser(
        description=BANNER + 
            '  ETHICAL Malware Analysis Toolkit\n'
            '  GitHub:    https://github.com/naveed-gung\n'
            '  Portfolio: https://naveed-gung.dev\n',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Run without arguments for interactive mode."
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # analyze
    ap = subparsers.add_parser('analyze', help='Analyze a file')
    ap.add_argument('file', help='File to analyze')
    ap.add_argument('--json', action='store_true', help='JSON output')
    ap.add_argument('--safe-sandbox', action='store_true', help='Enable sandboxed analysis')
    ap.add_argument('--report', choices=['html', 'pdf'], help='Generate report')

    # compare
    cp = subparsers.add_parser('compare', help='Compare two files')
    cp.add_argument('file1', help='First file')
    cp.add_argument('file2', help='Second file')

    # yara
    yp = subparsers.add_parser('yara', help='YARA scan')
    yp.add_argument('file', help='File to scan')
    yp.add_argument('--rules', required=True, help='Path to YARA rules')

    # collection
    colp = subparsers.add_parser('collection', help='Batch file analysis')
    colp.add_argument('files', nargs='+', help='Files to analyze')
    colp.add_argument('--json', action='store_true', help='JSON output')

    # search
    sp = subparsers.add_parser('search', help='Search past reports')
    sp.add_argument('--hash', help='Search by hash')
    sp.add_argument('--name', help='Search by filename')
    sp.add_argument('--query', '-q', help='General search query')

    # string
    strp = subparsers.add_parser('string', help='String/hex pattern search')
    strp.add_argument('file', help='File to search in')
    strp.add_argument('--pattern', '-p', required=True, help='Pattern to search')

    # server
    svp = subparsers.add_parser('server', help='Start web server')
    svp.add_argument('--start', action='store_true', help='Start server')
    svp.add_argument('--port', type=int, default=5000, help='Port number')

    # desktop
    subparsers.add_parser('desktop', help='Launch desktop GUI')

    args = parser.parse_args()

    if args.command == 'analyze':
        from CLI_TOOL.commands.analyze import analyze_file
        analyze_file(args.file, args.safe_sandbox, args.json, args.report)

    elif args.command == 'compare':
        from CLI_TOOL.commands.compare import compare_files
        compare_files(args.file1, args.file2)

    elif args.command == 'yara':
        from CLI_TOOL.commands.yara_scan import yara_scan
        yara_scan(args.file, args.rules)

    elif args.command == 'collection':
        from CLI_TOOL.commands.collection import collection_analyze
        collection_analyze(args.files, args.json)

    elif args.command == 'search':
        from CLI_TOOL.commands.search import search_reports
        query = args.hash or args.name or args.query or ''
        search_reports(query)

    elif args.command == 'string':
        from CLI_TOOL.commands.string_search import string_search
        string_search(args.file, args.pattern)

    elif args.command == 'server':
        if args.start:
            launch_web(args.port)
        else:
            print("Use --start to start the server.")

    elif args.command == 'desktop':
        launch_desktop()

    else:
        parser.print_help()


# ============================================================
# Main Entry Point
# ============================================================

def main():
    """Main entry point"""
    check_venv()

    if len(sys.argv) > 1:
        cli_mode()
    else:
        interactive_launcher()


if __name__ == '__main__':
    main()
