#!/usr/bin/env python3
"""
VIPER - CVE Intelligence and Prioritization Engine
Main entry point script with command line interface.
"""
import argparse
import os
import subprocess
import sys


def run_dashboard():
    """Launch the Streamlit dashboard."""
    print("Starting VIPER dashboard...")
    subprocess.run(["streamlit", "run", "src/dashboard/app.py"])


def run_cli(days=7):
    """Run the CLI application to fetch and analyze CVEs."""
    from src.main_mvp import run_cti_feed

    run_cti_feed(days_back=days)


def main():
    """Main entry point for the application."""
    parser = argparse.ArgumentParser(description="VIPER - CVE Intelligence and Prioritization Engine")
    subparsers = parser.add_subparsers(dest="command")

    # Dashboard command
    dashboard_parser = subparsers.add_parser("dashboard", help="Launch the interactive dashboard")

    # CLI command
    cli_parser = subparsers.add_parser("cli", help="Run the CLI application")
    cli_parser.add_argument("--days", type=int, default=7, help="Number of days to look back for CVEs (default: 7)")

    args = parser.parse_args()

    if args.command == "dashboard":
        run_dashboard()
    elif args.command == "cli":
        run_cli(days=args.days)
    else:
        # Default to showing help if no command specified
        parser.print_help()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
