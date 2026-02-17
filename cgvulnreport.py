#!/usr/bin/env python3
"""
Chainguard Vulnerability Comparison Tool
Compares vulnerabilities between standard container images and Chainguard equivalents.
"""

import argparse
import logging
import subprocess
import sys
from pathlib import Path
from typing import Optional

from src.scanner import ImageScanner
from src.report_generator import ReportGenerator
from src.utils import print_header, print_section, print_error, print_success

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s: %(message)s'
)


def setup_environment() -> bool:
    """Set up Python virtual environment and install dependencies."""
    venv_path = Path(".venv")

    if not venv_path.exists():
        print_section("Creating Python virtual environment...")
        result = subprocess.run(
            [sys.executable, "-m", "venv", ".venv"],
            capture_output=True
        )
        if result.returncode != 0:
            print_error("Failed to create virtual environment")
            return False

    # Check if dependencies are installed
    try:
        import pandas
        import requests
    except ImportError:
        print_section("Installing required Python packages...")
        pip_path = venv_path / "bin" / "pip"
        result = subprocess.run(
            [str(pip_path), "install", "-r", "requirements.txt"],
            capture_output=True
        )
        if result.returncode != 0:
            print_error("Failed to install required Python packages")
            return False
        print_success("Dependencies installed")

    return True


def authenticate_chainguard() -> bool:
    """Authenticate with Chainguard registry."""
    result = subprocess.run(["chainctl", "auth", "login"])
    return result.returncode == 0


def main():
    parser = argparse.ArgumentParser(
        description="Compare vulnerabilities between standard images and Chainguard equivalents"
    )
    parser.add_argument(
        "original_images",
        help="Path to file containing original image list"
    )
    parser.add_argument(
        "chainguard_images",
        help="Path to file containing Chainguard image list"
    )
    parser.add_argument(
        "--check-pullable",
        action="store_true",
        help="Verify that all images are pullable before scanning"
    )
    parser.add_argument(
        "--skip-scan-original",
        action="store_true",
        help="Skip scanning the original images (uses existing out.txt/out.json)"
    )
    parser.add_argument(
        "--skip-scan-chainguard",
        action="store_true",
        help="Skip scanning Chainguard images (uses existing cgout.txt/cgout.json)"
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=4,
        help="Number of parallel scan threads (default: 4)"
    )
    parser.add_argument(
        "--logo",
        type=str,
        default=None,
        help="Path to company logo image file (e.g., logo.png)"
    )

    args = parser.parse_args()

    # Validate input files
    original_path = Path(args.original_images)
    chainguard_path = Path(args.chainguard_images)

    if not original_path.exists():
        print_error(f"Original images file not found: {original_path}")
        sys.exit(1)

    if not chainguard_path.exists():
        print_error(f"Chainguard images file not found: {chainguard_path}")
        sys.exit(1)

    # Print header
    print_header()

    # Authenticate with Chainguard
    if not authenticate_chainguard():
        print_error("Failed to authenticate with Chainguard")
        sys.exit(1)

    # Set up environment
    if not setup_environment():
        sys.exit(3)

    # Initialize scanner
    scanner = ImageScanner(threads=args.threads)

    # Check image pullability if requested
    if args.check_pullable:
        print_section("Checking image pullability...")

        if not scanner.check_pullable(original_path):
            print_error(f"Some images in {original_path} are not pullable")
            sys.exit(1)

        if not scanner.check_pullable(chainguard_path):
            print_error(f"Some images in {chainguard_path} are not pullable")
            sys.exit(1)

        print_success("All images are pullable")
    else:
        print("⏭️  Skipping pullable check (use --check-pullable to enable)\n")

    # Scan original images
    scan_original = not args.skip_scan_original
    original_results = None

    if scan_original:
        print_section(f"Scanning original images (threads: {args.threads})...")
        original_results = scanner.scan_images(original_path, "out")

        if original_results is None:
            print_error("Scan failed for original images")
            sys.exit(1)

        print_success("Original image scan complete")
    else:
        print("⏭️  Skipping original image scan (using existing files)\n")
        if not Path("out.txt").exists() or not Path("out.json").exists():
            print_error("Cannot skip scan - output files not found")
            print_error("Run without --skip-scan-original to generate these files first")
            sys.exit(1)
        original_results = scanner.load_existing_results("out")

    # Scan Chainguard images
    scan_chainguard = not args.skip_scan_chainguard
    chainguard_results = None

    if scan_chainguard:
        print_section(f"Scanning Chainguard images (threads: {args.threads})...")
        chainguard_results = scanner.scan_images(chainguard_path, "cgout")

        if chainguard_results is None:
            print_error("Scan failed for Chainguard images")
            sys.exit(1)

        print_success("Chainguard image scan complete")
    else:
        print("⏭️  Skipping Chainguard image scan (using existing files)\n")
        if not Path("cgout.txt").exists() or not Path("cgout.json").exists():
            print_error("Cannot skip scan - output files not found")
            print_error("Run without --skip-scan-chainguard to generate these files first")
            sys.exit(1)
        chainguard_results = scanner.load_existing_results("cgout")

    # Generate report
    print_section("Generating HTML report...")

    generator = ReportGenerator(
        original_results=original_results,
        chainguard_results=chainguard_results,
        scanner=scanner,
        logo_path=args.logo
    )

    if not generator.generate():
        print_error("Failed to generate report")
        sys.exit(1)

    # Print completion message
    print("\n" + "="*52)
    print("✅ Report Generation Complete")
    print("="*52 + "\n")
    print("📊 Generated Report:")
    print("   📄 report.html\n")
    print("📋 Next steps:")
    print("   1️⃣  Open report.html in your browser")
    print("   2️⃣  Review the vulnerability analysis and KPI metrics")
    print("   3️⃣  Print to PDF (Cmd+P) for professional sharing\n")


if __name__ == "__main__":
    main()
