#!/usr/bin/env python

import argparse
import subprocess
import json
import sys

def run_scanner(scanner, image):
    try:
        if scanner == "trivy":
            result = subprocess.run([
                "trivy",
                "image",
                "--format",
                "json",
                image
            ], capture_output=True, text=True)
        elif scanner == "grype":
            result = subprocess.run([
                "grype",
                image,
                "-o",
                "json"
            ], capture_output=True, text=True)
        else:
            raise ValueError(f"Unsupported scanner: {scanner}")

        if result.returncode != 0:
            print(f"Error running {scanner}: {result.stderr}", file=sys.stderr)
            return None

        return json.loads(result.stdout)
    except Exception as e:
        print(f"An error occurred while running {scanner}: {e}", file=sys.stderr)
        return None

def check_scanners():
    import shutil
    for scanner in ["trivy", "grype"]:
        if not shutil.which(scanner):
            print(f"Error: {scanner} is not in the executable path.", file=sys.stderr)
            sys.exit(1)

def calculate_totals(results):
    totals = {
        "total_count": 0,
        "total_critical": 0,
        "total_high": 0,
        "total_medium": 0,
        "total_low": 0,
        "total_unknown": 0,
        "total_fixes": 0,
        "critical_fixes": 0,
        "high_fixes": 0,
        "medium_fixes": 0,
        "low_fixes": 0,
    }

    for scanner, scans in results.items():
        for data in scans:
            if isinstance(data, dict):
                if scanner == "trivy":
                    results_list = data.get("Results", [])
                    for result in results_list:
                        vulnerabilities = result.get("Vulnerabilities", [])
                        for vuln in vulnerabilities:
                            severity = vuln.get("Severity", "").lower()
                            fixed = vuln.get("FixedVersion") is not None
                            if severity == "critical":
                                totals["total_critical"] += 1
                                if fixed:
                                    totals["critical_fixes"] += 1
                            elif severity == "high":
                                totals["total_high"] += 1
                                if fixed:
                                    totals["high_fixes"] += 1
                            elif severity == "medium":
                                totals["total_medium"] += 1
                                if fixed:
                                    totals["medium_fixes"] += 1
                            elif severity == "low":
                                totals["total_low"] += 1
                                if fixed:
                                    totals["low_fixes"] += 1
                            else:
                                totals["total_unknown"] += 1
                            if fixed:
                                totals["total_fixes"] += 1
                            totals["total_count"] += 1
                elif scanner == "grype":
                    matches = data.get("matches", [])
                    for match in matches:
                        severity = match.get("vulnerability", {}).get("severity", "").lower()
                        fixed = match.get("vulnerability", {}).get("fix", {}).get("state") == "fixed"
                        if severity == "critical":
                            totals["total_critical"] += 1
                            if fixed:
                                totals["critical_fixes"] += 1
                        elif severity == "high":
                            totals["total_high"] += 1
                            if fixed:
                                totals["high_fixes"] += 1
                        elif severity == "medium":
                            totals["total_medium"] += 1
                            if fixed:
                                totals["medium_fixes"] += 1
                        elif severity == "low":
                            totals["total_low"] += 1
                            if fixed:
                                totals["low_fixes"] += 1
                        else:
                            totals["total_unknown"] += 1
                        if fixed:
                            totals["total_fixes"] += 1
                        totals["total_count"] += 1

    return totals

def process_images(images, scanners):
    combined_results = {}

    for image in images:
        for scanner in scanners:
            print(f"Running {scanner} scanner on image: {image}...")
            scan_result = run_scanner(scanner, image)
            if scan_result is not None:
                if scanner not in combined_results:
                    combined_results[scanner] = []
                combined_results[scanner].append(scan_result)

    return calculate_totals(combined_results)

def main():
    import shutil
    check_scanners()

    parser = argparse.ArgumentParser(description="Frontend for Trivy and Grype vulnerability scanners.")
    parser.add_argument(
        "--scanner",
        choices=["trivy", "grype", "both"],
        default="both",
        help="Specify which scanner to use. Defaults to 'both'."
    )
    parser.add_argument(
        "--originallist",
        help="A text file containing a line-by-line list of original images to scan.",
        required=True
    )
    parser.add_argument(
        "--newlist",
        help="A text file containing a line-by-line list of new images to scan.",
        required=True
    )

    args = parser.parse_args()

    scanners = [args.scanner] if args.scanner != "both" else ["trivy", "grype"]

    original_images = []
    new_images = []

    try:
        with open(args.originallist, "r") as file:
            original_images = [line.strip() for line in file if line.strip()]
    except Exception as e:
        print(f"Error reading file {args.originallist}: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        with open(args.newlist, "r") as file:
            new_images = [line.strip() for line in file if line.strip()]
    except Exception as e:
        print(f"Error reading file {args.newlist}: {e}", file=sys.stderr)
        sys.exit(1)

    print("Processing original images...")
    original_totals = process_images(original_images, scanners)
    print("\nOriginal List Results:")
    print(f"Total Vulnerabilities: {original_totals['total_count']}")
    print(f"Total Critical CVEs: {original_totals['total_critical']}")
    print(f"Total High CVEs: {original_totals['total_high']}")
    print(f"Total Medium CVEs: {original_totals['total_medium']}")
    print(f"Total Low CVEs: {original_totals['total_low']}")
    print(f"Total Unknown CVEs: {original_totals['total_unknown']}")

    print("\nProcessing new images...")
    new_totals = process_images(new_images, scanners)
    print("\nNew List Results:")
    print(f"Total Vulnerabilities: {new_totals['total_count']}")
    print(f"Total Critical CVEs: {new_totals['total_critical']}")
    print(f"Total High CVEs: {new_totals['total_high']}")
    print(f"Total Medium CVEs: {new_totals['total_medium']}")
    print(f"Total Low CVEs: {new_totals['total_low']}")
    print(f"Total Unknown CVEs: {new_totals['total_unknown']}")

    # Key Insights
    print("\nKey Insights:")
    print(f"Critical CVEs decreased from {original_totals['total_critical']} to {new_totals['total_critical']}.")
    print(f"High CVEs dropped from {original_totals['total_high']} to {new_totals['total_high']}.")
    print(f"Medium CVEs dropped from {original_totals['total_medium']} to {new_totals['total_medium']}.")
    print(f"Low CVEs dropped from {original_totals['total_low']} to {new_totals['total_low']}.")
    print(f"Unknown CVEs dropped from {original_totals['total_unknown']} to {new_totals['total_unknown']}.")

    # Reduction Table
    print("\nSeverity\tOriginal\tNew\tReduction")
    print(f"Critical\t{original_totals['total_critical']}\t{new_totals['total_critical']}\t{original_totals['total_critical'] - new_totals['total_critical']}")
    print(f"High\t{original_totals['total_high']}\t{new_totals['total_high']}\t{original_totals['total_high'] - new_totals['total_high']}")
    print(f"Medium\t{original_totals['total_medium']}\t{new_totals['total_medium']}\t{original_totals['total_medium'] - new_totals['total_medium']}")
    print(f"Low\t{original_totals['total_low']}\t{new_totals['total_low']}\t{original_totals['total_low'] - new_totals['total_low']}")
    print(f"Unknown\t{original_totals['total_unknown']}\t{new_totals['total_unknown']}\t{original_totals['total_unknown'] - new_totals['total_unknown']}")

    # Fixes Available Summary Original List
    print("\nFixes Available Summary (Original List):")
    print("Fix Type\tTotal\tAverage")
    print(f"Fixes Available\t{original_totals['total_fixes']}\t{original_totals['total_fixes'] / len(original_images):.2f}")
    print(f"Critical Fixes Available\t{original_totals['critical_fixes']}\t{original_totals['critical_fixes'] / len(original_images):.2f}")
    print(f"High Fixes Available\t{original_totals['high_fixes']}\t{original_totals['high_fixes'] / len(original_images):.2f}")
    print(f"Medium Fixes Available\t{original_totals['medium_fixes']}\t{original_totals['medium_fixes'] / len(original_images):.2f}")
    print(f"Low Fixes Available\t{original_totals['low_fixes']}\t{original_totals['low_fixes'] / len(original_images):.2f}")

    # Fixes Available Summary New List
    print("\nFixes Available Summary (New List):")
    print("Fix Type\tTotal\tAverage")
    print(f"Fixes Available\t{new_totals['total_fixes']}\t{new_totals['total_fixes'] / len(new_images):.2f}")
    print(f"Critical Fixes Available\t{new_totals['critical_fixes']}\t{new_totals['critical_fixes'] / len(new_images):.2f}")
    print(f"High Fixes Available\t{new_totals['high_fixes']}\t{new_totals['high_fixes'] / len(new_images):.2f}")
    print(f"Medium Fixes Available\t{new_totals['medium_fixes']}\t{new_totals['medium_fixes'] / len(new_images):.2f}")
    print(f"Low Fixes Available\t{new_totals['low_fixes']}\t{new_totals['low_fixes'] / len(new_images):.2f}")

if __name__ == "__main__":
    main()
