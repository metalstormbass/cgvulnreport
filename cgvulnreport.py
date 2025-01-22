#!/usr/bin/env python
# POC: peter.gregel@chainguard.dev 

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
    total_count = 0
    total_critical = 0
    total_high = 0
    total_medium = 0
    total_low = 0

    for scanner, scans in results.items():
        for data in scans:
            if scanner == "trivy":
                results_list = data.get("Results", [])
                for result in results_list:
                    vulnerabilities = result.get("Vulnerabilities", [])
                    for vuln in vulnerabilities:
                        severity = vuln.get("Severity", "").lower()
                        if severity == "critical":
                            total_critical += 1
                        elif severity == "high":
                            total_high += 1
                        elif severity == "medium":
                            total_medium += 1
                        elif severity == "low":
                            total_low += 1
                        total_count += 1
            elif scanner == "grype":
                matches = data.get("matches", [])
                for match in matches:
                    severity = match.get("vulnerability", {}).get("severity", "").lower()
                    if severity == "critical":
                        total_critical += 1
                    elif severity == "high":
                        total_high += 1
                    elif severity == "medium":
                        total_medium += 1
                    elif severity == "low":
                        total_low += 1
                    total_count += 1

    return total_count, total_critical, total_high, total_medium, total_low

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
        "image",
        nargs="?",
        help="The container image to scan."
    )
    parser.add_argument(
        "--list",
        help="A text file containing a line-by-line list of images to scan.",
        required=False
    )
    parser.add_argument(
        "--second-image",
        help="A placeholder for a second image to be used for future comparison.",
        required=False
    )

    args = parser.parse_args()

    if not args.image and not args.list:
        print("Error: Either an image or a list of images must be specified.", file=sys.stderr)
        sys.exit(1)

    scanners = [args.scanner] if args.scanner != "both" else ["trivy", "grype"]

    images = []
    if args.image:
        images.append(args.image)
    if args.list:
        try:
            with open(args.list, "r") as file:
                images.extend([line.strip() for line in file if line.strip()])
        except Exception as e:
            print(f"Error reading file {args.list}: {e}", file=sys.stderr)
            sys.exit(1)

    combined_results = {}

    for image in images:
        for scanner in scanners:
            print(f"Running {scanner} scanner on image: {image}...")
            scan_result = run_scanner(scanner, image)
            if scan_result is not None:
                if scanner not in combined_results:
                    combined_results[scanner] = []
                combined_results[scanner].append(scan_result)

    total_count, total_critical, total_high, total_medium, total_low = calculate_totals(combined_results)

    print(f"Total Vulnerabilities: {total_count}")
    print(f"Total Critical CVEs: {total_critical}")
    print(f"Total High CVEs: {total_high}")
    print(f"Total Medium CVEs: {total_medium}")
    print(f"Total Low CVEs: {total_low}")

    print(f"Average Vulnerabilities: {total_count / len(images):.2f}")
    print(f"Average Critical CVEs: {total_critical / len(images):.2f}")
    print(f"Average High CVEs: {total_high / len(images):.2f}")
    print(f"Average Medium CVEs: {total_medium / len(images):.2f}")
    print(f"Average Low CVEs: {total_low / len(images):.2f}")

if __name__ == "__main__":
    main()
