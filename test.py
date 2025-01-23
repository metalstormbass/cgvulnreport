#!/usr/bin/env python

import argparse
import subprocess
import json
import sys
import docker

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

def generate_detailed_report(images, scanners):
    report_rows = []
    for image in images:
        for scanner in scanners:
            scan_result = run_scanner(scanner, image)
            if scan_result:
                if scanner == "trivy":
                    results_list = scan_result.get("Results", [])
                    for result in results_list:
                        vulnerabilities = result.get("Vulnerabilities", [])
                        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0, "wont_fix": 0, "fixed_critical": 0, "fixed_high": 0, "fixed_medium": 0, "fixed_low": 0, "total": 0, "fixed_total": 0}
                        for vuln in vulnerabilities:
                            severity = vuln.get("Severity", "").lower()
                            fixed = vuln.get("FixedVersion") is not None
                            if severity not in counts:
                                severity = "unknown"
                            counts[severity] += 1
                            if fixed:
                                counts[f"fixed_{severity}"] += 1
                                counts["fixed_total"] += 1
                            counts["total"] += 1
                        report_rows.append([image, scanner, counts['critical'], counts['high'], counts['medium'], counts['low'], counts['wont_fix'], counts['total'], counts['fixed_critical'], counts['fixed_high'], counts['fixed_medium'], counts['fixed_low'], counts['fixed_total']])
                elif scanner == "grype":
                    matches = scan_result.get("matches", [])
                    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0, "wont_fix": 0, "fixed_critical": 0, "fixed_high": 0, "fixed_medium": 0, "fixed_low": 0, "total": 0, "fixed_total": 0}
                    for match in matches:
                        severity = match.get("vulnerability", {}).get("severity", "").lower()
                        fixed = match.get("vulnerability", {}).get("fix", {}).get("state") == "fixed"
                        if severity not in counts:
                            severity = "unknown"
                        counts[severity] += 1
                        if fixed:
                            counts[f"fixed_{severity}"] += 1
                            counts["fixed_total"] += 1
                        counts["total"] += 1
                    report_rows.append([image, scanner, counts['critical'], counts['high'], counts['medium'], counts['low'], counts['wont_fix'], counts['total'], counts['fixed_critical'], counts['fixed_high'], counts['fixed_medium'], counts['fixed_low'], counts['fixed_total']])
    return report_rows

def format_table(headers, rows):
    """Formats a table in RST format."""
    col_widths = [max(len(str(row[i])) for row in rows) for i in range(len(headers))]
    col_widths = [max(len(header), col_width) for header, col_width in zip(headers, col_widths)]

    def format_row(row):
        return "| " + " | ".join(f"{str(cell):<{col_width}}" for cell, col_width in zip(row, col_widths)) + " |"

    def format_separator():
        return "+-" + "-+-".join("-" * col_width for col_width in col_widths) + "-+"

    table = []
    table.append(format_separator())
    table.append(format_row(headers))
    table.append(format_separator().replace("-", "="))
    for row in rows:
        table.append(format_row(row))
        table.append(format_separator())

    return "\n".join(table)

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

def generate_size_report(images):
    client = docker.from_env()
    rows = []
    total_size_mb = 0
    for image in images:
        try:
            img_info = client.images.get(image)
            size_mb = img_info.attrs['Size'] / (1024 * 1024)
            total_size_mb += size_mb
            rows.append([image, f"{size_mb:.2f}"])
        except docker.errors.ImageNotFound:
            rows.append([image, "Not found"])
        except Exception as e:
            rows.append([image, f"Error ({e})"])
    rows.append(["Total Size", f"{total_size_mb:.2f}"])
    return rows, total_size_mb

def generate_fixes_summary(totals, list_name):
    headers = ["Fix Type", "Total", "Average"]
    rows = [
        ["Fixes Available", totals['total_fixes'], f"{totals['total_fixes'] / totals['total_count']:.2f}" if totals['total_count'] > 0 else "0.00"],
        ["Critical Fixes Available", totals['critical_fixes'], f"{totals['critical_fixes'] / totals['total_count']:.2f}" if totals['total_count'] > 0 else "0.00"],
        ["High Fixes Available", totals['high_fixes'], f"{totals['high_fixes'] / totals['total_count']:.2f}" if totals['total_count'] > 0 else "0.00"],
        ["Medium Fixes Available", totals['medium_fixes'], f"{totals['medium_fixes'] / totals['total_count']:.2f}" if totals['total_count'] > 0 else "0.00"],
        ["Low Fixes Available", totals['low_fixes'], f"{totals['low_fixes'] / totals['total_count']:.2f}" if totals['total_count'] > 0 else "0.00"]
    ]
    print(f"\nFixes Available Summary ({list_name}):\n")
    print(format_table(headers, rows))

def main():
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

    original_totals = process_images(original_images, scanners)
    new_totals = process_images(new_images, scanners)

    original_size_rows, original_total_size = generate_size_report(original_images)
    new_size_rows, new_total_size = generate_size_report(new_images)

    original_detailed_report = generate_detailed_report(original_images, scanners)
    new_detailed_report = generate_detailed_report(new_images, scanners)

    print("\nDetailed Vulnerability Scans - Original List\n")
    headers = ["Image", "Type", "Critical", "High", "Medium", "Low", "Wont Fix", "Total", "Fixed Critical", "Fixed High", "Fixed Medium", "Fixed Low", "Fixed Total"]
    print(format_table(headers, original_detailed_report))

    print("\nDetailed Vulnerability Scans - New List\n")
    print(format_table(headers, new_detailed_report))

    print("\nImage Size Report - Original List\n")
    headers = ["Image", "Size (MB)"]
    print(format_table(headers, original_size_rows))

    print("\nImage Size Report - New List\n")
    print(format_table(headers, new_size_rows))

    generate_fixes_summary(original_totals, "Original List")
    generate_fixes_summary(new_totals, "New List")

    size_difference = new_total_size - original_total_size
    size_percentage_change = (size_difference / original_total_size * 100) if original_total_size > 0 else 0

    print(f"\nSize Change Analysis")
    print("====================\n")
    print(f"- **Original Total Size:** {original_total_size:.2f} MB")
    print(f"- **New Total Size**: {new_total_size:.2f} MB")
    print(f"- **Size Difference**: {size_difference:.2f} MB")
    print(f"- **Percentage Change**: {size_percentage_change:.2f}%")
    print("\n")
