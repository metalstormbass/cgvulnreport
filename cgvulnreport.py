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
                        report_rows.append(f"{image}\t{scanner}\t{counts['critical']}\t{counts['high']}\t{counts['medium']}\t{counts['low']}\t{counts['wont_fix']}\t{counts['total']}\t{counts['fixed_critical']}\t{counts['fixed_high']}\t{counts['fixed_medium']}\t{counts['fixed_low']}\t{counts['fixed_total']}")
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
                    report_rows.append(f"{image}\t{scanner}\t{counts['critical']}\t{counts['high']}\t{counts['medium']}\t{counts['low']}\t{counts['wont_fix']}\t{counts['total']}\t{counts['fixed_critical']}\t{counts['fixed_high']}\t{counts['fixed_medium']}\t{counts['fixed_low']}\t{counts['fixed_total']}")
    return report_rows

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
    table_header = "=================  =========\nImage            Size (MB)\n=================  ========="
    table_rows = []
    for image in images:
        try:
            img_info = client.images.get(image)
            size_mb = img_info.attrs['Size'] / (1024 * 1024)
            table_rows.append(f"{image:<16}  {size_mb:.2f}")
        except docker.errors.ImageNotFound:
            table_rows.append(f"{image:<16}  Not found")
        except Exception as e:
            table_rows.append(f"{image:<16}  Error ({e})")
    table_footer = "=================  ========="
    return f"{table_header}\n" + "\n".join(table_rows) + f"\n{table_footer}"


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

    original_totals = process_images(original_images, scanners)
    new_totals = process_images(new_images, scanners)

    original_size_report = generate_size_report(original_images)
    new_size_report = generate_size_report(new_images)

    original_detailed_report = generate_detailed_report(original_images, scanners)
    new_detailed_report = generate_detailed_report(new_images, scanners)

    print("\nDetailed Vulnerability Scans - Original List:")
    print("Image\tType\tCritical\tHigh\tMedium\tLow\tWont Fix\tTotal\tFixed Critical\tFixed High\tFixed Medium\tFixed Low\tFixed Total")
    for row in original_detailed_report:
        print(row)

    print("\nDetailed Vulnerability Scans - New List:")
    print("Image\tType\tCritical\tHigh\tMedium\tLow\tWont Fix\tTotal\tFixed Critical\tFixed High\tFixed Medium\tFixed Low\tFixed Total")
    for row in new_detailed_report:
        print(row)

    critical_reduction = original_totals['total_critical'] - new_totals['total_critical']
    high_reduction = original_totals['total_high'] - new_totals['total_high']
    medium_reduction = original_totals['total_medium'] - new_totals['total_medium']
    low_reduction = original_totals['total_low'] - new_totals['total_low']
    unknown_reduction = original_totals['total_unknown'] - new_totals['total_unknown']

    avg_fixes_original = original_totals['total_fixes'] / len(original_images)
    avg_critical_fixes_original = original_totals['critical_fixes'] / len(original_images)
    avg_high_fixes_original = original_totals['high_fixes'] / len(original_images)
    avg_medium_fixes_original = original_totals['medium_fixes'] / len(original_images)
    avg_low_fixes_original = original_totals['low_fixes'] / len(original_images)

    avg_fixes_new = new_totals['total_fixes'] / len(new_images)
    avg_critical_fixes_new = new_totals['critical_fixes'] / len(new_images)
    avg_high_fixes_new = new_totals['high_fixes'] / len(new_images)
    avg_medium_fixes_new = new_totals['medium_fixes'] / len(new_images)
    avg_low_fixes_new = new_totals['low_fixes'] / len(new_images)

    print(f"""
Original List Results:
----------------------
Total Vulnerabilities: {original_totals['total_count']}
Total Critical CVEs: {original_totals['total_critical']}
Total High CVEs: {original_totals['total_high']}
Total Medium CVEs: {original_totals['total_medium']}
Total Low CVEs: {original_totals['total_low']}
Total Unknown CVEs: {original_totals['total_unknown']}

Fixes Available Summary (Original List):
----------------------------------------
Fix Type                 Total    Average
----------------------   -------  -------
Fixes Available          {original_totals['total_fixes']}   {avg_fixes_original:.2f}
Critical Fixes Available {original_totals['critical_fixes']}   {avg_critical_fixes_original:.2f}
High Fixes Available     {original_totals['high_fixes']}   {avg_high_fixes_original:.2f}
Medium Fixes Available   {original_totals['medium_fixes']}   {avg_medium_fixes_original:.2f}
Low Fixes Available      {original_totals['low_fixes']}   {avg_low_fixes_original:.2f}

Image Size Report (Original List):
----------------------------------
{original_size_report}

New List Results:
-----------------
Total Vulnerabilities: {new_totals['total_count']}
Total Critical CVEs: {new_totals['total_critical']}
Total High CVEs: {new_totals['total_high']}
Total Medium CVEs: {new_totals['total_medium']}
Total Low CVEs: {new_totals['total_low']}
Total Unknown CVEs: {new_totals['total_unknown']}

Fixes Available Summary (New List):
-----------------------------------
Fix Type                 Total    Average
----------------------   -------  -------
Fixes Available          {new_totals['total_fixes']}   {avg_fixes_new:.2f}
Critical Fixes Available {new_totals['critical_fixes']}   {avg_critical_fixes_new:.2f}
High Fixes Available     {new_totals['high_fixes']}   {avg_high_fixes_new:.2f}
Medium Fixes Available   {new_totals['medium_fixes']}   {avg_medium_fixes_new:.2f}
Low Fixes Available      {new_totals['low_fixes']}   {avg_low_fixes_new:.2f}

Reduction Table:
----------------
=================  ==========  ========  ===========
Severity           Original    New       Reduction
=================  ==========  ========  ===========
Critical           {original_totals['total_critical']}      {new_totals['total_critical']}       {critical_reduction}
High               {original_totals['total_high']}          {new_totals['total_high']}           {high_reduction}
Medium             {original_totals['total_medium']}        {new_totals['total_medium']}         {medium_reduction}
Low                {original_totals['total_low']}           {new_totals['total_low']}            {low_reduction}
Unknown            {original_totals['total_unknown']}       {new_totals['total_unknown']}        {unknown_reduction}
=================  ==========  ========  ===========

Key Insights:
-------------
* Critical CVEs decreased from {original_totals['total_critical']} to {new_totals['total_critical']}.
* High CVEs dropped from {original_totals['total_high']} to {new_totals['total_high']}.
* Medium CVEs dropped from {original_totals['total_medium']} to {new_totals['total_medium']}.
* Low CVEs dropped from {original_totals['total_low']} to {new_totals['total_low']}.
* Unknown CVEs dropped from {original_totals['total_unknown']} to {new_totals['total_unknown']}.

Image Size Report (New List):
-----------------------------
{new_size_report}
""")
    
if __name__ == "__main__":
    main()
