Vulnerability Scanner Frontend

This script provides a unified interface for running vulnerability scans using both Trivy and Grype. It processes container images to identify vulnerabilities and summarizes the results with totals and averages.

Features

Supports Trivy and Grype: Run scans using either or both tools.

Single or Multiple Images: Scan a single image or a list of images from a file.

Aggregated Results: Combine and summarize vulnerability results across all scanned images.

Customizable Options: Specify scanner and input method via command-line arguments.

Requirements

Python 3.6 or higher

Trivy and Grype installed and available in the executable path.

Installation

Install Trivy and Grype:

Trivy: https://github.com/aquasecurity/trivy

Grype: https://github.com/anchore/grype

Ensure both tools are accessible in your system's PATH.

Clone or download this script.

Make the script executable:

chmod +x script.py

Usage

Command-Line Arguments

Options

--scanner: Specify which scanner to use (trivy, grype, or both). Default: both.

image: The container image to scan (e.g., nginx:latest).

--list: Path to a text file with a list of images to scan (one per line).

--second-image: Reserved for future functionality.

Example Commands

Scan a single image with both scanners:

./script.py --scanner both nginx:latest

Scan multiple images from a list file:

./script.py --list images.txt

Scan a single image using only Trivy:

./script.py --scanner trivy nginx:latest

Output

The script outputs the following information:

Total vulnerabilities detected (all severities).

Totals for each severity level: Critical, High, Medium, and Low.

Averages of vulnerabilities across all scanned images.

Sample Output

Running trivy scanner on image: nginx:latest...
Running grype scanner on image: nginx:latest...
Total Vulnerabilities: 150
Total Critical CVEs: 10
Total High CVEs: 40
Total Medium CVEs: 70
Total Low CVEs: 30
Average Vulnerabilities: 150.00
Average Critical CVEs: 10.00
Average High CVEs: 40.00
Average Medium CVEs: 70.00
Average Low CVEs: 30.00

Notes

If both --list and image arguments are provided, only the images in the list file will be processed.

Ensure both Trivy and Grype are correctly installed and configured before running the script.

Contributing

Contributions are welcome! Please submit a pull request or open an issue for feedback or improvements.
