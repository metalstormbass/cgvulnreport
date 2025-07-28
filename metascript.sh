#!/bin/bash

# Source helper functions
source ./scripts/vuln_reduction.sh
source ./scripts/txt_to_markdown.sh
source ./scripts/size_reduction.sh
source ./scripts/json_to_markdown.sh
source ./scripts/parse_kev.sh
source ./scripts/parse_epss.sh  

# Check for two arguments
if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <images.txt> <cg_images.txt>"
  exit 1
fi

input_file1="$1"
input_file2="$2"

# Authentication with CG and checking if all images are pullable

chainctl auth login

set -euo pipefail

# Set up Python virtual environment and install requirements
if [ ! -d ".venv" ]; then
  echo -e "\033[1;33mCreating Python virtual environment...\033[0m"
  python3 -m venv .venv
fi
source .venv/bin/activate

if ! python3 -m pip show markdown pandas > /dev/null 2>&1; then
  echo -e "\033[1;33mInstalling required Python packages...\033[0m"
  if ! python3 -m pip install -r requirements.txt; then
    echo -e "\033[1;31m❌ Failed to install required Python packages.\033[0m"
    deactivate
    exit 3
  fi
fi

# Run the first check
python3 check-pullable-dryrun/check-pullable.py "$input_file1" --threads 4
exit_code1=$?

if [[ $exit_code1 -eq 1 ]]; then
  echo "❌ Some images in $input_file1 are not pullable."
  exit 1
elif [[ $exit_code1 -eq 2 ]]; then
  echo "🚫 Error with $input_file1: bad arguments, no images, or Docker is missing."
  exit 2
fi

# Run the second check
python3 check-pullable-dryrun/check-pullable.py "$input_file2" --threads 4
exit_code2=$?

if [[ $exit_code2 -eq 1 ]]; then
  echo "❌ Some images in $input_file2 are not pullable."
  exit 1
elif [[ $exit_code2 -eq 2 ]]; then
  echo "🚫 Error with $input_file2: bad arguments, no images, or Docker is missing."
  exit 2
fi

echo "✅ All images in both files are pullable."



echo -e "\n\033[1;33m🟡 Scanning original images...\033[0m"
./scan_script.sh "$input_file1" > out.txt
echo -e "\033[1;32m✅ Done scanning original images.\033[0m"
echo -e "\033[1;31m📦 Original Images:\033[0m"
grep -A 10 'Image Size On Disk:' out.txt | tail -n +2 | grep -v '^$' | grep -v '^Total'


md_out1=$(generate_txt2md out.txt)
json_out1=$(json2md out.json)

echo -e "\n\033[1;33m🟡 Scanning Chainguard images...\033[0m"
./scan_script.sh "$input_file2" > cgout.txt
echo -e "\033[1;32m✅ Done scanning Chainguard images.\033[0m"
echo -e "\033[1;35m📦 Chainguard Images:\033[0m"
grep -A 10 'Image Size On Disk:' cgout.txt | tail -n +2 | grep -v '^$' | grep -v '^Total'

md_out2=$(generate_txt2md cgout.txt)
json_out2=$(json2md cgout.json)

# Generate vulnerability reduction summary
vuln_report=$(generate_vulnerability_report out.json cgout.json)

# Generate KEV report
kev_report=$(generate_kev_markdown out-kev.txt)

# Generate EPSS report (only EPSS >= 0.75 will be included)
epss_report=$(generate_epss_markdown out-epss.txt)

# Generate size reduction summary
size_reduction_output=$(size_reduction out.txt cgout.txt)

# Assemble final report content
report_body=$(cat <<EOF
## Executive Summary
$vuln_report

$size_reduction_output

$kev_report

$epss_report

---

## Original Image Analysis
$md_out1
$json_out1

---


## Chainguard Image Analysis
$md_out2
$json_out2
EOF
)

# Inject into template and output to final_report.md
sed '/\[INSERT OUTPUT FROM SCRIPT HERE\]/ {
    r /dev/stdin
    d
}' template.md <<< "$report_body" > final_report.md

python3 reportbuild.py final_report.md

echo -e "\033[1;34m==============================="

echo -e "\n\033[1;32m✅ Report generated: report.html\033[0m"
echo -e "\033[1;34m===============================\033[0m"
echo -e "\nNext steps:"
echo "1. Print report.html page to PDF."
echo "2. Share or archive your report as needed."

