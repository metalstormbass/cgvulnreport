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


echo -e "\033[1;34m==============================="

echo -e "\n\033[1;32m✅ Report generated: final_report.md\033[0m"
echo -e "\033[1;34m===============================\033[0m"
echo -e "\nNext steps:"
echo "1. Review your the final_report.md' file."
echo "2. Export to HTML using VS Code's Markdown PDF extension."
echo "3. Print HTML page to PDF."
echo "4. Share or archive your report as needed."

