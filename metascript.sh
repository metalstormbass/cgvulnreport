#!/bin/bash

# Source helper functions
source ./scripts/vuln_reduction.sh
source ./scripts/txt_to_markdown.sh
source ./scripts/size_reduction.sh
source ./scripts/json_to_markdown.sh
source ./scripts/parse_kev.sh

# Check for two arguments
if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <original-images.txt> <chainguard-images.txt>"
  exit 1
fi

input_file1="$1"
input_file2="$2"

# Run scan_script.sh on original images
./scan_script.sh "$input_file1" > out.txt
md_out1=$(generate_txt2md out.txt)
json_out1=$(json2md out.json)

# Run scan_script.sh on Chainguard images
./scan_script.sh "$input_file2" > cgout.txt
md_out2=$(generate_txt2md cgout.txt)
json_out2=$(json2md cgout.json)

# Generate vulnerability reduction summary
vuln_report=$(generate_vulnerability_report out.json cgout.json)

# Generate KEV report from out-kev.txt (if entries exist)
kev_report=$(generate_kev_markdown out-kev.txt)

# Generate size reduction summary
size_reduction_output=$(size_reduction out.txt cgout.txt)

# Assemble final report content
report_body=$(cat <<EOF
## **Executive Summary**
$vuln_report

$kev_report

$size_reduction_output

---

## **Analysis: Original Images**
$md_out1
$json_out1

---

## **Analysis: Chainguard Images**
$md_out2
$json_out2
EOF
)

# Inject into template and output to final_report.md
sed '/\[INSERT OUTPUT FROM SCRIPT HERE\]/{
    r /dev/stdin
    d
}' template.md <<< "$report_body" > final_report.md

echo "✅ Report generated: final_report.md"
