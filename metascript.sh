#!/bin/bash

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

# Run scan_script.sh on the first input
./scan_script.sh "$input_file1" > out.txt
md_out1=$(generate_txt2md out.txt)
json_out1=$(json2md out.json)

# Run scan_script.sh on the second input
./scan_script.sh "$input_file2" > cgout.txt
md_out2=$(generate_txt2md cgout.txt)
json_out2=$(json2md cgout.json)

# Generate vulnerability comparison
vuln_report=$(generate_vulnerability_report out.json cgout.json)

# Generate size comparison
size_reduction_output=$(size_reduction out.txt cgout.txt)

# Generate KEV report
kev_report=$(generate_kev_markdown out-kev.txt)

# Output summary and comparisons
echo "## **Executive Summary**"
echo "$vuln_report"
echo "$kev_report"
echo "$size_reduction_output"
echo ""
echo "---"

echo "## **Analysis: Original Images**"
echo "$md_out1"
echo "$json_out1"
echo "---"

echo "## **Analysis: Chainguard Images**"
echo "$md_out2"
echo "$json_out2"
