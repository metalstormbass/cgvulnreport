#!/bin/bash

# Function to convert EPSS matches to a Markdown table
generate_epss_markdown() {
  if [ $# -ne 1 ]; then
    echo "Usage: $0 <epss.txt>"
    return 1
  fi

  epss_input="$1"

  if [ ! -f "$epss_input" ]; then
    echo "Error: File '$epss_input' not found."
    return 1
  fi

  # Count lines with EPSS >= 0.75
  entry_count=$(awk '$1+0 >= 0.75' "$epss_input" | grep -cve '^\s*$')
  if [[ "$entry_count" -eq 0 ]]; then
    return 0  # skip if no high-risk CVEs
  fi

  echo "## Exploit Prediction Scoring System (EPSS)"
echo
echo "The following CVEs have an **EPSS score of 0.75 or higher**, indicating a high likelihood of exploitation in the wild."
echo "These vulnerabilities should be **prioritized for immediate review and remediation**."
echo
echo "| **EPSS Score** | **CVE ID** | **Image** | **Package** |"
echo "|---------------:|------------|-----------|-------------|"

while IFS= read -r line; do
  [[ -z "$line" ]] && continue  # Skip empty lines
  score=$(awk '{print $1}' <<< "$line")
  if awk "BEGIN {exit !($score >= 0.75)}"; then
    cve=$(awk '{print $2}' <<< "$line")
    image=$(awk '{print $3}' <<< "$line")
    pkg=$(awk '{print $4}' <<< "$line")
    printf "| %.2f | %s | \`%s\` | %s |\n" "$score" "$cve" "$image" "$pkg"
  fi
done < "$epss_input"

}
