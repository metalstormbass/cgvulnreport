#!/bin/bash

# Check if two arguments are provided (two JSON files)
if [ $# -ne 2 ]; then
  echo "Usage: $0 <file1.json> <file2.json>"
  exit 1
fi

# Assign the input files to variables
file1=$1
file2=$2

# Function to extract vulnerability counts from a JSON file
get_vulnerabilities() {
  local file=$1
  local vuln_type=$2
  
  jq "[.items[].scan.$vuln_type] | add" "$file"
}

# Extract the total, critical, high, medium, and low vulnerabilities for each file
critical_vuln_file1=$(get_vulnerabilities "$file1" "critical")
high_vuln_file1=$(get_vulnerabilities "$file1" "high")
medium_vuln_file1=$(get_vulnerabilities "$file1" "medium")
low_vuln_file1=$(get_vulnerabilities "$file1" "low")

critical_vuln_file2=$(get_vulnerabilities "$file2" "critical")
high_vuln_file2=$(get_vulnerabilities "$file2" "high")
medium_vuln_file2=$(get_vulnerabilities "$file2" "medium")
low_vuln_file2=$(get_vulnerabilities "$file2" "low")

# Calculate the reduction in vulnerabilities
reduction_critical=$((critical_vuln_file1 - critical_vuln_file2))
reduction_high=$((high_vuln_file1 - high_vuln_file2))
reduction_medium=$((medium_vuln_file1 - medium_vuln_file2))
reduction_low=$((low_vuln_file1 - low_vuln_file2))

# Calculate total reduction (sum of all individual reductions)
total_reduction=$((reduction_critical + reduction_high + reduction_medium + reduction_low))


# Display the results in Markdown format
cat << EOF
# Vulnerability Reduction Report

The total reduction in vulnerabilities is **$total_reduction**.

The table below shows the reduction in vulnerabilities between the **Original Images** and **Chainguard** images. The **Critical**, **High**, **Medium**, and **Low** vulnerability types are listed with their respective reductions.

| Severity | Original | Chainguard | Reduction |
|--------------------|----------|------------|-----------|
| Critical           | $critical_vuln_file1 | $critical_vuln_file2 | $reduction_critical |
| High               | $high_vuln_file1     | $high_vuln_file2     | $reduction_high     |
| Medium             | $medium_vuln_file1   | $medium_vuln_file2   | $reduction_medium   |
| Low                | $low_vuln_file1      | $low_vuln_file2      | $reduction_low      |

EOF
