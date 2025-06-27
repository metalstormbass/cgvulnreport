#!/bin/bash

# Function to generate the vulnerability reduction report
generate_vulnerability_report() {
  # Check if two arguments are provided (two JSON files)
  if [ $# -ne 2 ]; then
    echo "Usage: $0 <file1.json> <file2.json>"
    return 1
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

  number_of_images=$(jq '.items | length' "$file1")

  # Display the results in Markdown format
cat << EOF

This report presents a comparative analysis between the **Original** and **Chainguard** container images, highlighting substantial improvements in overall **security posture**. The findings are based on a sample set of **$number_of_images images**.

- **Total Vulnerabilities Eliminated**: **$total_reduction**
- **Critical & High Severity Reduction**: **$reduction_critical Critical**, **$reduction_high High**
- **Improved Security Hygiene**: Chainguard images exhibit near-zero residual vulnerabilities across all severity categories.

### Key Insights

- **Critical CVEs**: $critical_vuln_file1 → $critical_vuln_file2
- **High CVEs**: $high_vuln_file1 → $high_vuln_file2
- **Medium CVEs**: $medium_vuln_file1 → $medium_vuln_file2
- **Low CVEs**: $low_vuln_file1 → $low_vuln_file2

### Vulnerability Reduction Summary

| Severity     | Original | Chainguard | Reduction |
|--------------|----------|------------|-----------|
| Critical     | $critical_vuln_file1 | $critical_vuln_file2 | **$reduction_critical** |
| High         | $high_vuln_file1     | $high_vuln_file2     | **$reduction_high**     |
| Medium       | $medium_vuln_file1   | $medium_vuln_file2   | **$reduction_medium**   |
| Low          | $low_vuln_file1      | $low_vuln_file2      | **$reduction_low**      |
| **Total**    | $((critical_vuln_file1 + high_vuln_file1 + medium_vuln_file1 + low_vuln_file1)) | $((critical_vuln_file2 + high_vuln_file2 + medium_vuln_file2 + low_vuln_file2)) | **$total_reduction** |

EOF

}

