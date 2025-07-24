#!/bin/bash

# Function to generate detailed vulnerability report
json2md() {
    if [ -z "$1" ]; then
        echo "Usage: $0 <input.json>"
        return 1
    fi

    local json_data
    json_data=$(cat "$1")
    echo ""
    echo "## Detailed Vulnerability Scan Results"
    echo
    echo "This table provides a breakdown of vulnerabilities by image, including severity levels and fix availability."
    echo
    echo "| **Image** | **Scan Type** | **Critical** | **High** | **Medium** | **Low** | **Unknown** | **Won't Fix** | **Total** |"
    echo "|-----------|---------------|--------------|----------|------------|---------|----------|----------------|-----------|"

    jq -r '
        .items[] |
        "| \(.image | sub("@.*$"; "")) | \(.scan.type) | \(.scan.critical) | \(.scan.high) | \(.scan.medium) | \(.scan.low) | \(.scan.unknown) | \(.scan.wontfix) | \(.scan.total) |"
    ' <<< "$json_data"
}


