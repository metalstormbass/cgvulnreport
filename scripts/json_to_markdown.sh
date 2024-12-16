#!/bin/bash

# Check if the input file is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <input.json>"
    exit 1
fi

# Read the JSON file
json_data=$(cat "$1")


# Print the header for the Markdown table
echo "### **Detailed Vulnerabilty Scans**" 
echo "This table provides a detailed breakdown of vulnerabilities per image, categorized by severity and fix availability."
echo "<br>"
echo "| **Image** | **Type** | **Critical** | **High** | **Medium** | **Low** | **Wont Fix** | **Total** | **Fixed Critical** | **Fixed High** | **Fixed Medium** | **Fixed Low | **Fixed Total** |"
echo "|-------|------|----------|------|--------|-----|----------|-------|----------------|------------|--------------|-----------|-------------|"

# Use jq to parse the JSON data, remove the tag, and print each item in the table format
echo "$json_data" | jq -r '.items[] | 
    "| \(.image | sub("@.*$"; "")) | \(.scan.type) | \(.scan.critical) | \(.scan.high) | \(.scan.medium) | \(.scan.low) | \(.scan.wontfix) | \(.scan.total) | \(.scan.fixed_critical) | \(.scan.fixed_high) | \(.scan.fixed_medium) | \(.scan.fixed_low) | \(.scan.fixed_total) |"'
