#!/bin/bash

# Function to generate detailed vulnerability report
json2md() {
    # Check if the input file is provided
    if [ -z "$1" ]; then
        echo "Usage: $0 <input.json>"
        return 1
    fi

    # Read the JSON file
    local json_data
    json_data=$(cat "$1")

    # --- Fixes Available Summary ---
    echo "### **Fixes Available Summary**"
    echo "This summary lists the availability of fixes for vulnerabilities, grouped by severity."
    echo "<br>"
    echo "| **Fix Type**                | **Total** |"
    echo "|----------------------------|----------|"

    # Initialize total and count variables for each fix type
    total_critical=0
    total_high=0
    total_medium=0
    total_low=0
    total_fixes=0

    count_critical=0
    count_high=0
    count_medium=0
    count_low=0
    count_fixes=0

    # Loop through each item in the JSON
    for item in $(jq -c '.items[]' <<< "$json_data"); do
        # Extract values for each severity from the scan data
        critical=$(jq '.scan.critical' <<< "$item")
        high=$(jq '.scan.high' <<< "$item")
        medium=$(jq '.scan.medium' <<< "$item")
        low=$(jq '.scan.low' <<< "$item")
        fixed_critical=$(jq '.scan.fixed_critical' <<< "$item")
        fixed_high=$(jq '.scan.fixed_high' <<< "$item")
        fixed_medium=$(jq '.scan.fixed_medium' <<< "$item")
        fixed_low=$(jq '.scan.fixed_low' <<< "$item")
        
        # Sum totals and count occurrences for each severity
        total_critical=$((total_critical + critical))
        total_high=$((total_high + high))
        total_medium=$((total_medium + medium))
        total_low=$((total_low + low))
        total_fixes=$((total_fixes + fixed_critical + fixed_high + fixed_medium + fixed_low))

        count_critical=$((count_critical + (fixed_critical > 0 ? 1 : 0)))
        count_high=$((count_high + (fixed_high > 0 ? 1 : 0)))
        count_medium=$((count_medium + (fixed_medium > 0 ? 1 : 0)))
        count_low=$((count_low + (fixed_low > 0 ? 1 : 0)))
        count_fixes=$((count_fixes + (fixed_critical > 0 || fixed_high > 0 || fixed_medium > 0 || fixed_low > 0 ? 1 : 0)))
    done

    # Output the result for each fix category
    echo "| Critical Fixes Available      | $total_critical  |"
    echo "| High Fixes Available          | $total_high      |"
    echo "| Medium Fixes Available        | $total_medium    |"
    echo "| Low Fixes Available           | $total_low       |"
    echo "| Total Fixes Available         | $total_fixes     |" 

    # Print the header for the Markdown table
    echo "### **Detailed Vulnerabilty Scans**"
    echo "This table provides a detailed breakdown of vulnerabilities per image, categorized by severity and fix availability."
    echo "<br>"
    echo "| **Image** | **Type** | **Critical** | **High** | **Medium** | **Low** | **Wont Fix** | **Total** | **Fixed Critical** | **Fixed High** | **Fixed Medium** | **Fixed Low** | **Fixed Total** |"
    echo "|-------|------|----------|------|--------|-----|----------|-------|----------------|------------|--------------|-----------|-------------|"

    # Use jq to parse the JSON data and print each item in the table format
    jq -r '.items[] | 
        "| \(.image | sub("@.*$"; "")) | \(.scan.type) | \(.scan.critical) | \(.scan.high) | \(.scan.medium) | \(.scan.low) | \(.scan.wontfix) | \(.scan.total) | \(.scan.fixed_critical) | \(.scan.fixed_high) | \(.scan.fixed_medium) | \(.scan.fixed_low) | \(.scan.fixed_total) |"' <<< "$json_data"
}


