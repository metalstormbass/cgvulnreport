#!/bin/bash

generate_txt2md() {
    # Check if the input file is provided
    if [ -z "$1" ]; then
        echo "Usage: $0 <input-file>"
        return 1
    fi

    # Read the input file
    input_file="$1"

    # Output the markdown table header
    echo "### **Image Size Report**"
    echo "This table lists the disk sizes of the analyzed images to highlight storage considerations."
    echo "<br>"
    echo "| **Image Name**                                          |  **Size on Disk (MB)** |"
    echo "|-----------------------------------------------------|---------------|"

    # Extract the lines containing image names and sizes, and format them
    grep -E "^[^ ]+:.*: [0-9.]+ MB$" "$input_file" | while read -r line; do
        # Extract the image name and size (including MB)
        image_name=$(echo "$line" | cut -d: -f1-2)

        size=$(echo "$line" | cut -d' ' -f2- | sed 's/ MB$//')
        
        # Output the formatted markdown line
        printf "| %-49s | %-13s |\n" "$image_name" "$size"
    done

    echo ""

    # --- Vulnerabilities Summary ---
    echo "### **Vulnerabilities Summary**"
    echo "This summary shows the total and average vulnerabilities found across all analyzed images, categorized by severity."
    echo "<br>"
    echo "| **Vulnerability Type**       | **Total** | **Average** |"
    echo "|--------------------------|-------|---------|"

    # Extract and process the vulnerability lines
    vulnerabilities=("Vulnerabilities" "Critical CVEs" "High CVEs" "Medium CVEs" "Low CVEs")
    for vuln in "${vulnerabilities[@]}"; do
        vuln_to_search="$vuln"
        total=$(grep "Total $vuln_to_search" "$input_file" | awk -F': ' '{print $2}' || echo "")
        average=$(grep "Average $vuln_to_search" "$input_file" | awk -F': ' '{print $2}' || echo "")
        echo "| $vuln           | $total | $average |"
    done

    echo ""
    return 0
}

