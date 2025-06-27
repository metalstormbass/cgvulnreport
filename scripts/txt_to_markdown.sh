#!/bin/bash

generate_txt2md() {
    if [ -z "$1" ]; then
        echo "Usage: $0 <input-file>"
        return 1
    fi

    local input_file="$1"

    # === Image Size Report ===
    echo "### Image Size Report"
    echo
    echo "The following table lists the disk sizes of the analyzed container images to help assess storage efficiency."
    echo
    echo "| **Image Name**                                  | **Size on Disk (MB)** |"
    echo "|:--------------------------------------------------|------------------------:|"
    grep -E "^[^ ]+:.*: [0-9.]+ MB$" "$input_file" | while read -r line; do
        image_name=$(echo "$line" | cut -d: -f1-2)
        size=$(echo "$line" | grep -oE "[0-9.]+ MB" | sed 's/ MB//')
        printf "| %-48s | %22s |\n" "$image_name" "$size"
    done

    echo ""

    # === Vulnerabilities Summary ===
    echo "### Vulnerabilities Summary"
    echo
    echo "This summary highlights the total and average number of vulnerabilities detected across all images, categorized by severity level."
    echo
    echo "| **Vulnerability Type** | **Total** | **Average per Image** |"
    echo "|:------------------------|-----------:|------------------------:|"

    local vulnerabilities=("Vulnerabilities" "Critical CVEs" "High CVEs" "Medium CVEs" "Low CVEs")
    for vuln in "${vulnerabilities[@]}"; do
        total=$(grep "Total $vuln" "$input_file" | awk -F': ' '{print $2}')
        average=$(grep "Average $vuln" "$input_file" | awk -F': ' '{print $2}')
        printf "| %-22s | %-9s | %-22s |\n" "$vuln" "$total" "$average"
    done

    echo ""
    return 0
}
