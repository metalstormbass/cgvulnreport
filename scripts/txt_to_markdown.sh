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
    return 0
}
