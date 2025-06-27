#!/bin/bash

# Function to calculate size reduction
size_reduction() {
    # Check if two arguments (file paths) are provided
    if [ "$#" -ne 2 ]; then
        echo "Usage: $0 <file1> <file2>"
        return 1
    fi

    # Read in the file names
    local file1="$1"
    local file2="$2"

    # Function to extract the total image size from the file
    extract_image_size() {
        local file="$1"
        local size_total=0

        # Extract image sizes from the file
        while read -r line; do
            # Look for lines with "MB" to capture the image size
            if [[ "$line" =~ :\ ([0-9]+\.[0-9]+)\ MB$ ]]; then
                # Add the extracted size in MB to the total size
                size_total=$(echo "$size_total + ${BASH_REMATCH[1]}" | bc)
            fi
        done < "$file"

        # Return the total size
        echo "$size_total"
    }

    # Function to count the number of items (images) in the file
    count_items() {
        local file="$1"
        grep -c "MB$" "$file"
    }

    # Get the total image sizes from both files
    local size1
    size1=$(extract_image_size "$file1")

    local size2
    size2=$(extract_image_size "$file2")

    # Get the number of items (images) in the files
    local count
    count=$(count_items "$file1")

    # Calculate the average size of the original images
    local average_original
    average_original=$(echo "scale=2; $size1 / $count" | bc)

    # Calculate the average size of the Chainguard images
    local average_chainguard
    average_chainguard=$(echo "scale=2; $size2 / $count" | bc)

    # Calculate the percentage reduction
    local percentage_reduction
    percentage_reduction=$(echo "scale=2; (($average_original - $average_chainguard) / $average_original) * 100" | bc)

 # Display the results in Markdown format
echo "## Image Size Reduction"
echo "On average, **Chainguard** images are **$percentage_reduction% smaller** per image compared to their **Original** counterparts."

}

