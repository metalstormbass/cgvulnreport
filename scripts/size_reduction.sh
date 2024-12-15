#!/bin/bash

# Check if two arguments (file paths) are provided
if [ "$#" -ne 2 ]; then
  echo "Usage: $0 <file1> <file2>"
  exit 1
fi

# Read in the file names
file1="$1"
file2="$2"

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

# Get the total image sizes from both files
size1=$(extract_image_size "$file1")
size2=$(extract_image_size "$file2")

# Calculate the reduction in size
reduction=$(echo "$size1 - $size2" | bc)

# Display the result
echo "Total reduction in image size between the **Original** and **Chainguard** images: $reduction MB"
