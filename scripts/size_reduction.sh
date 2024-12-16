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

# Function to count the number of items (images) in the file
count_items() {
  local file="$1"
  grep -c "MB$" "$file"
}

# Get the total image sizes from both files
size1=$(extract_image_size "$file1")
size2=$(extract_image_size "$file2")

# Get the number of items (images) in the files
count=$(count_items "$file1")

# Calculate the average size of the original images
average_original=$(echo "scale=2; $size1 / $count" | bc)

# Calculate the average size of the Chainguard images
average_chainguard=$(echo "scale=2; $size2 / $count" | bc)

# Calculate the percentage reduction
percentage_reduction=$(echo "scale=2; (($average_original - $average_chainguard) / $average_original) * 100" | bc)

# Display the results in Markdown format
echo "### **Size Reduction:**"
echo "The **Chainguard** images are, on average, **$percentage_reduction% smaller per image** than their **Original counterparts**."
