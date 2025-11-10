#!/bin/bash

# Default scanner is 'grype'
scanner="grype"

# Ensure an input file is provided
if [[ -z "$1" ]]; then
  echo "Usage: $0 <images.txt>"
  exit 1
fi

input_file="$1"

# Ensure the file exists
if [[ ! -f "$input_file" ]]; then
  echo "Error: File '$input_file' not found!"
  exit 1
fi

# Read non-empty trimmed lines into the images array
images=()
while IFS= read -r line || [ -n "$line" ]; do
  # Trim leading/trailing whitespace and skip empty lines
  line="$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  [[ -z "$line" ]] && continue
  images+=("$line")
done < "$input_file"

# Download kev json
curl -s https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json > kev.json

# Define output file
output_file="out"
if [[ "${images[0]}" == cgr.dev/chainguard-private/* ]]; then
  output_file="cgout"
fi

# Define kev file name
kev_output_file="${output_file}-kev.txt"
epss_output_file="${output_file}-epss.txt"

> "$kev_output_file"  # Clear or create the file
> "$epss_output_file"
echo ""
echo "Image Size On Disk:"

# Loop through each item and append ":latest" if no tag is present
for i in "${!images[@]}"; do
  if [[ "${images[i]}" != *:* ]]; then
    images[i]="${images[i]}:latest"
  fi

  origimagestr="${images[i]}"

  # Pull the image and check for errors
  if ! docker pull "${images[i]}" 2>&1; then
    echo "Error encountered while pulling ${images[i]}. Exiting..."
    exit 1
  fi

  images[i]=$(docker inspect "${images[i]}" | jq -r '.[0].RepoDigests[0]')
  size=$(docker inspect "${images[i]}" | jq -r '.[0].Size // 0')
  size_mb=$(echo "scale=2; $size / 1024 / 1024" | bc)

  echo "$origimagestr: $size_mb MB"
done

json='{"items":[]}'
totalCritical=0
totalHigh=0
totalMedium=0
totalLow=0
totalUnknown=0
totalWontFix=0
totalCount=0
totalfixedCritical=0
totalfixedHigh=0
totalfixedMedium=0
totalfixedLow=0
totalfixedUnknown=0
totalfixedCount=0

echo ""

# Function to scan a single image
scan_image() {
  local IMAGE="$1"
  local temp_dir="$2"
  local scanner="$3"
  
  if [[ "$scanner" == "grype" ]]; then
    echo "Scanning image: $IMAGE" >&2
    
    # Run grype and store the raw JSON output
    raw_json=$(grype "$IMAGE" -o json 2>/dev/null)
    local exit_code=$?
    
    if [[ $exit_code -ne 0 ]]; then
      echo "Error scanning $IMAGE" >&2
      return 1
    fi

    # Then apply the vulnerability summary filter using jq
    output=$(jq -c '{
      Total: [.matches[].vulnerability] | length,
      Critical: [.matches[] | select(.vulnerability.severity == "Critical")] | length,
      High: [.matches[] | select(.vulnerability.severity == "High")] | length,
      Medium: [.matches[] | select(.vulnerability.severity == "Medium")] | length,
      Low: [.matches[] | select(.vulnerability.severity == "Low")] | length,
      Unknown: [.matches[] | select(.vulnerability.severity == null or .vulnerability.severity == "Unknown")] | length,
      WontFix: [.matches[] | select(.vulnerability.fix.state == "wont-fix")] | length,
      FixedTotal: [.matches[] | select((.vulnerability.fix.state | ascii_downcase) == "fixed")] | length
    }' <<< "$raw_json")

    # Step 1: Extract CVEs from the scan result
    scan_cves=$(jq -r '.matches[].vulnerability.id' <<< "$raw_json" | sort -u)

    # Step 2: Extract known CVEs from kev.json
    kev_cves=$(jq -r '.vulnerabilities[].cveID' kev.json | sort -u)

    while IFS= read -r cve; do
      if grep -qx "$cve" <<< "$kev_cves"; then
        echo "$cve from $IMAGE" >> "$temp_dir/kev.txt"
      fi
    done <<< "$scan_cves"

    # Remove tag and digest from original image string
    image_name_no_tag=$(echo "$IMAGE" | sed 's/[@:].*$//')

    # Extract EPSS score, CVE ID, and package; inject known image name (no tag)
    jq -r --arg img "$image_name_no_tag" '.matches[]
      | select(.vulnerability.epss != null and .vulnerability.epss[0].epss != null and .vulnerability.epss[0].epss >= 0.75)
      | "\(.vulnerability.epss[0].epss) \(.vulnerability.id) \($img) \(.matchDetails[0].searchedBy.package.name)"' <<< "$raw_json" >> "$temp_dir/epss.txt"

    # Store the output JSON for this image
    echo "$output" > "$temp_dir/$(echo $IMAGE | sed 's/[/:.]/_/g').json"
  fi
  
  return 0
}

export -f scan_image

# Create temporary directory for parallel results
temp_dir=$(mktemp -d)
trap "rm -rf $temp_dir" EXIT

# Initialize temp files
> "$temp_dir/kev.txt"
> "$temp_dir/epss.txt"

# Run scans in parallel using GNU parallel or xargs
# Default to 4 threads if not specified
num_threads=${2:-4}

# Use xargs for parallel execution
printf '%s\n' "${images[@]}" | xargs -P "$num_threads" -I {} bash -c "scan_image '{}' '$temp_dir' '$scanner'"
parallel_exit=$?

if [[ $parallel_exit -ne 0 ]]; then
  echo "Error: One or more scans failed" >&2
  exit 1
fi

# Merge KEV results
if [[ -f "$temp_dir/kev.txt" ]]; then
  cat "$temp_dir/kev.txt" > "$kev_output_file"
fi

# Merge EPSS results
if [[ -f "$temp_dir/epss.txt" ]]; then
  cat "$temp_dir/epss.txt" > "$epss_output_file"
fi

echo "Image Size On Disk:"

# Process scan results and build JSON
json='{"items":[]}'
totalCritical=0
totalHigh=0
totalMedium=0
totalLow=0
totalUnknown=0
totalWontFix=0
totalCount=0
totalfixedCount=0

for IMAGE in "${images[@]}"; do
  # Find the corresponding scan result file
  image_filename=$(echo $IMAGE | sed 's/[/:.]/_/g').json
  
  if [[ -f "$temp_dir/$image_filename" ]]; then
    output=$(cat "$temp_dir/$image_filename")
    
    critical=$(jq '.Critical' <<< "$output")
    high=$(jq '.High' <<< "$output")
    medium=$(jq '.Medium' <<< "$output")
    low=$(jq '.Low' <<< "$output")
    unknown=$(jq '.Unknown' <<< "$output")
    wontfix=$(jq '.WontFix' <<< "$output")
    total=$(jq '.Total' <<< "$output")
    fixed_total=$(jq '.FixedTotal' <<< "$output")

    json=$(jq --arg image "$IMAGE" \
      --arg critical "$critical" \
      --arg high "$high" \
      --arg medium "$medium" \
      --arg low "$low" \
      --arg unknown "$unknown" \
      --arg wontfix "$wontfix" \
      --arg total "$total" \
      --arg fixed_total "$fixed_total" \
      '.items += [{
        image: $image,
        scan: {
          type: "grype",
          critical: ($critical | tonumber),
          high: ($high | tonumber),
          medium: ($medium | tonumber),
          low: ($low | tonumber),
          unknown: ($unknown | tonumber),
          wontfix: ($wontfix | tonumber),
          total: ($total | tonumber),
          fixed_total: ($fixed_total | tonumber)
        }
      }]' <<< "$json")

    totalCritical=$((totalCritical + critical))
    totalHigh=$((totalHigh + high))
    totalMedium=$((totalMedium + medium))
    totalLow=$((totalLow + low))
    totalUnknown=$((totalUnknown + unknown))
    totalWontFix=$((totalWontFix + wontfix))
    totalCount=$((totalCount + total))
    totalfixedCount=$((totalfixedCount + fixed_total))
  fi
done

# Calculate averages
averageCritical=$((totalCritical / ${#images[@]}))
averageHigh=$((totalHigh / ${#images[@]}))
averageMedium=$((totalMedium / ${#images[@]}))
averageLow=$((totalLow / ${#images[@]}))
averageUnknown=$((totalUnknown / ${#images[@]}))
averageWontFix=$((totalWontFix / ${#images[@]}))

# Display totals and averages
echo "Total Vulnerabilities: $totalCount"
echo "Total Critical CVEs: $totalCritical"
echo "Total High CVEs: $totalHigh"
echo "Total Medium CVEs: $totalMedium"
echo "Total Low CVEs: $totalLow"
echo "Total Unknown CVEs: $totalUnknown"
echo -n "Average Vulnerabilities: "; echo "scale=2; $totalCount / ${#images[@]}" | bc
echo -n "Average Critical CVEs: "; echo "scale=2; $totalCritical / ${#images[@]}" | bc
echo -n "Average High CVEs: "; echo "scale=2; $totalHigh / ${#images[@]}" | bc
echo -n "Average Medium CVEs: "; echo "scale=2; $totalMedium / ${#images[@]}" | bc
echo -n "Average Low CVEs: "; echo "scale=2; $totalLow / ${#images[@]}" | bc
echo -n "Average Unknown CVEs: "; echo "scale=2; $totalUnknown / ${#images[@]}" | bc

if [[ "$scanner" == "grype" ]]; then
  echo ""
  echo "Total Fixes Available: $totalfixedCount"
  echo ""
fi

# Construct full output filename with .json suffix
json_output_file="${output_file}.json"

# Save the JSON content to that file
echo "$json" > "$json_output_file"
rm kev.json
