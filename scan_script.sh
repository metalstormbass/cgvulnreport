#!/bin/bash

# Default scanner is 'grype'
scanner="grype"


images=(
  "node:22"
  "python:3.12"
)

echo ""
echo "Image Size On Disk:"
    
# Loop through each item and append ":latest" if no tag is present
for i in "${!images[@]}"; do
    if [[ "${images[i]}" != *:* ]]; then
        images[i]="${images[i]}:latest"
    fi
    
    origimagestr="${images[i]}"
    
    # Pull the image and check for errors
    if docker pull "${images[i]}" 2>&1 | grep -iq "error"; then
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
totalWontFix=0
totalCount=0
totalfixedCritical=0
totalfixedHigh=0
totalfixedMedium=0
totalfixedLow=0
totalfixedCount=0

echo ""

for image in "${!image_digests[@]}"; do
    echo "Image: $image, Digest: ${image_digests[$image]}, "
done

for IMAGE in "${images[@]}"; do
  
 if [[ "$scanner" == "grype" ]]; then
 
  # Grype
  output=$(grype "$IMAGE" -o json 2>/dev/null | jq -c '{
    Total: [.matches[].vulnerability] | length,
    Critical: [.matches[] | select(.vulnerability.severity == "Critical")] | length,
    High: [.matches[] | select(.vulnerability.severity == "High")] | length,
    Medium: [.matches[] | select(.vulnerability.severity == "Medium")] | length,
    Low: [.matches[] | select(.vulnerability.severity == "Low")] | length,
    WontFix: [.matches[] | select(.vulnerability.fix.state == "wont-fix")] | length,
    FixedTotal: [.matches[] | select((.vulnerability.fix.state | ascii_downcase) == "fixed")] | length,
    FixedCritical: [.matches[] | select((.vulnerability.severity | ascii_downcase) == "critical" and (.vulnerability.fix.state | ascii_downcase) == "fixed")] | length,
    FixedHigh: [.matches[] | select((.vulnerability.severity | ascii_downcase) == "high" and (.vulnerability.fix.state | ascii_downcase) == "fixed")] | length,
    FixedMedium: [.matches[] | select((.vulnerability.severity | ascii_downcase) == "medium" and (.vulnerability.fix.state | ascii_downcase) == "fixed")] | length,
    FixedLow: [.matches[] | select((.vulnerability.severity | ascii_downcase) == "low" and (.vulnerability.fix.state | ascii_downcase) == "fixed")] | length
  }')
  
  critical=$(jq '.Critical' <<< "$output")
  high=$(jq '.High' <<< "$output")
  medium=$(jq '.Medium' <<< "$output")
  low=$(jq '.Low' <<< "$output")
  wontfix=$(jq '.WontFix' <<< "$output")
  total=$(jq '.Total' <<< "$output")
  fixed_critical=$(jq '.FixedCritical' <<< "$output")
  fixed_high=$(jq '.FixedHigh' <<< "$output")
  fixed_medium=$(jq '.FixedMedium' <<< "$output")
  fixed_low=$(jq '.FixedLow' <<< "$output")
  fixed_total=$(jq '.FixedTotal' <<< "$output")

  json=$(jq --arg image "$IMAGE" \
    --arg critical "$critical" \
    --arg high "$high" \
    --arg medium "$medium" \
    --arg low "$low" \
    --arg wontfix "$wontfix" \
    --arg total "$total" \
    --arg fixed_critical "$fixed_critical" \
    --arg fixed_high "$fixed_high" \
    --arg fixed_medium "$fixed_medium" \
    --arg fixed_low "$fixed_low" \
    --arg fixed_total "$fixed_total" \
    '.items += [{
      image: $image,
      scan: {
        type: "grype",
        critical: ($critical | tonumber),
        high: ($high | tonumber),
        medium: ($medium | tonumber),
        low: ($low | tonumber),
        wontfix: ($wontfix | tonumber),
        total: ($total | tonumber),
        fixed_critical: ($fixed_critical | tonumber),
        fixed_high: ($fixed_high | tonumber),
        fixed_medium: ($fixed_medium | tonumber),
        fixed_low: ($fixed_low | tonumber),
        fixed_total: ($fixed_total | tonumber)
      }
    }]' <<< "$json")

    totalfixedCritical=$((totalfixedCritical + fixed_critical))
    totalfixedHigh=$((totalfixedHigh + fixed_high))
    totalfixedMedium=$((totalfixedMedium + fixed_medium))
    totalfixedLow=$((totalfixedLow + fixed_low))
    totalfixedCount=$((totalfixedCount + fixed_total))

  fi

  totalCritical=$((totalCritical + critical))
  totalHigh=$((totalHigh + high))
  totalMedium=$((totalMedium + medium))
  totalLow=$((totalLow + low))
  totalWontFix=$((totalWontFix + wontfix))
  totalCount=$((totalCount + total))

done

# Calculate averages
averageCritical=$((totalCritical / ${#images[@]}))
averageHigh=$((totalHigh / ${#images[@]}))
averageMedium=$((totalMedium / ${#images[@]}))
averageLow=$((totalLow / ${#images[@]}))
averageWontFix=$((totalWontFix / ${#images[@]}))

# Display totals and averages
echo "Total Vulnerabilities: $totalCount"
echo "Total Critical CVEs: $totalCritical"
echo "Total High CVEs: $totalHigh"
echo "Total Medium CVEs: $totalMedium"
echo "Total Low CVEs: $totalLow"
echo -n "Average Vulnerabilities: "; echo "scale=2; $totalCount / ${#images[@]}" | bc
echo -n "Average Critical CVEs: "; echo "scale=2; $totalCritical / ${#images[@]}" | bc
echo -n "Average High CVEs: "; echo "scale=2; $totalHigh / ${#images[@]}" | bc
echo -n "Average Medium CVEs: "; echo "scale=2; $totalMedium / ${#images[@]}" | bc
echo -n "Average Low CVEs: "; echo "scale=2; $totalLow / ${#images[@]}" | bc

if [[ "$scanner" == "grype" ]]; then


  echo ""
  echo "Total Fixes Available: $totalfixedCount"
  echo "Total Critical Fixes Available: $totalfixedCritical"
  echo "Total High Fixes Available: $totalfixedHigh"
  echo "Total Medium Fixes Available: $totalfixedMedium"
  echo "Total Low Fixes Available: $totalfixedLow"
  echo ""

fi

# Generate a shorter random filename (no padding)
random_filename="out1.json"

# Save the JSON content to the random filename
echo $json > $random_filename
