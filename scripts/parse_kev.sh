#!/bin/bash

# Function to convert KEV matches to Markdown
generate_kev_markdown() {
  # Check for one argument
  if [ $# -ne 1 ]; then
    echo "Usage: $0 <kev.txt>"
    return 1
  fi

  kev_input="$1"

  if [ ! -f "$kev_input" ]; then
    echo "Error: File '$kev_input' not found."
    return 1
  fi

  # Count non-empty lines
  entry_count=$(grep -cve '^\s*$' "$kev_input")
  if [[ "$entry_count" -eq 0 ]]; then
    return 0  # silently skip output
  fi

echo "## Known Exploited Vulnerabilities (KEV)"
echo
echo "The following vulnerabilities were detected in your container images and are listed in the **CISA Known Exploited Vulnerabilities (KEV)** catalog."
echo "These CVEs are **actively exploited in the wild** and should be prioritized for immediate patching or mitigation."
echo
echo "### Matched CVEs"
echo

while IFS= read -r line; do
  [[ -z "$line" ]] && continue  # Skip empty lines
  cve=$(awk '{print $1}' <<< "$line")
  image=$(awk '{print $3}' <<< "$line")
  echo "- **$cve** — detected in image \`$image\`"
done < "$kev_input"

}
