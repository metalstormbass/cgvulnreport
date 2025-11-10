#!/bin/bash

# Source helper functions
source ./scripts/vuln_reduction.sh
source ./scripts/txt_to_markdown.sh
source ./scripts/size_reduction.sh
source ./scripts/json_to_markdown.sh
source ./scripts/parse_kev.sh
source ./scripts/parse_epss.sh  

# Default values
check_pullable=false
scan_original=true
scan_chainguard=true
threads=4

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --check-pullable)
      check_pullable=true
      shift
      ;;
    --skip-scan-original)
      scan_original=false
      shift
      ;;
    --skip-scan-chainguard)
      scan_chainguard=false
      shift
      ;;
    --threads)
      if [[ -z "$2" ]] || ! [[ "$2" =~ ^[0-9]+$ ]]; then
        echo "Error: --threads requires a positive integer argument"
        exit 1
      fi
      threads="$2"
      shift 2
      ;;
    --help)
      echo "Usage: $0 <images.txt> <cg_images.txt> [OPTIONS]"
      echo ""
      echo "Arguments:"
      echo "  <images.txt>      Path to file containing original image list"
      echo "  <cg_images.txt>   Path to file containing Chainguard image list"
      echo ""
      echo "Options:"
      echo "  --check-pullable           Verify that all images are pullable before scanning"
      echo "  --skip-scan-original       Skip scanning the original images (uses existing out.txt/out.json)"
      echo "  --skip-scan-chainguard     Skip scanning Chainguard images (uses existing cgout.txt/cgout.json)"
      echo "  --threads N                Number of parallel scan threads (default: 4)"
      echo "  --help                     Display this help message"
      exit 0
      ;;
    *)
      if [[ -z "${input_file1:-}" ]]; then
        input_file1="$1"
      elif [[ -z "${input_file2:-}" ]]; then
        input_file2="$1"
      else
        echo "Error: Unknown argument '$1'"
        echo "Use --help for usage information"
        exit 1
      fi
      shift
      ;;
  esac
done

# Check for required arguments
if [[ -z "${input_file1:-}" ]] || [[ -z "${input_file2:-}" ]]; then
  echo "Error: Missing required arguments"
  echo "Usage: $0 <images.txt> <cg_images.txt> [OPTIONS]"
  echo "Use --help for more information"
  exit 1
fi

# Authentication with CG and checking if all images are pullable

# Authentication with CG and checking if all images are pullable

echo -e "\n\033[1;36m╔════════════════════════════════════════════════════╗\033[0m"
echo -e "\033[1;36m║   Chainguard Vulnerability Comparison Report       ║\033[0m"
echo -e "\033[1;36m╚════════════════════════════════════════════════════╝\033[0m\n"

chainctl auth login

set -euo pipefail

# Set up Python virtual environment and install requirements
if [ ! -d ".venv" ]; then
  echo -e "\033[1;33m📦 Creating Python virtual environment...\033[0m"
  python3 -m venv .venv
fi
source .venv/bin/activate

if ! python3 -m pip show markdown pandas > /dev/null 2>&1; then
  echo -e "\033[1;33m📦 Installing required Python packages...\033[0m"
  if ! python3 -m pip install -r requirements.txt > /dev/null 2>&1; then
    echo -e "\033[1;31m❌ Failed to install required Python packages.\033[0m"
    deactivate
    exit 3
  fi
  echo -e "\033[1;32m✅ Dependencies installed\033[0m\n"
fi

# Check if images are pullable (optional, enabled with --check-pullable flag)
if [[ "$check_pullable" == true ]]; then
  echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
  echo -e "\033[1;33m� Checking image pullability...\033[0m"
  echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n"
  
  # Run the first check
  python3 check-pullable-dryrun/check-pullable.py "$input_file1" --threads 4
  exit_code1=$?

  if [[ $exit_code1 -eq 1 ]]; then
    echo -e "\033[1;31m❌ Some images in $input_file1 are not pullable.\033[0m"
    exit 1
  elif [[ $exit_code1 -eq 2 ]]; then
    echo -e "\033[1;31m❌ Error with $input_file1: bad arguments, no images, or Docker is missing.\033[0m"
    exit 2
  fi

  # Run the second check
  python3 check-pullable-dryrun/check-pullable.py "$input_file2" --threads 4
  exit_code2=$?

  if [[ $exit_code2 -eq 1 ]]; then
    echo -e "\033[1;31m❌ Some images in $input_file2 are not pullable.\033[0m"
    exit 1
  elif [[ $exit_code2 -eq 2 ]]; then
    echo -e "\033[1;31m❌ Error with $input_file2: bad arguments, no images, or Docker is missing.\033[0m"
    exit 2
  fi

  echo -e "\033[1;32m✅ All images are pullable\033[0m\n"
else
  echo -e "\033[1;37m⏭️  Skipping pullable check (use --check-pullable to enable)\033[0m\n"
fi



# Scan original images (optional, enabled by default)
if [[ "$scan_original" == true ]]; then
  echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
  echo -e "\033[1;33m� Scanning original images (threads: $threads)...\033[0m"
  echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n"
  ./scan_script.sh "$input_file1" "$threads" > out.txt
  if [[ $? -ne 0 ]]; then
    echo -e "\033[1;31m❌ Scan failed for original images.\033[0m"
    deactivate
    exit 1
  fi
  echo -e "\033[1;32m✅ Original image scan complete\033[0m\n"
else
  echo -e "\033[1;37m⏭️  Skipping original image scan (using existing files)\033[0m\n"
  if [[ ! -f "out.txt" ]] || [[ ! -f "out.json" ]]; then
    echo -e "\033[1;31m❌ Error: Cannot skip scan - output files not found.\033[0m"
    echo -e "\033[1;31mRun without --skip-scan-original to generate these files first.\033[0m"
    deactivate
    exit 1
  fi
fi

echo -e "\033[1;35m� Original Images Summary:\033[0m"
grep -A 10 'Image Size On Disk:' out.txt | tail -n +2 | grep -v '^$' | grep -v '^Total' || true
echo ""

md_out1=$(generate_txt2md out.txt)
json_out1=$(json2md out.json)

# Scan Chainguard images (optional, enabled by default)
if [[ "$scan_chainguard" == true ]]; then
  echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
  echo -e "\033[1;33m� Scanning Chainguard images (threads: $threads)...\033[0m"
  echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n"
  ./scan_script.sh "$input_file2" "$threads" > cgout.txt
  if [[ $? -ne 0 ]]; then
    echo -e "\033[1;31m❌ Scan failed for Chainguard images.\033[0m"
    deactivate
    exit 1
  fi
  echo -e "\033[1;32m✅ Chainguard image scan complete\033[0m\n"
else
  echo -e "\033[1;37m⏭️  Skipping Chainguard image scan (using existing files)\033[0m\n"
  if [[ ! -f "cgout.txt" ]] || [[ ! -f "cgout.json" ]]; then
    echo -e "\033[1;31m❌ Error: Cannot skip scan - output files not found.\033[0m"
    echo -e "\033[1;31mRun without --skip-scan-chainguard to generate these files first.\033[0m"
    deactivate
    exit 1
  fi
fi

echo -e "\033[1;35m� Chainguard Images Summary:\033[0m"
grep -A 10 'Image Size On Disk:' cgout.txt | tail -n +2 | grep -v '^$' | grep -v '^Total' || true
echo ""

md_out2=$(generate_txt2md cgout.txt)
json_out2=$(json2md cgout.json)

# Generate vulnerability reduction summary
vuln_report=$(generate_vulnerability_report out.json cgout.json)

# Generate KEV report
kev_report=$(generate_kev_markdown out-kev.txt)

# Generate EPSS report (only EPSS >= 0.75 will be included)
epss_report=$(generate_epss_markdown out-epss.txt)

# Generate size reduction summary
size_reduction_output=$(size_reduction out.txt cgout.txt)

# Assemble final report content
report_body=$(cat <<EOF
## Executive Summary
$vuln_report

$size_reduction_output

$kev_report

$epss_report

---

## Original Image Analysis
$md_out1
$json_out1

## Chainguard Image Analysis
$md_out2
$json_out2
EOF
)

# Inject into template and output to final_report.md
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "\033[1;33m📄 Generating HTML report...\033[0m"
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n"

sed '/\[INSERT OUTPUT FROM SCRIPT HERE\]/ {
    r /dev/stdin
    d
}' template.md <<< "$report_body" > final_report.md

python3 reportbuild.py final_report.md > /dev/null 2>&1

echo -e "\033[1;36m╔════════════════════════════════════════════════════╗\033[0m"
echo -e "\033[1;32m║  ✅ Report Generation Complete                      ║\033[0m"
echo -e "\033[1;36m╚════════════════════════════════════════════════════╝\033[0m\n"

echo -e "\033[1;32m📊 Generated Report:\033[0m"
echo -e "   📄 report.html\n"

echo -e "\033[1;33m📋 Next steps:\033[0m"
echo -e "   1️⃣  Open report.html in your browser"
echo -e "   2️⃣  Review the vulnerability analysis and KPI metrics"
echo -e "   3️⃣  Export to PDF from your browser (Cmd+P on macOS)\n"

deactivate

