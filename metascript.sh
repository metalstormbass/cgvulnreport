source ./scripts/vuln_reduction.sh
source ./scripts/txt_to_markdown.sh
source ./scripts/size_reduction.sh
source ./scripts/json_to_markdown.sh

# Read the input file
input_file1="scan_script.sh"

# Run the first scan script and capture the output
out1=$(./"$input_file1" > out1.txt)

# Generate markdown from the txt output and capture it
md_out1=$(generate_txt2md out1.txt)


# Convert the JSON to markdown and capture it
json_out1=$(json2md out1.json)

# Read the second input file
input_file2="scan_script_chainguard.sh"

# Run the second scan script and capture the output
out2=$(./"$input_file2" > out2.txt)

# Generate markdown from the txt output and capture it
md_out2=$(generate_txt2md out2.txt)

# Convert the second JSON to markdown and capture it
json_out2=$(json2md out2.json)


# Generate the vulnerability report and capture the output
vuln_report=$(generate_vulnerability_report out1.json out2.json)

# Perform size reduction and capture the output
size_reduction_output=$(size_reduction out1.txt out2.txt)

# You can now use the captured variables wherever you need

echo "## **Executive Summary**"
echo "$vuln_report"
echo "$size_reduction_output"
echo ""
echo "---"


echo "## **Analysis: Original Images**"
echo "$md_out1"
echo "$json_out1"
echo "---"

echo "## **Analysis: Chainguard Images**"
echo "$md_out2"
echo "$json_out2"

