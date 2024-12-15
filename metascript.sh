# Check if the input file is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <scan_script> <cg_scan_script>"
    exit 1
fi

# Read the input file
input_file1="$1"

./"$input_file1" > out1.txt


./scripts/txt_to_markdown.sh out1.txt 

echo ""
./scripts/json_to_markdown.sh out1.json

echo ""
echo ""
echo ""
echo ""

# Read the input file
input_file1="$2"

./"$input_file1" > out2.txt

./scripts/txt_to_markdown.sh out2.txt 

echo ""

./scripts/json_to_markdown.sh out2.json

echo ""
echo ""
echo ""
echo ""

./scripts/vuln_reduction.sh out1.json out2.json
./scripts/size_reduction.sh out1.txt out2.txt

#rm out1.txt
#rm out1.json
#rm out2.txt
#rm out2.json
