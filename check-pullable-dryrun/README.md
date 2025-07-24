1. Create your dryrun list with one image per line (images-dryrun.txt)
2. python3 ./check-pullable-dryrun/check-pullable.py images-dryrun.txt

Output: 

prints a ✓/✗ result per image, plus a summary

exits 0 if every image is pullable, 1 if any are not, and 2 on malformed input / environment errors

