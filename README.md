# Chainguard Vulnerability Comparison

## Usage

**Note: for best results, use VS Code**

1. **Clone the repository:**
   ```
   git clone https://github.com/metalstormbass/cgvulnreport.git
   cd cgvulnreport
   ```

2. **Edit the image lists:**
   - Edit `images.txt` and list the images you want to compare (one per line).
   - Edit `cg_images.txt` and list the Chainguard equivalent images (one per line, in the same order).

   Example `images.txt`:
   ```
    node:22
    python:3.12
    ghcr.io/groundnuty/k8s-wait-for:v2.0
   ```

   Example `cg_images.txt`:
   ```
    cgr.dev/chainguard-private/node:22
    cgr.dev/chainguard-private/python:3.12
    cgr.dev/chainguard-private/k8s-wait-for:latest
   ```

3. **Make the script executable (if needed):**
   ```
   chmod +x metascript.sh
   ```

4. **Find logo and save it in this directory. Update the template.md:**
```
**Prepared for:**  
<img src="logo.png" alt="Customer Logo" width="200">
```

5. **Run the comparison:**
   ```
   ./metascript.sh images.txt cg_images.txt
   ```
   - Copy the output and paste it into `template.md` where indicated.

6. **Export the report:**
   - Use the Markdown PDF plugin for VS Code.
   - Export the completed `template.md` to HTML, then print the HTML to PDF for best results.
