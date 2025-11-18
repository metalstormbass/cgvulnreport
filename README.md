# 🚀 Chainguard Vulnerability Comparison

Easily compare vulnerabilities between standard container images and their Chainguard equivalents.

---

## 🛠️ Quick Start

> **Best experience:** Use [Visual Studio Code](https://code.visualstudio.com/)

### 1️⃣ Clone the Repository
```sh
git clone https://github.com/metalstormbass/cgvulnreport.git
cd cgvulnreport
```

### 2️⃣ Prepare Your Image Lists
- **Edit `images.txt`**: List the images you want to compare (one per line).
- **Edit `cg_images.txt`**: List the Chainguard equivalents (one per line, in the same order).

**Example `images.txt`:**
```
node:22
python:3.12
ghcr.io/groundnuty/k8s-wait-for:v2.0
```

**Example `cg_images.txt`:**
```
cgr.dev/chainguard-private/node:22
cgr.dev/chainguard-private/python:3.12
cgr.dev/chainguard-private/k8s-wait-for:latest
```

### 3️⃣ Make the Script Executable
```sh
chmod +x metascript.sh
```

### 4️⃣ Add The Logo
- Save your logo as `logo.png` in this directory.
- Update `template.md`:
  ```markdown
  **Prepared for:**  
  <img src="logo.png" alt="Customer Logo" width="200">
  ```

### 5️⃣ Run the Comparison
```sh
./metascript.sh images.txt cg_images.txt
```

The final report will be generated as `final_report.md` and `report.html` using the template in `template.md`.

#### Command-Line Options

Use these flags to customize the scan behavior:

```sh
# Check if all images are pullable before scanning (recommended on first run)
./metascript.sh images.txt cg_images.txt --check-pullable

# Skip re-scanning original images (uses existing out.txt/out.json)
./metascript.sh images.txt cg_images.txt --skip-scan-original

# Skip re-scanning Chainguard images (uses existing cgout.txt/cgout.json)
./metascript.sh images.txt cg_images.txt --skip-scan-chainguard

# Control parallel scanning threads (default: 4)
./metascript.sh images.txt cg_images.txt --threads 8

# Combine flags
./metascript.sh images.txt cg_images.txt --check-pullable --threads 16

# Skip both scans and just regenerate report (very fast)
./metascript.sh images.txt cg_images.txt --skip-scan-original --skip-scan-chainguard

# Display help
./metascript.sh --help
```

**Performance & Optimization:**
- **Parallel scanning** - Use `--threads N` to control how many images scan simultaneously (default: 4)
  - Increase threads on powerful machines for faster scanning
  - Use `--threads 1` for sequential scanning if needed
- **Rate limiting** - To avoid hitting Docker Hub rate limits:
  - Skip `--check-pullable` on subsequent runs (only needed on first run or when images change)
  - Use `--skip-scan-original` and/or `--skip-scan-chainguard` to reuse existing scan data

**Troubleshooting:** If the report is not successfully generated, check `out.txt` for any error messages.

### 6️⃣ Export the Report
- Use the **Markdown PDF** plugin for VS Code.
- Export the completed `template.md` to HTML, then print the HTML to PDF for best results.

---

## 🔧 How It Works

The main workflow is fully automated via `metascript.sh`:

1. **Environment Setup** - Creates a Python virtual environment (`.venv`) if needed
2. **Dependency Installation** - Automatically installs required packages (`markdown`, `pandas`)
3. **Image Scanning** - Scans both image lists in parallel (configurable thread count)
   - Uses multi-threaded scanning to speed up vulnerability analysis
   - KEV and EPSS checks run after all scans complete
4. **Report Generation** - Processes vulnerability data and generates HTML report
5. **Template Injection** - Injects results into `template.md` at the `[INSERT OUTPUT FROM SCRIPT HERE]` marker

**All dependencies are handled automatically** — just run the script!

---

## 📋 Requirements

- Python 3.8+
- Docker CLI (for image scanning)
- `markdown` and `pandas` Python packages (installed automatically by the script)

---

## 💡 Tips

- Keep your `images.txt` and `cg_images.txt` in sync (same number and order of images) for accurate comparisons.
- Use `--check-pullable` on your first run to verify image accessibility.
- Use `--threads N` to optimize scanning performance:
  - Higher thread count = faster scanning (uses more system resources)
  - Lower thread count = lighter system load
  - Start with `--threads 4` (default) and adjust based on your hardware
- Use skip flags to regenerate reports quickly without re-scanning when rate limits are a concern!


