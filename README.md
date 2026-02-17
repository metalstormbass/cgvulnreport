# 🚀 Chainguard Vulnerability Comparison

Easily compare vulnerabilities between standard container images and their Chainguard equivalents.

## ✨ Features

- **Comprehensive Vulnerability Analysis** - Scans both CVE and GHSA (GitHub Security Advisory) vulnerabilities
- **Chainguard Security Feed Integration** - Real-time remediation status from Chainguard's security feed
- **KEV Detection** - Identifies CISA Known Exploited Vulnerabilities in your images
- **EPSS Scoring** - Highlights vulnerabilities with high exploitation probability
- **Professional Reports** - Generates HTML reports with clean light mode styling, optimized for print-to-PDF
- **Custom Branding** - Add your company logo with the `--logo` flag
- **Confidential Footer** - Automatically includes confidential notice with generation date
- **Parallel Scanning** - Multi-threaded image scanning for faster results
- **Size Comparison** - Shows disk space savings with Chainguard images

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

### 3️⃣ Run the Comparison
```sh
python3 cgvulnreport.py images.txt cg_images.txt
```

The tool will generate a comprehensive HTML report as `report.html` ready to view in your browser and print to PDF.

#### Command-Line Options

Use these flags to customize the scan behavior:

```sh
# Check if all images are pullable before scanning (recommended on first run)
python3 cgvulnreport.py images.txt cg_images.txt --check-pullable

# Skip re-scanning original images (uses existing out.txt/out.json)
python3 cgvulnreport.py images.txt cg_images.txt --skip-scan-original

# Skip re-scanning Chainguard images (uses existing cgout.txt/cgout.json)
python3 cgvulnreport.py images.txt cg_images.txt --skip-scan-chainguard

# Control parallel scanning threads (default: 4)
python3 cgvulnreport.py images.txt cg_images.txt --threads 8

# Add company logo to report (logo will appear in report header)
python3 cgvulnreport.py images.txt cg_images.txt --logo logo.png

# Combine flags
python3 cgvulnreport.py images.txt cg_images.txt --check-pullable --threads 16 --logo logo.png

# Skip both scans and just regenerate report (very fast)
python3 cgvulnreport.py images.txt cg_images.txt --skip-scan-original --skip-scan-chainguard

# Display help
python3 cgvulnreport.py --help
```

**Performance & Optimization:**
- **Parallel scanning** - Use `--threads N` to control how many images scan simultaneously (default: 4)
  - Increase threads on powerful machines for faster scanning
  - Use `--threads 1` for sequential scanning if needed
- **Rate limiting** - To avoid hitting Docker Hub rate limits:
  - Skip `--check-pullable` on subsequent runs (only needed on first run or when images change)
  - Use `--skip-scan-original` and/or `--skip-scan-chainguard` to reuse existing scan data

**Troubleshooting:**

| Issue | Solution |
|-------|----------|
| Image pulls fail with "no space left on device" | Clean up Docker: `docker system prune -af --volumes` |
| "Failed to pull" errors | Check for leading/trailing spaces in image names |
| Authentication failures | Run `chainctl auth login` manually to verify credentials |
| Report not generated | Check `out.txt` and `cgout.txt` for scan errors |
| Missing vulnerabilities | Ensure Grype is up to date: `grype version` |

### 4️⃣ View and Print the Report

**View in Browser:**
```sh
open report.html  # macOS
```

**Print to PDF:**
The report includes optimized print styles with proper margins (2cm top/bottom, 1.5cm left/right). To export as PDF:
1. Open `report.html` in your browser
2. Press **Cmd+P** (macOS) or **Ctrl+P** (Windows/Linux)
3. Select "Save as PDF" as the destination
4. Print - the margins are already optimized for professional output

The report includes:
- Executive summary with vulnerability reduction statistics
- Image size comparison and savings
- KEV (Known Exploited Vulnerabilities) matches
- EPSS (Exploit Prediction Scoring System) high-risk vulnerabilities
- Detailed CVE analysis with Chainguard remediation status
- Comprehensive vulnerability tables for both image sets

---

## 🔧 How It Works

The main workflow is fully automated via `cgvulnreport.py`:

1. **Authentication** - Authenticates with Chainguard registry via `chainctl`
2. **Environment Setup** - Creates a Python virtual environment (`.venv`) if needed
3. **Dependency Installation** - Automatically installs required packages (`pandas`, `requests`)
4. **Image Scanning** - Scans both image lists in parallel (configurable thread count)
   - Pulls images and calculates disk sizes
   - Uses Grype for vulnerability detection
   - Identifies both CVE and GHSA vulnerabilities
   - KEV (Known Exploited Vulnerabilities) matching
   - EPSS (Exploit Prediction Scoring) analysis
5. **Chainguard Feed Integration** - Fetches remediation status from Chainguard security feed
   - Checks fix availability for each vulnerability
   - Provides "Fixed in version X" or "Under Review" status
6. **Report Generation** - Creates professional HTML report with clean light mode styling
   - Embeds logo (if provided) as base64
   - Adds confidential footer with generation date
   - Print-optimized CSS with proper margins (2cm top/bottom, 1.5cm left/right)

**All dependencies are handled automatically** — just run the Python script!

### Architecture

The tool is now fully implemented in Python:
- `cgvulnreport.py` - Main entry point and orchestration
- `src/scanner.py` - Image scanning and vulnerability detection
- `src/report_generator.py` - Report generation and HTML creation
- `src/utils.py` - Utility functions and helpers

---

## 📋 Requirements

- **Python 3.8+** - For running the main script and report generation
- **Docker CLI** - For pulling and inspecting container images
- **Grype** - For vulnerability scanning ([install instructions](https://github.com/anchore/grype))
- **chainctl CLI** - For Chainguard registry authentication ([install instructions](https://edu.chainguard.dev/chainguard/chainguard-enforce/chainctl-docs/chainctl/))
- **Python packages** - `pandas`, `requests` (installed automatically by the script)

---

## 📊 Report Contents

The generated `report.html` includes:

### Executive Summary
- Total vulnerabilities eliminated across all images
- Critical & High severity reduction counts
- Vulnerability breakdown by severity (Critical, High, Medium, Low)
- Image size comparison and average reduction percentage

### Security Analysis
- **KEV Matches** - Lists any CISA Known Exploited Vulnerabilities found
- **EPSS High-Risk** - Vulnerabilities with EPSS score ≥ 0.75 (high exploitation probability)
- **Chainguard Remediation Status** - Real-time fix status from Chainguard security feed
  - "Fixed in version X" for resolved vulnerabilities
  - "Under Review" for vulnerabilities being investigated

### Detailed Analysis
- **Per-Image Vulnerability Tables** - Complete breakdown for each scanned image
- **CVE Details** - Links to vulnerability databases (NVD, GitHub Security Advisories)
- **Package Information** - Affected packages and versions
- **Size Metrics** - Disk usage for each image

### Professional Formatting
- Clean light mode design optimized for readability and professional presentation
- Color-coded severity badges (Critical=Red, High=Orange, Medium=Yellow, Low=Green)
- Print-optimized CSS with proper margins (2cm top/bottom, 1.5cm left/right)
- Browser print-to-PDF produces professional output with preserved styling

---

## 🎨 Report Customization

### Adding Your Company Logo

Use the `--logo` flag to brand reports with your company logo:

```sh
python3 cgvulnreport.py images.txt cg_images.txt --logo /path/to/logo.png
```

**Logo Requirements:**
- Supported formats: PNG, JPG, SVG
- Recommended size: 200x80 pixels (will be auto-scaled)
- Logo is embedded as base64 in the HTML (no external file dependencies)
- Appears centered at the top of the report

### Confidential Footer

The report automatically includes a confidential footer with:
- ⚠️ Confidential notice and warning
- Distribution restrictions
- Auto-generated date stamp (e.g., "Generated on February 04, 2026")

No configuration needed - the footer is added automatically to every report.

---

## 💡 Tips

### Image Lists
- Keep your `images.txt` and `cg_images.txt` in sync (same number and order of images)
- Remove any leading/trailing spaces from image names
- Use `--check-pullable` on your first run to verify all images are accessible

### Performance Optimization
- **Threading**: Adjust `--threads N` based on your hardware
  - Default: 4 threads (balanced for most systems)
  - High-end systems: 8-16 threads for faster scanning
  - Resource-constrained: `--threads 1` for sequential scanning
- **Skip Flags**: Use `--skip-scan-original` or `--skip-scan-chainguard` to reuse existing scan data
  - Useful for tweaking reports without re-scanning
  - Helps avoid Docker Hub rate limits on subsequent runs

### Docker Management
- If scans fail due to disk space, clean up Docker resources:
  ```sh
  docker system prune -af --volumes
  ```
- Monitor Docker disk usage: `docker system df`

### Report Customization
- Add your logo with `--logo path/to/logo.png` for professional branding
- Reports automatically include confidential footer with generation date
- Light mode styling optimized for browser viewing and print-to-PDF

---

## 📸 Example Output

When you run the tool, you'll see progress output like this:

```
════════════════════════════════════════════════════
   Chainguard Vulnerability Comparison Report
════════════════════════════════════════════════════

✅ Dependencies installed

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Scanning original images (threads: 4)...
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Image Size On Disk:
node:22: 1079.51 MB
python:3.12: 1069.07 MB

✅ Original image scan complete

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Scanning Chainguard images (threads: 4)...
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Image Size On Disk:
cgr.dev/chainguard-private/node:22: 143.38 MB
cgr.dev/chainguard-private/python:3.12: 61.25 MB

✅ Chainguard image scan complete

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Generating HTML report...
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✅ Final report saved as 'report.html'

📊 Generated Report:
   📄 report.html
```

**Typical Results:**
- Original images: 600-2,400 vulnerabilities
- Chainguard images: 0-10 vulnerabilities
- Reduction: 99%+ elimination of vulnerabilities
- Size savings: 60-80% smaller images

