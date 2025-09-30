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
- The final report will be generated as `final_report.md` using the template in `template.md`.
- **Troubleshooting**: If the report is not successfully generated, check `out.txt` for any error messages that could indicate what to do next (like opening & running Docker Desktop).

**Note:** You no longer need to manually copy and paste the output into the template. The script automatically injects the generated content into the template at the `[INSERT OUTPUT FROM SCRIPT HERE]` marker.
**API Rate Limit Note:** To avoid hitting Chainguard or Docker Hub rate limits, you can scan images that are already stored locally on your machine instead of pulling them with every run of `metascript.sh`. This is done by commenting out lines 43-52 (from `python3 check-pullable...` to `exit2 fi`.

### 6️⃣ Export the Report
- Use the **Markdown PDF** plugin for VS Code.
- Export the completed `template.md` to HTML, then print the HTML to PDF for best results.

---

## 🚦 Automated Workflow & Python Integration

The main workflow is fully automated:

- **metascript.sh** orchestrates the entire process, including:
  - Setting up a Python virtual environment (`.venv`) if one does not exist.
  - Automatically installing required Python dependencies (`markdown`, `pandas`) using `requirements.txt`.
  - Running all necessary Python scripts for report generation, including `reportbuild.py`.
- **No manual pip install required!** The script checks and installs dependencies for you.
- **Report Generation:**
  - The Python script `reportbuild.py` is called automatically by `metascript.sh` after all data is processed.
  - It parses the vulnerability reduction table, generates KPI cards, and injects them into the final HTML report.
  - The final report (`report.html`) is created with all metrics and summary cards, ready for export or sharing.

**You only need to run:**
```sh
./metascript.sh images.txt cg_images.txt
```

Everything else is handled for you!

---

## Python Requirements

This project requires Python 3 and the following packages:

```
markdown
pandas
```

You can install them using:

```
pip install -r requirements.txt
```

The report generation script (`reportbuild.py`) depends only on these packages. No other Python dependencies are required.

💡 **Tip:** Keep your `images.txt` and `cg_images.txt` in sync (same number/order of images) for accurate comparisons.

---

Made with ❤️ by [metalstormbass](https://github.com/metalstormbass)
