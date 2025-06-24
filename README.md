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

### 4️⃣ (Optional) Add Your Logo
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
- Copy the output and paste it into `template.md` where indicated.

### 6️⃣ Export the Report
- Use the **Markdown PDF** plugin for VS Code.
- Export the completed `template.md` to HTML, then print the HTML to PDF for best results.

---

💡 **Tip:** Keep your `images.txt` and `cg_images.txt` in sync (same number/order of images) for accurate comparisons.

---

Made with ❤️ by [metalstormbass](https://github.com/metalstormbass)
