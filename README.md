# Chainguard Vulnerability Comparison

## Usage

**Note: for best results, use VS Code**

Clone Repo

```
git clone https://github.com/metalstormbass/cgvulnreport.git
```

Update ```scan_script.sh``` with images you would like to compare with Chainguard:

```
images=(
  "nginx:latest"
  "mysql:latest"
  "python:latest"
  "golang:latest"
  "docker.io/otel/opentelemetry-collector-contrib"
  "docker.io/bitnami/redis-cluster"
  "mcr.microsoft.com/dotnet/sdk:9.0"
  "mcr.microsoft.com/dotnet/runtime:9.0"
  "jupyter/base-notebook"
)
```

Update ```scan_script_chainguard.sh``` with the Chainguard equivalent images

```
images=(
 "cgr.dev/chainguard-private/nginx:latest"
  "cgr.dev/chainguard-private/mysql:latest"
  "cgr.dev/chainguard-private/python:latest"
  "cgr.dev/chainguard-private/go:latest"
  "cgr.dev/chainguard-private/opentelemetry-collector-contrib:latest"
  "cgr.dev/chainguard-private/redis:latest"
  "cgr.dev/chainguard-private/dotnet-sdk:latest"
  "cgr.dev/chainguard-private/dotnet-runtime:latest"
  "cgr.dev/chainguard-private/jupyter-base-notebook:latest"
)
```

Make the scripts executable:

```
chmod +x scan_script_chainguard.sh
chmod +x scan_script.sh
chmod +x metascript.sh
```
Run ```metascript.sh```

```
./metascript.sh
```

Find logo and save it in this directory. Update the template.md:

```
**Prepared for:**  
<img src="logo.png" alt="Customer Logo" width="200">
```

Run the script copy the output into the template where indicated.

```
 ./metascript. 
```

To get the best results for PDF output, use Markdown PDF plugin for VS Code. **Export the completed template to HTML** and then print that HTML to PDF.
