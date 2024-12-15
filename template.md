# Image Report 

Prepared for:<br>
<img src="CUSTOMERLOGO" alt="Logo" width="200">

---
## Executive Summary

The table below shows the reduction in vulnerabilities between the **Original Images** and **Chainguard ** images. The **Critical**, **High**, **Medium**, and **Low** vulnerability types are listed with their respective reductions.

The total reduction in vulnerabilities is **223**.

| Vulnerability Type | Original | Chainguard | Reduction |
|--------------------|----------|------------|-----------|
| Critical           | 12 | 0 | 12 |
| High               | 61     | 0     | 61     |
| Medium             | 83   | 0   | 83   |
| Low                | 67      | 0      | 67      |

---

## Original Images

| Image Name                                          | Size on Disk  |
|-----------------------------------------------------|---------------|
| registry.access.redhat.com/ubi9/openjdk-17:latest | 72.093 MB     |
| python:3.10.8-slim                                | 18.311 MB     |

### Vulnerabilities Summary
| Vulnerability Type       | Total | Average |
|--------------------------|-------|---------|
| Vulnerabilities           | 311 | 155.50 |
| Critical CVEs           | 12 | 6.00 |
| High CVEs           | 61 | 30.50 |
| Medium CVEs           | 83 | 41.50 |
| Low CVEs           | 67 | 33.50 |

### Fixes Available Summary
| Fix Type                 | Total | Average |
|--------------------------|-------|---------|
| Fixes Available           | 134 | 155.50 |
| Critical Fixes Available           | 10 | 6.00 |
| High Fixes Available           | 55 | 30.50 |
| Medium Fixes Available           | 44 | 41.50 |
| Low Fixes Available           | 12 | 33.50 |

### Scans
| Image | Type | Critical | High | Medium | Low | Wont Fix | Total | Fixed Critical | Fixed High | Fixed Medium | Fixed Low | Fixed Total |
|-------|------|----------|------|--------|-----|----------|-------|----------------|------------|--------------|-----------|-------------|
| registry.access.redhat.com/ubi9/openjdk-17 | grype | 0 | 3 | 20 | 53 | 32 | 80 | 0 | 1 | 1 | 1 | 3 |
| python | grype | 12 | 58 | 63 | 14 | 28 | 231 | 10 | 54 | 43 | 11 | 131 |

---

<br><img src="cg-logo.png" alt="Logo" width="200"><br>


## Chainguard Images

| Image Name                                          | Size on Disk  |
|-----------------------------------------------------|---------------|
| cgr.dev/chainguard-private/jdk:openjdk-17         | 73.422 MB     |
| cgr.dev/chainguard-private/python:3.10            | 34.75 MB      |

### Vulnerabilities Summary
| Vulnerability Type       | Total | Average |
|--------------------------|-------|---------|
| Vulnerabilities           | 0 | 0 |
| Critical CVEs           | 0 | 0 |
| High CVEs           | 0 | 0 |
| Medium CVEs           | 0 | 0 |
| Low CVEs           | 0 | 0 |

### Fixes Available Summary
| Fix Type                 | Total | Average |
|--------------------------|-------|---------|
| Fixes Available           | 0 | 0 |
| Critical Fixes Available           | 0 | 0 |
| High Fixes Available           | 0 | 0 |
| Medium Fixes Available           | 0 | 0 |
| Low Fixes Available           | 0 | 0 |

### Scans
| Image | Type | Critical | High | Medium | Low | Wont Fix | Total | Fixed Critical | Fixed High | Fixed Medium | Fixed Low | Fixed Total |
|-------|------|----------|------|--------|-----|----------|-------|----------------|------------|--------------|-----------|-------------|
| cgr.dev/chainguard-private/jdk | grype | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| cgr.dev/chainguard-private/python | grype | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
