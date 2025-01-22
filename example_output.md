### **Image Size Report**
This table lists the disk sizes of the analyzed images to highlight storage considerations.
<br>
| **Image Name**                                          |  **Size on Disk (MB)** |
|-----------------------------------------------------|---------------|
| registry.access.redhat.com/ubi9/openjdk-17:latest | 394.94        |
| registry.access.redhat.com/ubi9/openjdk-21:latest | 402.61        |
| node:20.18.1                                      | 1044.83       |
| node:22.13.0                                      | 1066.40       |
| python:3.11                                       | 968.60        |
| python:3.12                                       | 971.71        |
| nginx:latest                                      | 187.88        |
| mysql:latest                                      | 596.76        |
| postgres:latest                                   | 435.37        |
| redis:latest                                      | 133.05        |
| rabbitmq:latest                                   | 235.21        |

### **Vulnerabilities Summary**
This summary shows the total and average vulnerabilities found across all analyzed images, categorized by severity.
<br>
| **Vulnerability Type**       | **Total** | **Average** |
|--------------------------|-------|---------|
| Vulnerabilities           | 2993 | 272.09 |
| Critical CVEs           | 51 | 4.63 |
| High CVEs           | 188 | 17.09 |
| Medium CVEs           | 440 | 40.00 |
| Low CVEs           | 301 | 27.36 |

### **Fixes Available Summary**
This summary lists the availability of fixes for vulnerabilities, grouped by severity.
<br>
| **Fix Type**                | **Total** | **Average** |
|--------------------------|-------|---------|
| Fixes Available           | 189 | 272.09 |
| Critical Fixes Available           | 22 | 4.63 |
| High Fixes Available           | 98 | 17.09 |
| Medium Fixes Available           | 60 | 40.00 |
| Low Fixes Available           | 5 | 27.36 |

### **Detailed Vulnerabilty Scans**
This table provides a detailed breakdown of vulnerabilities per image, categorized by severity and fix availability.
<br>
| **Image** | **Type** | **Critical** | **High** | **Medium** | **Low** | **Wont Fix** | **Total** | **Fixed Critical** | **Fixed High** | **Fixed Medium** | **Fixed Low** | **Fixed Total** |
|-------|------|----------|------|--------|-----|----------|-------|----------------|------------|--------------|-----------|-------------|
| registry.access.redhat.com/ubi9/openjdk-17 | grype | 0 | 3 | 25 | 54 | 29 | 86 | 0 | 1 | 1 | 1 | 3 |
| registry.access.redhat.com/ubi9/openjdk-21 | grype | 0 | 3 | 28 | 51 | 29 | 83 | 0 | 1 | 1 | 1 | 3 |
| node | grype | 6 | 17 | 63 | 40 | 122 | 555 | 0 | 1 | 0 | 0 | 1 |
| node | grype | 6 | 16 | 63 | 40 | 122 | 554 | 0 | 0 | 0 | 0 | 0 |
| python | grype | 6 | 21 | 69 | 42 | 134 | 590 | 0 | 1 | 0 | 0 | 1 |
| python | grype | 6 | 21 | 69 | 42 | 134 | 590 | 0 | 1 | 0 | 0 | 1 |
| nginx | grype | 2 | 7 | 24 | 9 | 47 | 131 | 0 | 0 | 0 | 0 | 0 |
| mysql | grype | 7 | 30 | 21 | 1 | 0 | 60 | 7 | 30 | 21 | 1 | 60 |
| postgres | grype | 8 | 36 | 33 | 7 | 36 | 188 | 7 | 30 | 16 | 1 | 55 |
| redis | grype | 9 | 31 | 30 | 6 | 22 | 125 | 7 | 30 | 16 | 1 | 55 |
| rabbitmq | grype | 1 | 3 | 15 | 9 | 0 | 31 | 1 | 3 | 5 | 0 | 10 |




### **Image Size Report**
This table lists the disk sizes of the analyzed images to highlight storage considerations.
<br>
| **Image Name**                                          |  **Size on Disk (MB)** |
|-----------------------------------------------------|---------------|
| cgr.dev/chainguard-private/jdk:openjdk-17         | 222.01        |
| cgr.dev/chainguard-private/jdk:openjdk-21         | 241.82        |
| cgr.dev/chainguard-private/node:20                | 118.51        |
| cgr.dev/chainguard-private/node:22                | 136.58        |
| cgr.dev/chainguard-private/python:3.11            | 64.68         |
| cgr.dev/chainguard-private/python:3.12            | 59.98         |
| cgr.dev/chainguard-private/nginx:latest           | 19.61         |
| cgr.dev/chainguard-private/mysql:latest           | 431.18        |
| cgr.dev/chainguard-private/postgres:latest        | 97.20         |
| cgr.dev/chainguard-private/redis:latest           | 21.74         |
| cgr.dev/chainguard-private/rabbitmq:latest        | 140.22        |

### **Vulnerabilities Summary**
This summary shows the total and average vulnerabilities found across all analyzed images, categorized by severity.
<br>
| **Vulnerability Type**       | **Total** | **Average** |
|--------------------------|-------|---------|
| Vulnerabilities           | 20 | 1.81 |
| Critical CVEs           | 0 | 0 |
| High CVEs           | 0 | 0 |
| Medium CVEs           | 0 | 0 |
| Low CVEs           | 0 | 0 |

### **Fixes Available Summary**
This summary lists the availability of fixes for vulnerabilities, grouped by severity.
<br>
| **Fix Type**                | **Total** | **Average** |
|--------------------------|-------|---------|
| Fixes Available           | 20 | 1.81 |
| Critical Fixes Available           | 0 | 0 |
| High Fixes Available           | 0 | 0 |
| Medium Fixes Available           | 0 | 0 |
| Low Fixes Available           | 0 | 0 |

### **Detailed Vulnerabilty Scans**
This table provides a detailed breakdown of vulnerabilities per image, categorized by severity and fix availability.
<br>
| **Image** | **Type** | **Critical** | **High** | **Medium** | **Low** | **Wont Fix** | **Total** | **Fixed Critical** | **Fixed High** | **Fixed Medium** | **Fixed Low** | **Fixed Total** |
|-------|------|----------|------|--------|-----|----------|-------|----------------|------------|--------------|-----------|-------------|
| cgr.dev/chainguard-private/jdk | grype | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 1 |
| cgr.dev/chainguard-private/jdk | grype | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 1 |
| cgr.dev/chainguard-private/node | grype | 0 | 0 | 0 | 0 | 0 | 2 | 0 | 0 | 0 | 0 | 2 |
| cgr.dev/chainguard-private/node | grype | 0 | 0 | 0 | 0 | 0 | 2 | 0 | 0 | 0 | 0 | 2 |
| cgr.dev/chainguard-private/python | grype | 0 | 0 | 0 | 0 | 0 | 2 | 0 | 0 | 0 | 0 | 2 |
| cgr.dev/chainguard-private/python | grype | 0 | 0 | 0 | 0 | 0 | 2 | 0 | 0 | 0 | 0 | 2 |
| cgr.dev/chainguard-private/nginx | grype | 0 | 0 | 0 | 0 | 0 | 2 | 0 | 0 | 0 | 0 | 2 |
| cgr.dev/chainguard-private/mysql | grype | 0 | 0 | 0 | 0 | 0 | 3 | 0 | 0 | 0 | 0 | 3 |
| cgr.dev/chainguard-private/postgres | grype | 0 | 0 | 0 | 0 | 0 | 2 | 0 | 0 | 0 | 0 | 2 |
| cgr.dev/chainguard-private/redis | grype | 0 | 0 | 0 | 0 | 0 | 2 | 0 | 0 | 0 | 0 | 2 |
| cgr.dev/chainguard-private/rabbitmq | grype | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 1 |





The analysis of the **Original** and **Chainguard** container images reveals significant improvements in both **security** and **image size**. This report examines a sample size of **11 images**.

- **Total Vulnerabilities Reduced**: A **total of 980 vulnerabilities** were mitigated.
- **Critical & High Vulnerabilities**: The **Chainguard** images successfully reduced **Critical vulnerabilities by 51** and **High vulnerabilities by 188**.
- **Security Hygiene**: Chainguard images demonstrate near-zero vulnerabilities across **Critical**, **High**, **Medium**, and **Low** categories.

### **Key Insights:**
- **Critical CVEs** decreased from **51** to **0**.
- **High CVEs** dropped from **188** to **0**.
- **Medium CVEs** dropped from **440** to **0**.
- **Low CVEs** dropped from **301** to **0**.


| Severity   | Original            | Chainguard          | Reduction          |
|------------|---------------------|---------------------|--------------------|
| **Critical** | 51 | 0 | **51** |
| **High**    | 188     | 0     | **188**     |
| **Medium**  | 440   | 0   | **440**   |
| **Low**     | 301      | 0      | **301**      |

### **Size Reduction:**
The **Chainguard** images are, on average, **75.00% smaller per image** than their **Original counterparts**.
