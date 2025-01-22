Detailed Vulnerability Scans - Original List:
---------------------------------------------
Image	Type	Critical	High	Medium	Low	Wont Fix	Total	Fixed Critical	Fixed High	Fixed Medium	Fixed Low	Fixed Total
registry.access.redhat.com/ubi9/openjdk-17:latest	trivy	0	0	27	54	0	81	0	0	0	0	0
registry.access.redhat.com/ubi9/openjdk-17:latest	grype	0	3	25	54	0	86	0	1	1	1	3
node:20.18.1	trivy	6	95	459	529	0	1092	0	0	0	0	0
node:20.18.1	trivy	0	1	0	0	0	1	0	1	0	0	1
node:20.18.1	grype	6	17	63	40	0	555	0	1	0	0	1
python:3.11	trivy	6	99	465	554	0	1127	0	0	0	0	0
python:3.11	trivy	0	1	0	0	0	1	0	1	0	0	1
python:3.11	grype	6	21	69	42	0	590	0	1	0	0	1

Detailed Vulnerability Scans - New List:
----------------------------------------
Image	Type	Critical	High	Medium	Low	Wont Fix	Total	Fixed Critical	Fixed High	Fixed Medium	Fixed Low	Fixed Total
cgr.dev/chainguard-private/jdk	trivy	0	0	0	0	0	0	0	0	0	0	0
cgr.dev/chainguard-private/jdk	grype	0	0	0	0	0	1	0	0	0	0	0
cgr.dev/chainguard-private/node	trivy	0	0	0	0	0	0	0	0	0	0	0
cgr.dev/chainguard-private/node	grype	0	0	0	0	0	2	0	0	0	0	0
cgr.dev/chainguard-private/python	trivy	0	0	0	0	0	0	0	0	0	0	0
cgr.dev/chainguard-private/python	grype	0	0	0	0	0	2	0	0	0	0	0

Original List Results:
----------------------
Total Vulnerabilities: 3533
Total Critical CVEs: 24
Total High CVEs: 237
Total Medium CVEs: 1108
Total Low CVEs: 1273
Total Unknown CVEs: 891

Fixes Available Summary (Original List):
----------------------------------------
Fix Type                 Total    Average
----------------------   -------  -------
Fixes Available          7   2.33
Critical Fixes Available 0   0.00
High Fixes Available     5   1.67
Medium Fixes Available   1   0.33
Low Fixes Available      1   0.33

Image Size Report (Original List):
----------------------------------
=================  =========
Image            Size (MB)
=================  =========
registry.access.redhat.com/ubi9/openjdk-17:latest  401.34
node:20.18.1      1067.81
python:3.11       989.95
=================  =========
Total Size:       2459.10 MB

New List Results:
-----------------
Total Vulnerabilities: 5
Total Critical CVEs: 0
Total High CVEs: 0
Total Medium CVEs: 0
Total Low CVEs: 0
Total Unknown CVEs: 5

Fixes Available Summary (New List):
-----------------------------------
Fix Type                 Total    Average
----------------------   -------  -------
Fixes Available          0   0.00
Critical Fixes Available 0   0.00
High Fixes Available     0   0.00
Medium Fixes Available   0   0.00
Low Fixes Available      0   0.00

Reduction Table:
----------------
=================  ==========  ========  ===========
Severity           Original    New       Reduction
=================  ==========  ========  ===========
Critical           24      0       24
High               237          0           237
Medium             1108        0         1108
Low                1273           0            1273
Unknown            891       5        886
=================  ==========  ========  ===========

Key Insights:
-------------
* Critical CVEs decreased from 24 to 0.
* High CVEs dropped from 237 to 0.
* Medium CVEs dropped from 1108 to 0.
* Low CVEs dropped from 1273 to 0.
* Unknown CVEs dropped from 891 to 5.

Image Size Report (New List):
-----------------------------
=================  =========
Image            Size (MB)
=================  =========
cgr.dev/chainguard-private/jdk  246.53
cgr.dev/chainguard-private/node  142.58
cgr.dev/chainguard-private/python  59.28
=================  =========
Total Size:       448.39 MB

Size Change Analysis:
---------------------
Original Total Size: 2459.10 MB
New Total Size: 448.39 MB
Size Difference: -2010.71 MB
Percentage Change: -81.77%

