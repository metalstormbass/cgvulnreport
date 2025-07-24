import markdown
from pathlib import Path
import re
import pandas as pd

# Load Markdown
with open("final_report.md", "r", encoding="utf-8") as f:
    md = f.read()

# Extract vulnerability table
table_match = re.search(
    r"\| *Severity *\| *Original *\| *Chainguard *\| *Reduction *\|\n"
    r"\|[-| ]+\|\n"  # separator line
    r"((?:\|.*\|\n)+?)"  # table rows
    r"\| *\*\*Total\*\* *\| *(\d+) *\| *(\d+) *\| *\*\*(\d+)\*\*",  # totals
    md
)

if not table_match:
    raise ValueError("Could not extract vulnerability reduction table.")

table_body, total_orig, total_cg, total_reduced = table_match.groups()

rows = [
    re.findall(r"\| *([^|]+?) *\| *(\d+) *\| *(\d+) *\| *\*\*(\d+)\*\*", line)[0]
    for line in table_body.strip().splitlines()
    if re.findall(r"\| *([^|]+?) *\| *(\d+) *\| *(\d+) *\| *\*\*(\d+)\*\*", line)
]

df = pd.DataFrame(rows, columns=["Severity", "Original", "Chainguard", "Reduction"])
df[["Original", "Chainguard", "Reduction"]] = df[["Original", "Chainguard", "Reduction"]].astype(int)

# Compute values
def reduction_card(severity):
    row = df[df["Severity"].str.lower() == severity.lower()].iloc[0]
    pct = 100 * row["Reduction"] / row["Original"] if row["Original"] > 0 else 0
    return {
        "label": f"{severity} → {row['Chainguard']}",
        "value": row["Reduction"],
        "delta": f"-{pct:.0f}%"
    }

cards = [
    {
        "label": "Total Vulns Eliminated",
        "value": int(total_reduced),
        "delta": f"-{100 * int(total_reduced) / int(total_orig):.0f}%"
    }
] + [reduction_card(sev) for sev in ["Critical", "High", "Medium", "Low"]]

# Generate KPI card HTML
kpi_cards_html = ""
for card in cards:
    kpi_cards_html += f"""
    <div class="kpi-card">
      <div class="kpi-label">{card["label"]}</div>
      <div class="kpi-value">{card["value"]}</div>
      {'<div class="kpi-delta good">' + card["delta"] + '</div>' if "delta" in card else ""}
    </div>
    """

exec_summary_cards_html = f"""
<section class="kpi-section" style="margin-top: 1rem; margin-bottom: 2rem;">
  <div class="kpi-grid">
    {kpi_cards_html}
  </div>
  <div class="kev-epss" style="margin-top: 1rem;">
    <span class="badge danger">KEV Present</span>
    <span class="badge warning">EPSS ≥ 0.75 Present</span>
  </div>
</section>
"""

# Convert markdown to HTML
html_body = markdown.markdown(md, extensions=["tables", "fenced_code", "attr_list", "toc"])

# Insert KPI cards below "Executive Summary"
html_body = re.sub(
    r"(<h2[^>]*>Executive Summary<\/h2>)",
    r"\1\n" + exec_summary_cards_html,
    html_body,
    flags=re.IGNORECASE
)

# Final HTML output
html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>🛡️ Image Vulnerability Report</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {{
            font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f8fafc;
            color: #1e293b;
            padding: 2rem;
            line-height: 1.6;
        }}
        h1, h2, h3 {{
            color: #0f172a;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 2rem 0;
        }}
        th, td {{
            border: 1px solid #e2e8f0;
            padding: 0.75rem;
            text-align: center;
        }}
        th {{
            background-color: #1e293b;
            color: white;
        }}
        tr:nth-child(even) {{
            background-color: #f1f5f9;
        }}
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 1rem;
            margin-top: 1rem;
            margin-bottom: 1.5rem;
        }}
        .kpi-card {{
            background: #ffffff;
            border: 1px solid #e2e8f0;
            border-radius: 12px;
            padding: 1rem 1.25rem;
            box-shadow: 0 1px 2px rgba(0,0,0,0.04);
        }}
        .kpi-label {{
            font-size: 0.9rem;
            color: #64748b;
            margin-bottom: 0.35rem;
        }}
        .kpi-value {{
            font-size: 2rem;
            font-weight: 700;
            color: #0f172a;
        }}
        .kpi-delta.good {{
            color: #059669;
            font-weight: 600;
        }}
        .badge {{
            display: inline-block;
            padding: 0.25rem 0.6rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            margin-right: 0.5rem;
        }}
        .badge.danger {{ background:#fee2e2; color:#b91c1c; }}
        .badge.warning {{ background:#fef3c7; color:#92400e; }}
        footer {{
            text-align: center;
            font-size: 12px;
            color: gray;
            margin-top: 4rem;
        }}
    </style>
</head>
<body>
{html_body}
<footer>
    <hr>
    <p>This document is confidential and proprietary. Prepared by Chainguard, Inc. |
    <a href="https://chainguard.dev" target="_blank">chainguard.dev</a></p>
</footer>
</body>
</html>
"""

# Save to output file
Path("report.html").write_text(html_template, encoding="utf-8")
print("✅ Final report saved as 'report.html'")
