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
    r"\|[-| ]+\|\n"
    r"((?:\|.*\|\n)+?)"
    r"\| *\*\*Total\*\* *\| *(\d+) *\| *(\d+) *\| *\*\*(\d+)\*\*",
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

# Check for KEV and EPSS presence
has_kev = re.search(r"## +Known Exploited Vulnerabilities \(KEV\)", md, re.IGNORECASE) is not None
has_epss = re.search(r"## +Exploit Prediction Scoring System \(EPSS\)", md, re.IGNORECASE) is not None

badges_html = ""
if has_kev:
    badges_html += '<span class="badge danger">KEV Present</span>\n'
if has_epss:
    badges_html += '<span class="badge warning">EPSS ≥ 0.75 Present</span>\n'

exec_summary_cards_html = f"""
<section class="kpi-section">
  <div class="kpi-grid">
    {kpi_cards_html}
  </div>
  {'<div class="kev-epss">' + badges_html + '</div>' if badges_html else ''}
</section>
"""

# Convert markdown to HTML
html_body = markdown.markdown(md, extensions=["tables", "fenced_code", "attr_list", "toc"])

# Inject KPI section
html_body = re.sub(
    r"(<h2[^>]*>Executive Summary<\/h2>)",
    r"\1\n" + exec_summary_cards_html,
    html_body,
    flags=re.IGNORECASE
)

# Final HTML Template
html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>🛡️ Image Vulnerability Report</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body {{
      font-family: system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background-color: #f9fafb;
      color: #1f2937;
      padding: 2rem;
      max-width: 1200px;
      margin: auto;
      line-height: 1.7;
    }}
    h1, h2, h3 {{
      color: #111827;
      margin-top: 2rem;
      margin-bottom: 1rem;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin: 2rem 0;
    }}
    th, td {{
      border: 1px solid #e5e7eb;
      padding: 0.75rem 1rem;
      text-align: center;
    }}
    th {{
      background-color: #111827;
      color: white;
    }}
    tr:nth-child(even) {{
      background-color: #f3f4f6;
    }}
    .kpi-section {{
      margin: 2rem 0;
    }}
    .kpi-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1.5rem;
    }}
    .kpi-card {{
      background: white;
      border: 1px solid #e5e7eb;
      border-radius: 1rem;
      padding: 1.25rem 1.5rem;
      box-shadow: 0 2px 6px rgba(0, 0, 0, 0.05);
      display: flex;
      flex-direction: column;
      justify-content: center;
      align-items: center;
    }}
    .kpi-label {{
      font-size: 0.95rem;
      color: #6b7280;
      margin-bottom: 0.5rem;
      text-align: center;
    }}
    .kpi-value {{
      font-size: 2.2rem;
      font-weight: 700;
      color: #111827;
    }}
    .kpi-delta.good {{
      color: #059669;
      font-weight: 600;
      font-size: 0.9rem;
      margin-top: 0.3rem;
    }}
    .kev-epss {{
      margin-top: 1.5rem;
      text-align: center;
    }}
    .badge {{
      display: inline-block;
      padding: 0.35rem 0.75rem;
      border-radius: 9999px;
      font-size: 0.75rem;
      font-weight: 600;
      margin: 0 0.25rem;
      box-shadow: 0 1px 2px rgba(0,0,0,0.06);
    }}
    .badge.danger {{
      background-color: #fee2e2;
      color: #991b1b;
    }}
    .badge.warning {{
      background-color: #fef3c7;
      color: #92400e;
    }}
    footer {{
      text-align: center;
      font-size: 0.75rem;
      color: #9ca3af;
      margin-top: 4rem;
      padding-top: 2rem;
      border-top: 1px solid #e5e7eb;
    }}
    a {{
      color: #2563eb;
      text-decoration: none;
    }}
  </style>
</head>
<body>
{html_body}

</body>
</html>
"""

# Save to output file
Path("report.html").write_text(html_template, encoding="utf-8")
print("✅ Final report saved as 'report.html'")
