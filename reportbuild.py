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
    
    # Color mapping for severity levels
    color_map = {
        "critical": "#ef4444",
        "high": "#f97316",
        "medium": "#eab308",
        "low": "#22c55e"
    }
    color = color_map.get(severity.lower(), "#9333ea")
    
    return {
        "label": f"{severity} → {row['Chainguard']}",
        "value": row["Reduction"],
        "delta": f"{pct:.1f}%",
        "color": color,
        "severity": severity.lower()
    }

cards = [
    {
        "label": "Total Vulns Eliminated",
        "value": int(total_reduced),
        "delta": f"{100 * int(total_reduced) / int(total_orig):.1f}%",
        "color": "#9333ea",
        "severity": "total"
    }
] + [reduction_card(sev) for sev in ["Critical", "High", "Medium", "Low"]]

# Generate KPI card HTML with color coding
kpi_cards_html = ""
for i, card in enumerate(cards):
    is_primary = i == 0
    color = card.get("color", "#9333ea")
    severity = card.get("severity", "")
    
    kpi_cards_html += f"""
    <div class="kpi-card kpi-card-{severity}" data-severity="{severity}">
      <div class="kpi-accent" style="background-color: {color};"></div>
      <div class="kpi-label">{card["label"]}</div>
      <div class="kpi-value" style="{'color: ' + color + ';' if is_primary else ''}">{card["value"]}</div>
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

# Inject KPI section BEFORE Executive Summary title, then keep title after KPI
html_body = re.sub(
    r"(<h2[^>]*>Executive Summary<\/h2>)",
    exec_summary_cards_html + r"\1",
    html_body,
    flags=re.IGNORECASE
)

# Final HTML Template with Chainguard-inspired Professional Styling
html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>🛡️ Image Vulnerability Report</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    * {{
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }}
    
    html {{
      scroll-behavior: smooth;
    }}
    
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Roboto", sans-serif;
      background: #ffffff;
      color: #1a202c;
      padding: 0;
      line-height: 1.65;
      min-height: 100vh;
    }}
    
    main {{
      width: 100%;
      max-width: 1000px;
      margin: 0 auto;
      padding: 3.5rem 2.5rem;
    }}
    
    > h1 {{
      background: linear-gradient(135deg, #6b21a8 0%, #9333ea 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
      font-size: 2.8rem;
      font-weight: 900;
      margin-top: 0;
      margin-bottom: 0.5rem;
      letter-spacing: -0.03em;
      text-align: center;
    }}
    
    > h1::before {{
      content: "";
    }}
    
    > h2 {{
      color: #666;
      font-size: 1rem;
      font-weight: 500;
      margin-top: 0;
      margin-bottom: 3rem;
      text-align: center;
      letter-spacing: 0.5px;
      text-transform: uppercase;
    }}
    
    > h3 {{
      color: #2d2d2d;
      font-size: 1.5rem;
      font-weight: 700;
      margin-top: 2.5rem;
      margin-bottom: 1.5rem;
      text-align: center;
      position: relative;
      padding: 0.75rem 0;
      border-bottom: 3px solid #9333ea;
    }}
    
    h3 {{
      color: #1a202c;
      font-size: 1.1rem;
      font-weight: 700;
      margin-top: 1.75rem;
      margin-bottom: 0.875rem;
      text-align: left;
      color: #6b21a8;
      letter-spacing: 0.3px;
    }}
    
    p {{
      margin-bottom: 1rem;
      color: #3a3a3a;
      font-size: 0.95rem;
      line-height: 1.8;
      text-align: left;
    }}
    
    table {{
      width: 100%;
      border-collapse: collapse;
      margin: 2rem 0;
      background: #ffffff;
      border: 1px solid #ddd;
    }}
    
    th {{
      background: linear-gradient(135deg, #6b21a8 0%, #8b5cf6 100%);
      color: #ffffff;
      padding: 1rem 0.75rem;
      text-align: center;
      font-weight: 700;
      letter-spacing: 0.3px;
      font-size: 0.85rem;
      text-transform: uppercase;
      border: none;
    }}
    
    td {{
      padding: 0.875rem 0.75rem;
      text-align: center;
      border-bottom: 1px solid #e8e8e8;
      font-weight: 500;
      color: #2d2d2d;
    }}
    
    tr:last-child td {{
      border-bottom: 2px solid #6b21a8;
    }}
    
    .kpi-section {{
      margin: 0 -2.5rem 2rem -2.5rem;
      padding: 2rem 2.5rem;
      background: #f9f7ff;
      border-top: 2px solid #9333ea;
      border-bottom: 2px solid #9333ea;
      break-inside: avoid;
      page-break-inside: avoid;
    }}
    
    .kpi-grid {{
      display: grid;
      grid-template-columns: repeat(5, 1fr);
      gap: 1rem;
      margin-bottom: 1.5rem;
      break-inside: avoid;
      page-break-inside: avoid;
    }}
    
    @media (max-width: 1200px) {{
      .kpi-grid {{
        grid-template-columns: repeat(3, 1fr);
      }}
    }}
    
    @media (max-width: 768px) {{
      .kpi-grid {{
        grid-template-columns: repeat(2, 1fr);
      }}
    }}
    
    @media (max-width: 600px) {{
      .kpi-grid {{
        grid-template-columns: 1fr;
      }}
    }}
    
    .kpi-card {{
      background: #ffffff;
      border-radius: 0.5rem;
      padding: 1.5rem 1rem;
      border: 2px solid #e8d5f2;
      display: flex;
      flex-direction: column;
      justify-content: center;
      align-items: center;
      text-align: center;
      min-height: 140px;
      position: relative;
      overflow: hidden;
      box-shadow: none;
      break-inside: avoid;
      page-break-inside: avoid;
    }}
    
    .kpi-accent {{
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 4px;
      background: #9333ea;
    }}
    
    .kpi-card-critical .kpi-accent {{
      background: #ef4444;
    }}
    
    .kpi-card-high .kpi-accent {{
      background: #f97316;
    }}
    
    .kpi-card-medium .kpi-accent {{
      background: #eab308;
    }}
    
    .kpi-card-low .kpi-accent {{
      background: #22c55e;
    }}
    
    .kpi-label {{
      font-size: 0.7rem;
      color: #666;
      margin-bottom: 0.8rem;
      margin-top: 0.4rem;
      text-align: center;
      font-weight: 700;
      letter-spacing: 0.4px;
      text-transform: uppercase;
    }}
    
    .kpi-value {{
      font-size: 2.25rem;
      font-weight: 900;
      color: #1a1a1a;
      line-height: 1;
      margin-bottom: 0.4rem;
    }}
    
    .kpi-delta.good {{
      color: #10b981;
      font-weight: 700;
      font-size: 0.85rem;
      margin-top: 0.4rem;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 0.2rem;
    }}
    
    .kpi-delta.good::before {{
      content: "↓";
      font-weight: bold;
      font-size: 1rem;
    }}
    
    .kev-epss {{
      margin-top: 2rem;
      text-align: center;
      display: flex;
      gap: 1rem;
      justify-content: center;
      flex-wrap: wrap;
    }}
    
    .badge {{
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      padding: 0.65rem 1.25rem;
      border-radius: 0.5rem;
      font-size: 0.75rem;
      font-weight: 700;
      letter-spacing: 0.3px;
      text-transform: uppercase;
      box-shadow: none;
    }}
    
    .badge.danger {{
      background: #fecaca;
      color: #b91c1c;
      border: 2px solid #ef4444;
    }}
    
    .badge.warning {{
      background: #fde68a;
      color: #92400e;
      border: 1.5px solid #f59e0b;
    }}
    
    code {{
      background-color: #f3e8ff;
      padding: 0.25rem 0.5rem;
      border-radius: 0.3rem;
      font-family: "Menlo", "Monaco", monospace;
      color: #6b21a8;
      font-size: 0.85rem;
    }}
    
    pre {{
      background: #1f2937;
      color: #e5e7eb;
      padding: 1.5rem;
      border-radius: 0.5rem;
      overflow-x: auto;
      margin: 1.5rem 0;
      font-family: "Menlo", "Monaco", monospace;
      font-size: 0.8rem;
      line-height: 1.5;
      border-left: 4px solid #9333ea;
    }}
    
    pre code {{
      background: none;
      color: inherit;
      padding: 0;
    }}
    
    a {{
      color: #6b21a8;
      text-decoration: none;
      font-weight: 600;
    }}
    
    a:hover {{
      text-decoration: underline;
    }}
    
    ul, ol {{
      margin-left: 2rem;
      margin-bottom: 1rem;
      text-align: left;
      background: linear-gradient(135deg, #f9f7ff 0%, #faf8ff 100%);
      padding: 1.25rem 2rem 1.25rem 2.5rem;
      border-radius: 0.5rem;
      border-left: 4px solid #9333ea;
      box-shadow: 0 2px 4px rgba(147, 51, 234, 0.06);
    }}
    
    li {{
      margin-bottom: 0.7rem;
      color: #3a3a3a;
      line-height: 1.6;
      font-weight: 500;
    }}
    
    li:last-child {{
      margin-bottom: 0;
    }}
    
    blockquote {{
      border-left: 4px solid #9333ea;
      padding-left: 1.5rem;
      margin-left: 0;
      margin-bottom: 1.5rem;
      color: #3a3a3a;
      font-style: italic;
      background: #f8f4ff;
      padding: 1rem 1rem 1rem 1.5rem;
      border-radius: 0 0.3rem 0.3rem 0;
    }}
    
    footer {{
      text-align: center;
      font-size: 0.75rem;
      color: #888;
      margin-top: 3rem;
      padding: 2rem 2.5rem;
      border-top: 2px solid #e8e8e8;
    }}
    
    footer p {{
      margin-bottom: 0.25rem;
      text-align: center;
      color: #888;
    }}
    
    @media print {{
      body {{
        background: white;
      }}
      
      main {{
        padding: 2.5rem;
        max-width: 100%;
      }}
      
      .kpi-section {{
        margin: 0;
        page-break-inside: avoid;
      }}
      
      .kpi-card {{
        break-inside: avoid;
      }}
      
      table {{
        break-inside: avoid;
        page-break-inside: avoid;
      }}
      
      thead {{
        display: table-header-group;
      }}
      
      tfoot {{
        display: table-footer-group;
      }}
      
      tr {{
        page-break-inside: avoid;
      }}
      
      h2 {{
        page-break-after: avoid;
      }}
    }}
    
    @media print {{
      body {{
        background: white;
        padding: 0;
      }}
      
      main {{
        padding: 0;
      }}
      
      .kpi-section {{
        background: #f9f7ff;
        margin: 0;
        padding: 1.5rem 1rem;
        break-inside: avoid;
        page-break-inside: avoid;
      }}
      
      .kpi-grid {{
        gap: 0.75rem;
        break-inside: avoid;
        page-break-inside: avoid;
      }}
      
      .kpi-card {{
        break-inside: avoid;
        page-break-inside: avoid;
        background: white;
        border: 1px solid #d4d4d8;
        padding: 1rem 0.75rem;
        min-height: 120px;
        box-shadow: none;
      }}
      
      .kpi-label {{
        font-size: 0.65rem;
      }}
      
      .kpi-value {{
        font-size: 1.75rem;
      }}
      
      .kpi-delta {{
        font-size: 0.75rem;
      }}
      
      table {{
        break-inside: avoid;
      }}
    }}
    
    @media (max-width: 1200px) {{
      main {{
        padding: 3rem 1.5rem;
      }}
      
      > h1 {{
        font-size: 2.25rem;
      }}
      
      .kpi-section {{
        padding: 2.5rem 1.5rem;
      }}
    }}
    
    @media (max-width: 768px) {{
      main {{
        padding: 2rem 1rem;
      }}
      
      > h1 {{
        font-size: 1.75rem;
      }}
      
      h2 {{
        font-size: 1.5rem;
        margin-top: 2rem;
      }}
      
      .kpi-section {{
        padding: 1.5rem 1rem;
        margin: 2rem 0;
      }}
      
      .kpi-grid {{
        gap: 1rem;
      }}
      
      .kpi-card {{
        min-height: 140px;
        padding: 1.5rem 1rem;
      }}
      
      .kpi-label {{
        font-size: 0.7rem;
      }}
      
      .kpi-value {{
        font-size: 2rem;
      }}
      
      table {{
        font-size: 0.85rem;
      }}
      
      th {{
        padding: 1rem;
      }}
      
      td {{
        padding: 0.75rem 0.5rem;
      }}
      
      p {{
        font-size: 0.9rem;
      }}
    }}
    
    @media (max-width: 600px) {{
      main {{
        padding: 1.5rem 0.75rem;
      }}
      
      > h1 {{
        font-size: 1.5rem;
      }}
      
      .kpi-section {{
        padding: 1rem 0.75rem;
      }}
      
      .kpi-grid {{
        grid-template-columns: 1fr;
        gap: 0.75rem;
      }}
      
      .kpi-card {{
        min-height: 130px;
        padding: 1.25rem 0.75rem;
      }}
      
      .kpi-value {{
        font-size: 1.75rem;
      }}
    }}
  </style>
</head>
<body>
<main>
{html_body}
</main>
</body>
</html>
"""

# Save to output file
Path("report.html").write_text(html_template, encoding="utf-8")
print("✅ Final report saved as 'report.html'")
