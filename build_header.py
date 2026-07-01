#!/usr/bin/env python3
"""Build a self-contained, print-safe SVG header banner for the vulnerability report.

The banner bakes the title text, a vector shield mark, and the Chainguard logo
directly into an SVG so it renders crisply and reliably when printing to PDF
(unlike CSS gradient-clipped text or emoji, which drop out in many print engines).
"""
import base64
from pathlib import Path

LOGO = Path("cg-logo.png")
OUT = Path("assets/report-header.svg")

logo_b64 = base64.b64encode(LOGO.read_bytes()).decode()

# Chainguard brand palette (sampled from the official logo)
CG_BLUE = "#3443f4"      # primary wordmark blue
CG_PURPLE = "#6657f4"    # octopus body purple
CG_INK = "#1b1830"       # near-black ink for headings
CG_TINT = "#eef0fe"      # light blue tint

# Logo intrinsic aspect ratio 2666 x 394
logo_w = 250
logo_h = round(logo_w * 394 / 2666)  # ~37

svg = f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 220" role="img"
     aria-label="Image Vulnerability Report — Chainguard Container Security Analysis"
     font-family="'Helvetica Neue', 'Segoe UI', Arial, sans-serif">
  <defs>
    <linearGradient id="cgShield" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="{CG_BLUE}"/>
      <stop offset="1" stop-color="{CG_PURPLE}"/>
    </linearGradient>
    <linearGradient id="cgBar" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="{CG_PURPLE}"/>
      <stop offset="1" stop-color="{CG_BLUE}"/>
    </linearGradient>
  </defs>

  <!-- Card -->
  <rect x="2" y="2" width="1196" height="216" rx="20" fill="#ffffff" stroke="#d9dcfb" stroke-width="2"/>
  <!-- Left accent bar -->
  <rect x="2" y="2" width="12" height="216" rx="6" fill="url(#cgBar)"/>

  <!-- Shield mark -->
  <g transform="translate(34,64)">
    <path d="M36 4 L66 15 V46 C66 65 53 78 36 86 C19 78 6 65 6 46 V15 Z"
          fill="url(#cgShield)"/>
    <path d="M22 45 L32 56 L52 31" fill="none" stroke="#ffffff"
          stroke-width="7" stroke-linecap="round" stroke-linejoin="round"/>
  </g>

  <!-- Title -->
  <text x="150" y="98" font-size="43" font-weight="800" fill="{CG_INK}"
        letter-spacing="-1">Image Vulnerability Report</text>
  <text x="152" y="140" font-size="20" font-weight="600" fill="{CG_BLUE}"
        letter-spacing="0.2">Container Security Analysis</text>

  <!-- Divider + Chainguard logo -->
  <line x1="152" y1="160" x2="700" y2="160" stroke="{CG_TINT}" stroke-width="3"/>
  <image x="{1180 - logo_w}" y="{110 - logo_h // 2}" width="{logo_w}" height="{logo_h}"
         href="data:image/png;base64,{logo_b64}"/>
</svg>
"""

OUT.write_text(svg, encoding="utf-8")
print(f"Wrote {OUT} ({OUT.stat().st_size} bytes)")
