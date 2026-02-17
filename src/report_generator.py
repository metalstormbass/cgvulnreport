"""Report generation functionality - Direct HTML generation for PDF output."""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .scanner import ScanResult


class ReportGenerator:
    """Generates vulnerability comparison reports in HTML format optimized for PDF."""

    def __init__(
        self,
        original_results: ScanResult,
        chainguard_results: ScanResult,
        scanner=None,
        logo_path: Optional[str] = None
    ):
        self.original_results = original_results
        self.scanner = scanner
        self.chainguard_results = chainguard_results
        self.logo_path = logo_path

    def _get_vulnerability_stats(self):
        """Extract vulnerability statistics from scan results."""
        orig_data = self.original_results.json_data
        cg_data = self.chainguard_results.json_data

        # Sum vulnerabilities by severity
        stats = {
            'critical_orig': sum(item["scan"]["critical"] for item in orig_data["items"]),
            'high_orig': sum(item["scan"]["high"] for item in orig_data["items"]),
            'medium_orig': sum(item["scan"]["medium"] for item in orig_data["items"]),
            'low_orig': sum(item["scan"]["low"] for item in orig_data["items"]),
            'critical_cg': sum(item["scan"]["critical"] for item in cg_data["items"]),
            'high_cg': sum(item["scan"]["high"] for item in cg_data["items"]),
            'medium_cg': sum(item["scan"]["medium"] for item in cg_data["items"]),
            'low_cg': sum(item["scan"]["low"] for item in cg_data["items"]),
            'num_images': len(orig_data["items"])
        }

        # Calculate reductions
        stats['reduction_critical'] = stats['critical_orig'] - stats['critical_cg']
        stats['reduction_high'] = stats['high_orig'] - stats['high_cg']
        stats['reduction_medium'] = stats['medium_orig'] - stats['medium_cg']
        stats['reduction_low'] = stats['low_orig'] - stats['low_cg']
        stats['total_reduction'] = (stats['reduction_critical'] + stats['reduction_high'] +
                                   stats['reduction_medium'] + stats['reduction_low'])
        stats['total_orig'] = stats['critical_orig'] + stats['high_orig'] + stats['medium_orig'] + stats['low_orig']
        stats['total_cg'] = stats['critical_cg'] + stats['high_cg'] + stats['medium_cg'] + stats['low_cg']

        return stats

    def _generate_kpi_cards_html(self, stats: Dict) -> str:
        """Generate KPI cards HTML."""
        def reduction_card(severity, orig, cg, reduction, color):
            pct = 100 * reduction / orig if orig > 0 else 0
            return f"""
    <div class="kpi-card kpi-card-{severity.lower()}" data-severity="{severity.lower()}">
      <div class="kpi-accent" style="background-color: {color};"></div>
      <div class="kpi-label">{severity} → {cg}</div>
      <div class="kpi-value">{reduction}</div>
      <div class="kpi-delta good">↓ {pct:.1f}%</div>
    </div>"""

        total_pct = 100 * stats['total_reduction'] / stats['total_orig'] if stats['total_orig'] > 0 else 0

        kpi_html = f"""
    <div class="kpi-card kpi-card-total" data-severity="total">
      <div class="kpi-accent" style="background-color: #9333ea;"></div>
      <div class="kpi-label">Total Vulns Eliminated</div>
      <div class="kpi-value" style="color: #9333ea;">{stats['total_reduction']}</div>
      <div class="kpi-delta good">↓ {total_pct:.1f}%</div>
    </div>"""

        kpi_html += reduction_card("Critical", stats['critical_orig'], stats['critical_cg'],
                                   stats['reduction_critical'], "#ef4444")
        kpi_html += reduction_card("High", stats['high_orig'], stats['high_cg'],
                                   stats['reduction_high'], "#f97316")
        kpi_html += reduction_card("Medium", stats['medium_orig'], stats['medium_cg'],
                                   stats['reduction_medium'], "#eab308")
        kpi_html += reduction_card("Low", stats['low_orig'], stats['low_cg'],
                                   stats['reduction_low'], "#22c55e")

        return kpi_html

    def _generate_executive_summary_html(self, stats: Dict) -> str:
        """Generate executive summary section."""
        has_kev = len(self.original_results.kev_matches) > 0
        has_epss = any(m[0] >= 0.75 for m in self.original_results.epss_matches)

        badges_html = ""
        if has_kev:
            badges_html += '<span class="badge danger">KEV Present</span>\n'
        if has_epss:
            badges_html += '<span class="badge warning">EPSS ≥ 0.75 Present</span>\n'

        kpi_cards = self._generate_kpi_cards_html(stats)

        return f"""
<section class="kpi-section">
  <div class="kpi-grid">
    {kpi_cards}
  </div>
  {f'<div class="kev-epss">{badges_html}</div>' if badges_html else ''}
</section>

<h2>Executive Summary</h2>

<p>This report presents a comparative analysis between the <strong>Original</strong> and <strong>Chainguard</strong> container images, highlighting substantial improvements in overall <strong>security posture</strong>. The findings are based on a sample set of <strong>{stats['num_images']} images</strong>.</p>

<ul>
  <li><strong>Total Vulnerabilities Eliminated</strong>: <strong>{stats['total_reduction']}</strong></li>
  <li><strong>Critical &amp; High Severity Reduction</strong>: <strong>{stats['reduction_critical']} Critical</strong>, <strong>{stats['reduction_high']} High</strong></li>
  <li><strong>Improved Security Hygiene</strong>: Chainguard images exhibit near-zero residual vulnerabilities across all severity categories.</li>
</ul>

<h3>Key Insights</h3>

<ul>
  <li><strong>Critical CVEs</strong>: {stats['critical_orig']} → {stats['critical_cg']}</li>
  <li><strong>High CVEs</strong>: {stats['high_orig']} → {stats['high_cg']}</li>
  <li><strong>Medium CVEs</strong>: {stats['medium_orig']} → {stats['medium_cg']}</li>
  <li><strong>Low CVEs</strong>: {stats['low_orig']} → {stats['low_cg']}</li>
</ul>

<h3>Vulnerability Reduction Summary</h3>

<table class="vuln-summary-table">
  <thead>
    <tr>
      <th>Severity</th>
      <th>Original</th>
      <th>Chainguard</th>
      <th>Reduction</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Critical</td>
      <td><span class="vuln-count vuln-bad severity-critical">{stats['critical_orig']}</span></td>
      <td><span class="vuln-count vuln-good severity-critical">{stats['critical_cg']}</span></td>
      <td><span class="vuln-reduction">{stats['reduction_critical']}</span></td>
    </tr>
    <tr>
      <td>High</td>
      <td><span class="vuln-count vuln-bad severity-high">{stats['high_orig']}</span></td>
      <td><span class="vuln-count vuln-good severity-high">{stats['high_cg']}</span></td>
      <td><span class="vuln-reduction">{stats['reduction_high']}</span></td>
    </tr>
    <tr>
      <td>Medium</td>
      <td><span class="vuln-count vuln-bad severity-medium">{stats['medium_orig']}</span></td>
      <td><span class="vuln-count vuln-good severity-medium">{stats['medium_cg']}</span></td>
      <td><span class="vuln-reduction">{stats['reduction_medium']}</span></td>
    </tr>
    <tr>
      <td>Low</td>
      <td><span class="vuln-count vuln-bad severity-low">{stats['low_orig']}</span></td>
      <td><span class="vuln-count vuln-good severity-low">{stats['low_cg']}</span></td>
      <td><span class="vuln-reduction">{stats['reduction_low']}</span></td>
    </tr>
    <tr class="total-row">
      <td><strong>Total</strong></td>
      <td><span class="vuln-count vuln-bad total">{stats['total_orig']}</span></td>
      <td><span class="vuln-count vuln-good total">{stats['total_cg']}</span></td>
      <td><span class="vuln-reduction total">{stats['total_reduction']}</span></td>
    </tr>
  </tbody>
</table>
"""

    def _generate_size_reduction_html(self) -> str:
        """Generate size reduction section."""
        orig_sizes = []
        cg_sizes = []

        orig_txt = Path("out.txt")
        if orig_txt.exists():
            with open(orig_txt, "r") as f:
                for line in f:
                    match = re.search(r': ([0-9.]+) MB$', line)
                    if match:
                        orig_sizes.append(float(match.group(1)))

        cg_txt = Path("cgout.txt")
        if cg_txt.exists():
            with open(cg_txt, "r") as f:
                for line in f:
                    match = re.search(r': ([0-9.]+) MB$', line)
                    if match:
                        cg_sizes.append(float(match.group(1)))

        if not orig_sizes or not cg_sizes:
            return ""

        avg_orig = sum(orig_sizes) / len(orig_sizes)
        avg_cg = sum(cg_sizes) / len(cg_sizes)
        percentage_reduction = ((avg_orig - avg_cg) / avg_orig) * 100

        return f"""
<h2>Image Size Reduction</h2>
<p>On average, <strong>Chainguard</strong> images are <strong>{percentage_reduction:.2f}% smaller</strong> per image compared to their <strong>Original</strong> counterparts.</p>
"""

    def _generate_image_size_table_html(self, txt_file: Path, title: str) -> str:
        """Generate image size table."""
        if not txt_file.exists():
            return ""

        rows = []
        with open(txt_file, "r") as f:
            for line in f:
                match = re.match(r'^([^:]+:[^:]+): ([0-9.]+) MB$', line.strip())
                if match:
                    image_name = match.group(1)
                    size = match.group(2)
                    rows.append(f"<tr><td>{image_name}</td><td style='text-align: right;'>{size}</td></tr>")

        if not rows:
            return ""

        return f"""
<h3>Image Size Report</h3>
<p>The following table lists the disk sizes of the analyzed container images to help assess storage efficiency.</p>
<table>
  <thead>
    <tr>
      <th style="text-align: left;">Image Name</th>
      <th style="text-align: right;">Size on Disk (MB)</th>
    </tr>
  </thead>
  <tbody>
    {''.join(rows)}
  </tbody>
</table>
"""

    def _generate_vulnerability_table_html(self, json_file: Path, is_chainguard: bool = False) -> str:
        """Generate detailed vulnerability table with color coding."""
        if not json_file.exists():
            return ""

        with open(json_file, "r") as f:
            data = json.load(f)

        rows = []
        for item in data["items"]:
            image = item["image"].split("@")[0]
            scan = item["scan"]

            # Apply color classes based on image type
            color_class = "vuln-good" if is_chainguard else "vuln-bad"

            rows.append(f"""
<tr>
  <td>{image}</td>
  <td>{scan['type']}</td>
  <td><span class="vuln-count {color_class} severity-critical">{scan['critical']}</span></td>
  <td><span class="vuln-count {color_class} severity-high">{scan['high']}</span></td>
  <td><span class="vuln-count {color_class} severity-medium">{scan['medium']}</span></td>
  <td><span class="vuln-count {color_class} severity-low">{scan['low']}</span></td>
  <td><span class="vuln-count {color_class}">{scan['unknown']}</span></td>
  <td><span class="vuln-count {color_class}">{scan['wontfix']}</span></td>
  <td><span class="vuln-count {color_class} total">{scan['total']}</span></td>
</tr>""")

        return f"""
<h2>Detailed Vulnerability Scan Results</h2>
<p>This table provides a breakdown of vulnerabilities by image, including severity levels and fix availability.</p>
<table>
  <thead>
    <tr>
      <th>Image</th>
      <th>Scan Type</th>
      <th>Critical</th>
      <th>High</th>
      <th>Medium</th>
      <th>Low</th>
      <th>Unknown</th>
      <th>Won't Fix</th>
      <th>Total</th>
    </tr>
  </thead>
  <tbody>
    {''.join(rows)}
  </tbody>
</table>
"""

    def _generate_kev_html(self) -> str:
        """Generate KEV section."""
        kev_matches = self.original_results.kev_matches
        if not kev_matches:
            return ""

        rows = []
        for cve, image in kev_matches:
            rows.append(f"<li><strong>{cve}</strong> — detected in image <code>{image}</code></li>")

        return f"""
<h2>Known Exploited Vulnerabilities (KEV)</h2>
<p>The following vulnerabilities were detected in your container images and are listed in the <strong>CISA Known Exploited Vulnerabilities (KEV)</strong> catalog.
These CVEs are <strong>actively exploited in the wild</strong> and should be prioritized for immediate patching or mitigation.</p>
<h3>Matched CVEs</h3>
<ul>
  {''.join(rows)}
</ul>
"""

    def _generate_epss_html(self) -> str:
        """Generate EPSS section."""
        epss_matches = [m for m in self.original_results.epss_matches if m[0] >= 0.75]
        if not epss_matches:
            return ""

        rows = []
        for score, cve, image, package in epss_matches:
            rows.append(f"""
<tr>
  <td style="text-align: right;">{score:.2f}</td>
  <td>{cve}</td>
  <td><code>{image}</code></td>
  <td>{package}</td>
</tr>""")

        return f"""
<h2>Exploit Prediction Scoring System (EPSS)</h2>
<p>The following CVEs have an <strong>EPSS score of 0.75 or higher</strong>, indicating a high likelihood of exploitation in the wild.
These vulnerabilities should be <strong>prioritized for immediate review and remediation</strong>.</p>
<table>
  <thead>
    <tr>
      <th style="text-align: right;">EPSS Score</th>
      <th>CVE ID</th>
      <th>Image</th>
      <th>Package</th>
    </tr>
  </thead>
  <tbody>
    {''.join(rows)}
  </tbody>
</table>
"""

    def _generate_cg_advisories_html(self) -> str:
        """Generate Chainguard Security Advisories section."""
        advisories = self.chainguard_results.cg_security_advisories
        if not advisories:
            return ""

        rows = []
        for item in advisories:
            cve = item['cve']
            image = item['image'].split('@')[0]  # Remove digest
            advisory = item['advisory']

            # Extract useful information from the advisory
            advisory_id = advisory.get('id', 'N/A')
            package = advisory.get('package', {}).get('name', 'N/A')

            # Get status from events
            status = "Under Investigation"
            fixed_version = "N/A"
            if 'events' in advisory:
                for event in advisory['events']:
                    event_type = event.get('type', '')
                    if event_type == 'fixed':
                        status = "Fixed"
                        fixed_version = event.get('data', 'N/A')
                    elif event_type == 'false-positive-determination':
                        status = "False Positive"
                    elif event_type == 'analysis-not-planned':
                        status = "Analysis Not Planned"
                    elif event_type == 'pending-upstream-fix':
                        status = "Pending Upstream Fix"

            # Status badge color
            status_class = ""
            if status == "Fixed":
                status_class = "status-fixed"
            elif status == "False Positive":
                status_class = "status-false-positive"
            elif status == "Pending Upstream Fix":
                status_class = "status-pending"
            else:
                status_class = "status-investigating"

            rows.append(f"""
<tr>
  <td>{cve}</td>
  <td><code>{image}</code></td>
  <td>{package}</td>
  <td><span class="status-badge {status_class}">{status}</span></td>
  <td>{fixed_version if status == "Fixed" else "—"}</td>
  <td><a href="https://images.chainguard.dev/security/advisories/{advisory_id}" target="_blank" style="color: #a855f7;">View Details</a></td>
</tr>""")

        return f"""
<h2>Chainguard Security Advisory Status</h2>
<p>The following vulnerabilities were found in Chainguard images. This table shows the current status and remediation information from the <strong>Chainguard Security Feed</strong>.</p>
<table>
  <thead>
    <tr>
      <th>CVE ID</th>
      <th>Image</th>
      <th>Package</th>
      <th>Status</th>
      <th>Fixed Version</th>
      <th>Details</th>
    </tr>
  </thead>
  <tbody>
    {''.join(rows)}
  </tbody>
</table>

<style>
.status-badge {{
  padding: 0.35rem 0.75rem;
  border-radius: 0.35rem;
  font-size: 8pt;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  white-space: nowrap;
}}

.status-fixed {{
  background: rgba(34, 197, 94, 0.2);
  color: #6ee7b7;
  border: 1px solid rgba(34, 197, 94, 0.4);
}}

.status-false-positive {{
  background: rgba(168, 85, 247, 0.2);
  color: #c084fc;
  border: 1px solid rgba(168, 85, 247, 0.4);
}}

.status-pending {{
  background: rgba(245, 158, 11, 0.2);
  color: #fcd34d;
  border: 1px solid rgba(245, 158, 11, 0.4);
}}

.status-investigating {{
  background: rgba(59, 130, 246, 0.2);
  color: #93c5fd;
  border: 1px solid rgba(59, 130, 246, 0.4);
}}
</style>
"""

    def _generate_cg_detailed_vulns_html(self) -> str:
        """Generate detailed CVE explanations for Chainguard images with advisory status."""
        detailed_vulns = self.chainguard_results.cg_detailed_vulns
        advisories = self.chainguard_results.cg_security_advisories

        # Only show this section if there are actual CVEs
        if not detailed_vulns or not any(vulns for vulns in detailed_vulns.values()):
            return ""

        # Get current date for status timestamp
        from datetime import datetime
        current_date = datetime.now().strftime("%B %d, %Y")

        # Create a map of CVE -> advisory for quick lookup
        advisory_map = {}
        for adv_item in advisories:
            cve = adv_item.get('cve', '')
            advisory_map[cve] = adv_item.get('advisory', {})

        # Group all vulnerabilities by image
        sections = []
        for image, matches in detailed_vulns.items():
            if not matches:
                continue

            image_short = image.split('@')[0]
            rows = []

            for match in matches:
                vuln = match.get("vulnerability", {})
                cve_id = vuln.get("id", "N/A")
                severity = vuln.get("severity", "Unknown")

                # Get package info
                match_details = match.get("matchDetails", [{}])[0]
                package_info = match_details.get("searchedBy", {}).get("package", {})
                package_name = package_info.get("name", "N/A")
                package_version = package_info.get("version", "N/A")

                # Get data source URL
                data_source = vuln.get("dataSource", "")

                # Severity color class
                severity_class = f"severity-{severity.lower()}" if severity != "Unknown" else ""

                # Get Chainguard security status from feed
                cg_status_html = '<span style="color: #666;">—</span>'

                if self.scanner and (cve_id.startswith('CVE-') or cve_id.startswith('GHSA-')):
                    # Look up vulnerability status in Chainguard security feed
                    status_info = self.scanner._find_cve_status_in_feed(cve_id, package_name, package_version)

                    if status_info['status'] == 'Fixed':
                        fixed_ver = status_info.get('fixed_version', 'Unknown')
                        cg_status_html = f'<span class="status-badge status-fixed">Fixed in {fixed_ver}</span>'
                    elif status_info['status'] == 'Not Found':
                        cg_status_html = f'<span class="status-badge status-investigating">Under Review</span>'
                    else:
                        cg_status_html = '<span style="color: #666;">Unknown</span>'

                rows.append(f"""
<tr>
  <td><strong><a href="{data_source}" target="_blank" style="color: #a855f7; text-decoration: none;">{cve_id}</a></strong></td>
  <td><span class="vuln-count vuln-good {severity_class}">{severity}</span></td>
  <td><code>{package_name}</code></td>
  <td><code>{package_version}</code></td>
  <td>{cg_status_html}</td>
</tr>""")

            if rows:
                sections.append(f"""
<h3 style="margin-top: 2rem;">📦 {image_short}</h3>
<table>
  <thead>
    <tr>
      <th>CVE ID</th>
      <th>Severity</th>
      <th>Package</th>
      <th>Version</th>
      <th>CG Status</th>
    </tr>
  </thead>
  <tbody>
    {''.join(rows)}
  </tbody>
</table>""")

        if not sections:
            return ""

        return f"""
<h2>🔍 Detailed CVE Analysis for Chainguard Images</h2>
<p>The following section provides information about each vulnerability found in the Chainguard images, including <strong>Chainguard's fix status</strong> and affected packages. Status current as of <strong>{current_date}</strong>.</p>
{''.join(sections)}
"""

    def _generate_header_html(self) -> str:
        """Generate report header with optional logo."""
        logo_html = ""
        if self.logo_path and Path(self.logo_path).exists():
            import base64
            with open(self.logo_path, "rb") as f:
                logo_data = base64.b64encode(f.read()).decode()
                ext = Path(self.logo_path).suffix[1:]  # Remove the dot
                logo_html = f'<img src="data:image/{ext};base64,{logo_data}" alt="Company Logo" class="company-logo">'

        return f"""
<div class="report-header">
    {logo_html}
    <h1>🛡️ Image Vulnerability Report</h1>
</div>
"""

    def _generate_footer_html(self) -> str:
        """Generate confidential footer."""
        from datetime import datetime
        current_date = datetime.now().strftime("%B %d, %Y")

        return f"""
<div class="confidential-footer">
    <hr class="footer-divider">
    <div class="footer-content">
        <p class="confidential-notice">
            <strong>⚠️ CONFIDENTIAL</strong>
        </p>
        <p class="footer-text">
            This document contains confidential and proprietary information.
            Distribution or reproduction without prior written authorization is strictly prohibited.
        </p>
        <p class="footer-date">
            Generated on {current_date}
        </p>
    </div>
</div>
"""

    def generate(self) -> bool:
        """Generate the complete vulnerability comparison report as HTML."""
        try:
            # Get vulnerability statistics
            stats = self._get_vulnerability_stats()

            # Generate all sections
            header = self._generate_header_html()
            exec_summary = self._generate_executive_summary_html(stats)
            size_reduction = self._generate_size_reduction_html()
            kev_section = self._generate_kev_html()
            epss_section = self._generate_epss_html()
            cg_advisories_section = self._generate_cg_advisories_html()
            cg_detailed_vulns_section = self._generate_cg_detailed_vulns_html()
            footer = self._generate_footer_html()

            # Generate image analysis sections
            orig_size_table = self._generate_image_size_table_html(Path("out.txt"), "Original Images")
            orig_vuln_table = self._generate_vulnerability_table_html(Path("out.json"), is_chainguard=False)
            cg_size_table = self._generate_image_size_table_html(Path("cgout.txt"), "Chainguard Images")
            cg_vuln_table = self._generate_vulnerability_table_html(Path("cgout.json"), is_chainguard=True)

            # Assemble report body
            report_body = f"""
{header}

{exec_summary}

{size_reduction}

{kev_section}

{epss_section}

{cg_advisories_section}

{cg_detailed_vulns_section}

<hr class="section-divider">

<h2>Original Image Analysis</h2>
{orig_size_table}
{orig_vuln_table}

<h2>Chainguard Image Analysis</h2>
{cg_size_table}
{cg_vuln_table}

{footer}
"""

            # Generate final HTML
            html_output = self._get_html_template(report_body)

            # Save to HTML file
            Path("report.html").write_text(html_output, encoding="utf-8")
            print("✅ Final report saved as 'report.html'")

            return True

        except Exception as e:
            print(f"Error generating report: {str(e)}")
            import traceback
            traceback.print_exc()
            return False


    def _get_html_template(self, body_content: str) -> str:
        """Get the HTML template with light mode styling optimized for PDF."""
        return f"""<!DOCTYPE html>
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

    @page {{
      size: A4;
      margin: 2cm 1.5cm;
    }}

    /* Light mode optimized for PDF */
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Roboto", "Helvetica Neue", Arial, sans-serif;
      background: #ffffff;
      color: #1f2937;
      line-height: 1.6;
      font-size: 10pt;
      min-height: 100vh;
    }}

    main {{
      width: 100%;
      max-width: 1200px;
      margin: 0 auto;
      padding: 2.5rem 2rem;
    }}

    .report-header {{
      text-align: center;
      margin-bottom: 3rem;
      page-break-after: avoid;
    }}

    .company-logo {{
      max-width: 200px;
      max-height: 80px;
      margin: 0 auto 1.5rem;
      display: block;
    }}

    h1 {{
      background: linear-gradient(135deg, #6b21a8 0%, #a855f7 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
      font-size: 2.5rem;
      font-weight: 900;
      margin: 0 0 2rem 0;
      text-align: center;
      letter-spacing: -0.02em;
      page-break-after: avoid;
    }}

    h2 {{
      color: #111827;
      font-size: 1.5rem;
      font-weight: 700;
      margin-top: 3rem;
      margin-bottom: 1.25rem;
      padding-bottom: 0.75rem;
      border-bottom: 3px solid #a855f7;
      page-break-after: avoid;
      letter-spacing: -0.01em;
    }}

    h3 {{
      color: #6b21a8;
      font-size: 1.2rem;
      font-weight: 700;
      margin-top: 2rem;
      margin-bottom: 1rem;
      page-break-after: avoid;
    }}

    p {{
      margin-bottom: 1rem;
      color: #374151;
      line-height: 1.7;
    }}

    table {{
      width: 100%;
      border-collapse: collapse;
      margin: 2rem 0;
      background: #ffffff;
      border: 2px solid #e5e7eb;
      border-radius: 8px;
      overflow: hidden;
      page-break-inside: avoid;
      box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
    }}

    th {{
      background: linear-gradient(135deg, #6b21a8 0%, #7c3aed 100%);
      color: #ffffff;
      padding: 1rem 0.75rem;
      text-align: center;
      font-weight: 700;
      font-size: 9pt;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      border: none;
    }}

    td {{
      padding: 0.85rem 0.75rem;
      text-align: center;
      border-bottom: 1px solid #f3f4f6;
      color: #1f2937;
      font-size: 9pt;
    }}

    tr:hover td {{
      background: #f9fafb;
    }}

    tr:last-child td {{
      border-bottom: none;
    }}

    tr.total-row {{
      background: #f3f4f6;
      font-weight: 700;
    }}

    .kpi-section {{
      margin: 0 -2rem 3rem -2rem;
      padding: 2.5rem 2rem;
      background: linear-gradient(135deg, #faf5ff 0%, #f3e8ff 100%);
      border-top: 3px solid #a855f7;
      border-bottom: 3px solid #a855f7;
      page-break-inside: avoid;
    }}

    .kpi-grid {{
      display: grid;
      grid-template-columns: repeat(5, 1fr);
      gap: 1.25rem;
      margin-bottom: 2rem;
    }}

    .kpi-card {{
      background: #ffffff;
      border-radius: 12px;
      padding: 1.5rem 1.25rem;
      border: 2px solid #e5e7eb;
      display: flex;
      flex-direction: column;
      justify-content: center;
      align-items: center;
      text-align: center;
      min-height: 120px;
      position: relative;
      overflow: hidden;
      transition: all 0.3s ease;
      box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
    }}

    .kpi-card:hover {{
      transform: translateY(-4px);
      border-color: #a855f7;
      box-shadow: 0 8px 24px rgba(168, 85, 247, 0.2);
    }}

    .kpi-accent {{
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 4px;
      background: linear-gradient(90deg, #a855f7 0%, #ec4899 100%);
    }}

    .kpi-card-critical .kpi-accent {{
      background: linear-gradient(90deg, #dc2626 0%, #ef4444 100%);
    }}

    .kpi-card-high .kpi-accent {{
      background: linear-gradient(90deg, #ea580c 0%, #f97316 100%);
    }}

    .kpi-card-medium .kpi-accent {{
      background: linear-gradient(90deg, #ca8a04 0%, #eab308 100%);
    }}

    .kpi-card-low .kpi-accent {{
      background: linear-gradient(90deg, #16a34a 0%, #22c55e 100%);
    }}

    .kpi-label {{
      font-size: 0.7rem;
      color: #6b7280;
      margin-bottom: 0.75rem;
      margin-top: 0.5rem;
      font-weight: 700;
      letter-spacing: 0.5px;
      text-transform: uppercase;
    }}

    .kpi-value {{
      font-size: 2.25rem;
      font-weight: 900;
      color: #111827;
      line-height: 1;
      margin-bottom: 0.5rem;
    }}

    .kpi-delta.good {{
      color: #16a34a;
      font-weight: 700;
      font-size: 0.85rem;
    }}

    .kev-epss {{
      margin-top: 2rem;
      text-align: center;
      display: flex;
      gap: 1.25rem;
      justify-content: center;
      flex-wrap: wrap;
    }}

    .badge {{
      display: inline-flex;
      padding: 0.75rem 1.5rem;
      border-radius: 8px;
      font-size: 0.8rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
    }}

    .badge.danger {{
      background: #fee2e2;
      color: #991b1b;
      border: 2px solid #fca5a5;
    }}

    .badge.warning {{
      background: #fef3c7;
      color: #92400e;
      border: 2px solid #fcd34d;
    }}

    code {{
      background: #f3e8ff;
      padding: 0.3rem 0.6rem;
      border-radius: 6px;
      font-family: "SF Mono", "Monaco", "Menlo", "Courier New", monospace;
      color: #6b21a8;
      font-size: 8.5pt;
      border: 1px solid #e9d5ff;
    }}

    ul {{
      margin-left: 2rem;
      margin-bottom: 1.5rem;
      background: #faf5ff;
      padding: 1.5rem 2rem 1.5rem 2.5rem;
      border-radius: 8px;
      border-left: 4px solid #a855f7;
    }}

    li {{
      margin-bottom: 0.75rem;
      color: #374151;
      line-height: 1.7;
    }}

    li:last-child {{
      margin-bottom: 0;
    }}

    strong {{
      color: #111827;
      font-weight: 700;
    }}

    .section-divider {{
      border: none;
      height: 3px;
      background: linear-gradient(90deg, transparent 0%, #a855f7 50%, transparent 100%);
      margin: 3rem 0;
    }}

    /* Vulnerability count color coding - Light mode */
    .vuln-count {{
      padding: 0.35rem 0.7rem;
      border-radius: 6px;
      font-weight: 700;
      display: inline-block;
      min-width: 2.25rem;
      text-align: center;
    }}

    /* Status badges */
    .status-badge {{
      padding: 0.3rem 0.7rem;
      border-radius: 6px;
      font-weight: 600;
      display: inline-block;
      font-size: 0.85em;
      text-align: center;
    }}

    .status-badge.status-fixed {{
      background: #d1fae5;
      color: #065f46;
      border: 1px solid #6ee7b7;
    }}

    .status-badge.status-investigating {{
      background: #fef3c7;
      color: #92400e;
      border: 1px solid #fcd34d;
    }}

    /* Original images - Light mode (red/orange tones) */
    .vuln-bad.severity-critical {{
      background: #fee2e2;
      color: #991b1b;
      border: 2px solid #fca5a5;
    }}

    .vuln-bad.severity-high {{
      background: #fed7aa;
      color: #9a3412;
      border: 2px solid #fdba74;
    }}

    .vuln-bad.severity-medium {{
      background: #fef3c7;
      color: #92400e;
      border: 2px solid #fcd34d;
    }}

    .vuln-bad.severity-low {{
      background: #fff7ed;
      color: #9a3412;
      border: 2px solid #fed7aa;
    }}

    .vuln-bad.total {{
      background: #fee2e2;
      color: #7f1d1d;
      border: 2px solid #f87171;
      font-size: 1.05em;
      font-weight: 800;
    }}

    /* Chainguard images - Light mode (green tones) */
    .vuln-good.severity-critical,
    .vuln-good.severity-high,
    .vuln-good.severity-medium,
    .vuln-good.severity-low {{
      background: #d1fae5;
      color: #065f46;
      border: 2px solid #6ee7b7;
    }}

    .vuln-good.total {{
      background: #d1fae5;
      color: #064e3b;
      border: 2px solid #34d399;
      font-size: 1.05em;
      font-weight: 800;
    }}

    /* Reduction column */
    .vuln-reduction {{
      padding: 0.35rem 0.7rem;
      border-radius: 6px;
      font-weight: 900;
      display: inline-block;
      min-width: 2.25rem;
      text-align: center;
      background: linear-gradient(135deg, #6ee7b7 0%, #34d399 100%);
      color: #064e3b;
      border: 2px solid #10b981;
    }}

    .vuln-reduction.total {{
      font-size: 1.15em;
    }}

    /* Confidential Footer */
    .confidential-footer {{
      margin-top: 4rem;
      padding-top: 2.5rem;
      page-break-inside: avoid;
    }}

    .footer-divider {{
      border: none;
      height: 3px;
      background: linear-gradient(90deg, transparent 0%, #dc2626 50%, transparent 100%);
      margin: 2.5rem 0 2rem 0;
    }}

    .footer-content {{
      text-align: center;
      padding: 2rem;
      background: #fef2f2;
      border: 2px solid #fca5a5;
      border-radius: 8px;
    }}

    .confidential-notice {{
      color: #991b1b;
      font-size: 1.2rem;
      font-weight: 900;
      text-transform: uppercase;
      letter-spacing: 1px;
      margin-bottom: 1rem;
    }}

    .footer-text {{
      color: #374151;
      font-size: 0.9rem;
      line-height: 1.7;
      margin-bottom: 1rem;
      max-width: 700px;
      margin-left: auto;
      margin-right: auto;
    }}

    .footer-date {{
      color: #6b7280;
      font-size: 0.8rem;
      font-style: italic;
      margin-top: 1.25rem;
      margin-bottom: 0;
    }}
  </style>
</head>
<body>
  <main>
{body_content}
  </main>
</body>
</html>
"""
