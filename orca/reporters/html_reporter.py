"""Self-contained HTML reporter for ORCA."""

from html import escape
from orca.findings import ScanResult, Severity


class HTMLReporter:
    def generate(self, result: ScanResult) -> str:
        target = result.target
        findings = result.findings

        rows = []
        for f in findings:
            sev_color = {
                Severity.CRITICAL: "#dc2626",
                Severity.HIGH: "#ea580c",
                Severity.MEDIUM: "#ca8a04",
                Severity.LOW: "#16a34a",
                Severity.INFO: "#2563eb",
            }.get(f.severity, "#6b7280")
            rows.append(f"""
            <tr>
                <td><span class="badge" style="background:{sev_color}">{f.severity.value.upper()}</span></td>
                <td>{escape(f.check_name)}</td>
                <td>{escape(f.title)}</td>
                <td>{escape(f.description)}</td>
                <td><pre>{escape(f.evidence.request)}</pre><pre>{escape(f.evidence.response_snippet)}</pre></td>
                <td>{escape(f.remediation)}</td>
            </tr>
            """)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ORCA Report - {escape(target.url)}</title>
<style>
body {{ font-family: system-ui, -apple-system, sans-serif; margin: 2rem; background:#0f172a; color:#e2e8f0; }}
h1 {{ color:#38bdf8; }}
table {{ width:100%; border-collapse:collapse; margin-top:1rem; font-size:0.9rem; }}
th, td {{ border:1px solid #334155; padding:0.6rem; text-align:left; vertical-align:top; }}
th {{ background:#1e293b; color:#94a3b8; }}
tr:nth-child(even) {{ background:#1e293b; }}
.badge {{ padding:0.2rem 0.5rem; border-radius:0.25rem; font-size:0.75rem; font-weight:700; color:#fff; }}
pre {{ background:#0f172a; padding:0.5rem; overflow-x:auto; border-radius:0.25rem; font-size:0.8rem; }}
.summary {{ background:#1e293b; padding:1rem; border-radius:0.5rem; margin-bottom:1rem; }}
</style>
</head>
<body>
<h1>ORCA Report</h1>
<div class="summary">
    <strong>Target:</strong> {escape(target.url)}<br>
    <strong>Version:</strong> {escape(target.version or 'Unknown')}<br>
    <strong>Databases:</strong> {escape(', '.join(target.databases) if target.databases else 'None detected')}<br>
    <strong>Modules Detected:</strong> {len(target.detected_modules)}<br>
    <strong>WAF:</strong> {escape(target.waf_detected or 'None detected')}<br>
    <strong>Total Findings:</strong> {len(findings)}
</div>
<table>
<thead>
<tr><th>Severity</th><th>Check</th><th>Title</th><th>Description</th><th>Evidence</th><th>Remediation</th></tr>
</thead>
<tbody>
{''.join(rows)}
</tbody>
</table>
</body>
</html>"""

    def save(self, result: ScanResult, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.generate(result))
