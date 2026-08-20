import json
import os
from pathlib import Path
from src.config.settings import OUTPUT_DIR

class ReportGenerator:
    """
    Consolidates metadata, extracted artifacts, timeline, and threat scores 
    into JSON and local HTML report formats.
    """
    def __init__(self, case_id: str):
        self.case_id = case_id
        self.report_dir = Path(OUTPUT_DIR) / case_id
        os.makedirs(self.report_dir, exist_ok=True)

    def generate_json_report(self, report_data: dict) -> str:
        """Saves full analysis output as a structured JSON file."""
        json_path = self.report_dir / "forensic_report.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)
        print(f"[+] JSON Report saved to: {json_path}")
        return str(json_path)

    def generate_html_report(self, report_data: dict) -> str:
        """Generates a self-contained local HTML dashboard for browser viewing."""
        html_path = self.report_dir / "forensic_report.html"
        
        threats_html = ""
        for threat in report_data.get("threats", []):
            color = "#ff4d4d" if threat["risk_score"] >= 70 else "#ffa500"
            threats_html += f"""
            <tr style="background-color: {color}15;">
                <td><strong>{threat.get('risk_score')}</strong></td>
                <td>{threat.get('source_module').upper()}</td>
                <td>{threat.get('timestamp')}</td>
                <td>{threat.get('description')}</td>
            </tr>
            """

        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Forensic Report - {self.case_id}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f4f6f9; color: #333; }}
        h1, h2 {{ color: #1a252f; }}
        .card {{ background: #fff; padding: 15px; margin-bottom: 20px; border-radius: 5px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #2c3e50; color: white; }}
    </style>
</head>
<body>
    <h1>Hybrid Forensics Framework Report</h1>
    <div class="card">
        <h2>Case Overview</h2>
        <p><strong>Case ID:</strong> {self.case_id}</p>
        <p><strong>Intake ID:</strong> {report_data.get('evidence_metadata', {}).get('evidence_id', 'N/A')}</p>
        <p><strong>Timestamp (UTC):</strong> {report_data.get('evidence_metadata', {}).get('intake_timestamp_utc', 'N/A')}</p>
    </div>

    <div class="card">
        <h2>Detected Threats & Anomalies</h2>
        <table>
            <tr>
                <th>Risk Score</th>
                <th>Source</th>
                <th>Timestamp</th>
                <th>Description</th>
            </tr>
            {threats_html if threats_html else "<tr><td colspan='4'>No high-risk threats identified.</td></tr>"}
        </table>
    </div>
</body>
</html>
"""
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"[+] HTML Report saved to: {html_path}")
        return str(html_path)