import json
import os
import logging
import datetime
from pathlib import Path
from src.config.settings import OUTPUT_DIR

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Consolidates the massive Case Object JSON, generating a standardized 
    CASE_EXPORT JSON file and an offline-capable HTML forensic dashboard.
    """

    def __init__(self, case_id: str):
        self.case_id = case_id
        self.report_dir = Path(OUTPUT_DIR) / case_id
        os.makedirs(self.report_dir, exist_ok=True)

    def generate_json_report(self, case_data: dict) -> str:
        """Saves the full Case Object as a structured CASE_EXPORT JSON file."""
        timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        json_path = self.report_dir / f"CASE_EXPORT_{timestamp}.json"
        
        # Load the audit log if available
        audit_file = self.report_dir / "audit.log"
        if audit_file.exists():
            with open(audit_file, "r") as f:
                case_data["audit_log"] = [json.loads(line) for line in f if line.strip()]
        else:
            case_data["audit_log"] = []
            
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(case_data, f, indent=2, default=str)
        logger.info("JSON Case Export saved to: %s", json_path)
        return str(json_path)

    def generate_html_report(self, case_data: dict) -> str:
        """Generates a self-contained local HTML forensic dashboard using Case Object schema."""
        html_path = self.report_dir / "forensic_report.html"

        findings = case_data.get("findings", [])
        relationships = case_data.get("relationships", [])
        
        # In the new schema, threats are just findings where we care about risk_score.
        # But wait, run_unified_dashboard currently only pushes ONE massive 'UnifiedDashboard' finding containing all events.
        # We need to flatten the "all_events" from that unified finding if present, or just display findings.
        
        flat_threats = []
        timeline = []
        for f in findings:
            if f.get("source_module") == "UnifiedDashboard" and "raw_data" in f:
                raw = f["raw_data"]
                # Extract from old unified payload
                flat_threats.extend(raw.get("all_events", []))
                timeline.extend(raw.get("all_events", []))
            else:
                flat_threats.append(f)
                timeline.append(f)

        # Compute statistics
        total_events = len(timeline)
        total_threats = sum(1 for t in flat_threats if t.get("risk_score", 0) > 0)
        high_threats = sum(1 for t in flat_threats if t.get("risk_score", 0) >= 70)
        medium_threats = sum(1 for t in flat_threats if 40 <= t.get("risk_score", 0) < 70)
        low_threats = sum(1 for t in flat_threats if 0 < t.get("risk_score", 0) < 40)
        max_risk = max((t.get("risk_score", 0) for t in flat_threats), default=0)
        disk_events = sum(1 for e in timeline if e.get("source_module") == "disk")
        memory_events = sum(1 for e in timeline if e.get("source_module") == "memory")

        gen_timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Build threats table rows
        threats_html = ""
        # Sort threats by risk score descending
        sorted_threats = sorted([t for t in flat_threats if t.get("risk_score", 0) > 0], key=lambda x: x.get("risk_score", 0), reverse=True)
        
        for threat in sorted_threats:
            score = threat.get("risk_score", 0)
            if score >= 70:
                severity_class = "severity-critical"
                severity_label = "CRITICAL"
            elif score >= 40:
                severity_class = "severity-medium"
                severity_label = "MEDIUM"
            else:
                severity_class = "severity-low"
                severity_label = "LOW"

            source = (threat.get("source_module") or "UNKNOWN").upper()
            timestamp = threat.get("timestamp", "N/A")
            description = threat.get("description", "No description")

            # MITRE ATT&CK TTPs
            ttps = threat.get("mitre_attack_ttps", [])
            ttp_html = " ".join(
                f'<span class="ttp-badge">{ttp}</span>' for ttp in ttps
            ) if ttps else '<span style="color:var(--text-muted)">-</span>'

            threats_html += f"""
            <tr>
                <td><span class="risk-badge {severity_class}">{score}</span></td>
                <td><span class="severity-tag {severity_class}">{severity_label}</span></td>
                <td><span class="source-tag source-{source.lower()}">{source}</span></td>
                <td class="mono">{timestamp}</td>
                <td>{description}</td>
                <td>{ttp_html}</td>
            </tr>"""

        if not threats_html:
            threats_html = '<tr><td colspan="6" class="empty-state">No threats detected - system appears clean.</td></tr>'

        # Build relationship (Evidence Graph) rows
        relationships_html = ""
        for rel in relationships:
            relationships_html += f"""
            <tr>
                <td class="mono">{rel.get('source_id', '')}</td>
                <td><span style="color:var(--accent-purple); font-weight:bold;">{rel.get('relationship_type', 'RELATES_TO')}</span></td>
                <td class="mono">{rel.get('target_id', '')}</td>
                <td><span class="severity-tag">Conf: {rel.get('confidence', 'MEDIUM')}</span></td>
            </tr>"""
            
        if not relationships_html:
            relationships_html = '<tr><td colspan="4" class="empty-state">No cross-module relationships established.</td></tr>'

        # Risk distribution bar widths (percentage-based)
        total_for_pct = max(high_threats + medium_threats + low_threats, 1)
        high_pct = (high_threats / total_for_pct) * 100
        medium_pct = (medium_threats / total_for_pct) * 100
        low_pct = (low_threats / total_for_pct) * 100

        # Overall risk level
        if max_risk >= 70:
            overall_risk = "CRITICAL"
            overall_class = "severity-critical"
        elif max_risk >= 40:
            overall_risk = "ELEVATED"
            overall_class = "severity-medium"
        else:
            overall_risk = "LOW"
            overall_class = "severity-low"

        # Build timeline rows
        timeline_html = ""
        for idx, event in enumerate(timeline[:100]):  # Cap at 100 for performance
            source = (event.get("source_module") or "unknown").lower()
            risk = event.get("risk_score", 0)
            risk_class = "severity-critical" if risk >= 70 else ("severity-medium" if risk >= 40 else "severity-low")

            timeline_html += f"""
            <tr>
                <td class="mono">{idx + 1}</td>
                <td class="mono">{event.get('timestamp', 'N/A')}</td>
                <td><span class="source-tag source-{source}">{source.upper()}</span></td>
                <td>{event.get('event_type', 'N/A')}</td>
                <td>{event.get('description', '')}</td>
                <td><span class="risk-badge {risk_class}">{risk}</span></td>
            </tr>"""

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forensic Case Report - {self.case_id}</title>
    <style>
        :root {{
            --bg-primary: #0f1419;
            --bg-secondary: #1a2332;
            --bg-card: #1e2d3d;
            --bg-card-hover: #243447;
            --text-primary: #e6edf3;
            --text-secondary: #8b949e;
            --text-muted: #6e7681;
            --accent-blue: #58a6ff;
            --accent-cyan: #39d0d8;
            --accent-purple: #bc8cff;
            --border: #30363d;
            --critical: #f85149;
            --critical-bg: rgba(248, 81, 73, 0.12);
            --medium: #d29922;
            --medium-bg: rgba(210, 153, 34, 0.12);
            --low: #3fb950;
            --low-bg: rgba(63, 185, 80, 0.12);
            --glass: rgba(30, 45, 61, 0.7);
        }}

        * {{ margin: 0; padding: 0; box-sizing: border-box; }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            min-height: 100vh;
        }}

        .container {{ max-width: 1400px; margin: 0 auto; padding: 24px; }}

        /* Header */
        .header {{
            background: linear-gradient(135deg, #1a2332 0%, #0d1b2a 100%);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 32px;
            margin-bottom: 24px;
            position: relative;
            overflow: hidden;
        }}
        .header::before {{
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0;
            height: 3px;
            background: linear-gradient(90deg, var(--accent-blue), var(--accent-cyan), var(--accent-purple));
        }}
        .header-top {{ display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 16px; }}
        .header h1 {{
            font-size: 1.75rem;
            font-weight: 700;
            background: linear-gradient(135deg, var(--accent-blue), var(--accent-cyan));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 4px;
        }}
        .header .subtitle {{ color: var(--text-secondary); font-size: 0.9rem; }}
        .overall-risk {{
            padding: 12px 24px;
            border-radius: 12px;
            font-weight: 700;
            font-size: 1.1rem;
            text-align: center;
        }}
        .overall-risk.severity-critical {{ background: var(--critical-bg); color: var(--critical); border: 1px solid var(--critical); }}
        .overall-risk.severity-medium {{ background: var(--medium-bg); color: var(--medium); border: 1px solid var(--medium); }}
        .overall-risk.severity-low {{ background: var(--low-bg); color: var(--low); border: 1px solid var(--low); }}

        /* Grid layouts */
        .grid-4 {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }}
        .grid-2 {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 24px; margin-bottom: 24px; }}

        /* Stat cards */
        .stat-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            transition: all 0.2s ease;
        }}
        .stat-card:hover {{ background: var(--bg-card-hover); transform: translateY(-2px); }}
        .stat-card .label {{ color: var(--text-secondary); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px; }}
        .stat-card .value {{ font-size: 2rem; font-weight: 700; color: var(--accent-cyan); }}
        .stat-card .value.critical {{ color: var(--critical); }}
        .stat-card .value.medium {{ color: var(--medium); }}
        .stat-card .value.clean {{ color: var(--low); }}

        /* Section panels */
        .panel {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            margin-bottom: 24px;
            overflow: hidden;
        }}
        .panel-header {{
            padding: 16px 24px;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .panel-header h2 {{
            font-size: 1.1rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .panel-body {{ padding: 24px; }}

        /* Evidence metadata */
        .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; }}
        .meta-item {{ padding: 12px 16px; background: var(--bg-secondary); border-radius: 8px; border: 1px solid var(--border); }}
        .meta-item .meta-label {{ font-size: 0.75rem; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.5px; margin-bottom: 4px; }}
        .meta-item .meta-value {{ font-family: 'SFMono-Regular', Consolas, monospace; font-size: 0.9rem; color: var(--accent-blue); word-break: break-all; }}

        /* Risk distribution bar */
        .risk-bar {{ display: flex; height: 28px; border-radius: 14px; overflow: hidden; background: var(--bg-secondary); margin: 16px 0; }}
        .risk-bar .segment {{ transition: width 0.5s ease; display: flex; align-items: center; justify-content: center; font-size: 0.75rem; font-weight: 600; }}
        .risk-bar .seg-critical {{ background: var(--critical); color: #fff; }}
        .risk-bar .seg-medium {{ background: var(--medium); color: #000; }}
        .risk-bar .seg-low {{ background: var(--low); color: #000; }}
        .risk-legend {{ display: flex; gap: 24px; flex-wrap: wrap; margin-top: 8px; }}
        .risk-legend .legend-item {{ display: flex; align-items: center; gap: 8px; font-size: 0.85rem; color: var(--text-secondary); }}
        .risk-legend .dot {{ width: 10px; height: 10px; border-radius: 50%; }}
        .risk-legend .dot-critical {{ background: var(--critical); }}
        .risk-legend .dot-medium {{ background: var(--medium); }}
        .risk-legend .dot-low {{ background: var(--low); }}

        /* Tables */
        table {{ width: 100%; border-collapse: collapse; }}
        th {{
            text-align: left;
            padding: 12px 16px;
            background: var(--bg-secondary);
            color: var(--text-secondary);
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-weight: 600;
            border-bottom: 1px solid var(--border);
            position: sticky;
            top: 0;
        }}
        td {{
            padding: 12px 16px;
            border-bottom: 1px solid var(--border);
            font-size: 0.875rem;
            vertical-align: top;
        }}
        tr:hover td {{ background: rgba(88, 166, 255, 0.04); }}
        .table-scroll {{ max-height: 500px; overflow-y: auto; }}

        /* Badges and tags */
        .risk-badge {{
            display: inline-block;
            padding: 2px 10px;
            border-radius: 20px;
            font-weight: 700;
            font-size: 0.8rem;
            min-width: 36px;
            text-align: center;
        }}
        .severity-critical {{ background: var(--critical-bg); color: var(--critical); }}
        .severity-medium {{ background: var(--medium-bg); color: var(--medium); }}
        .severity-low {{ background: var(--low-bg); color: var(--low); }}
        .severity-tag {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.7rem;
            font-weight: 700;
            letter-spacing: 0.5px;
        }}
        .source-tag {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.7rem;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .source-disk {{ background: rgba(188, 140, 255, 0.15); color: var(--accent-purple); }}
        .source-memory {{ background: rgba(57, 208, 216, 0.15); color: var(--accent-cyan); }}
        .source-intake {{ background: rgba(88, 166, 255, 0.15); color: var(--accent-blue); }}
        .source-unknown {{ background: rgba(110, 118, 129, 0.15); color: var(--text-muted); }}

        .mono {{ font-family: 'SFMono-Regular', Consolas, monospace; font-size: 0.8rem; }}
        .empty-state {{ text-align: center; padding: 40px; color: var(--text-muted); font-style: italic; }}
        .ttp-badge {{
            display: inline-block;
            padding: 1px 6px;
            border-radius: 4px;
            font-size: 0.7rem;
            font-weight: 600;
            font-family: 'SFMono-Regular', Consolas, monospace;
            background: rgba(88, 166, 255, 0.12);
            color: var(--accent-blue);
            border: 1px solid rgba(88, 166, 255, 0.3);
            margin: 1px;
        }}

        /* Footer */
        .footer {{
            text-align: center;
            padding: 24px;
            color: var(--text-muted);
            font-size: 0.8rem;
            border-top: 1px solid var(--border);
            margin-top: 24px;
        }}

        /* Print styles */
        @media print {{
            body {{ background: #fff; color: #000; }}
            .panel, .stat-card, .header {{ border-color: #ccc; background: #fff; }}
            .header h1 {{ -webkit-text-fill-color: #1a2332; color: #1a2332; }}
            th {{ background: #f0f0f0; color: #333; }}
            td {{ border-color: #ddd; }}
            .risk-badge, .severity-tag, .source-tag {{ border: 1px solid #999; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div class="header-top">
                <div>
                    <h1>Hybrid Forensics Case Export</h1>
                    <p class="subtitle">Case Object Dashboard &bull; Case ID: {self.case_id} &bull; Analyst: {case_data.get('analyst', 'Unknown')} &bull; Status: {case_data.get('case_status', 'N/A')}</p>
                </div>
                <div class="overall-risk {overall_class}">
                    THREAT LEVEL: {overall_risk}
                </div>
            </div>
        </div>

        <!-- Stats -->
        <div class="grid-4">
            <div class="stat-card">
                <div class="label">Total Events</div>
                <div class="value">{total_events}</div>
            </div>
            <div class="stat-card">
                <div class="label">Threats Detected</div>
                <div class="value {'critical' if total_threats > 0 else 'clean'}">{total_threats}</div>
            </div>
            <div class="stat-card">
                <div class="label">Critical / High</div>
                <div class="value critical">{high_threats}</div>
            </div>
            <div class="stat-card">
                <div class="label">Max Risk Score</div>
                <div class="value {'critical' if max_risk >= 70 else ('medium' if max_risk >= 40 else 'clean')}">{max_risk}/100</div>
            </div>
        </div>

        <!-- Risk Distribution -->
        <div class="panel">
            <div class="panel-header">
                <h2>Risk Distribution</h2>
                <span class="mono" style="color:var(--text-muted)">{total_threats} threat(s)</span>
            </div>
            <div class="panel-body">
                <div class="risk-bar">
                    {"<div class='segment seg-critical' style='width:" + f"{high_pct:.0f}" + "%'>" + str(high_threats) + "</div>" if high_threats > 0 else ""}
                    {"<div class='segment seg-medium' style='width:" + f"{medium_pct:.0f}" + "%'>" + str(medium_threats) + "</div>" if medium_threats > 0 else ""}
                    {"<div class='segment seg-low' style='width:" + f"{low_pct:.0f}" + "%'>" + str(low_threats) + "</div>" if low_threats > 0 else ""}
                </div>
                <div class="risk-legend">
                    <div class="legend-item"><div class="dot dot-critical"></div>Critical (70-100): {high_threats}</div>
                    <div class="legend-item"><div class="dot dot-medium"></div>Medium (40-69): {medium_threats}</div>
                    <div class="legend-item"><div class="dot dot-low"></div>Low (0-39): {low_threats}</div>
                </div>

                <div style="display:flex; gap:24px; margin-top:24px; flex-wrap:wrap;">
                    <div class="stat-card" style="flex:1; min-width:180px;">
                        <div class="label">Disk Events</div>
                        <div class="value" style="font-size:1.5rem; color:var(--accent-purple);">{disk_events}</div>
                    </div>
                    <div class="stat-card" style="flex:1; min-width:180px;">
                        <div class="label">Memory Events</div>
                        <div class="value" style="font-size:1.5rem; color:var(--accent-cyan);">{memory_events}</div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Evidence Graph -->
        <div class="panel">
            <div class="panel-header">
                <h2>Evidence Graph (Cross-Module Relationships)</h2>
            </div>
            <div class="table-scroll">
                <table>
                    <thead>
                        <tr>
                            <th style="width:200px">Source FND ID</th>
                            <th style="width:150px">Relationship</th>
                            <th style="width:200px">Target FND ID</th>
                            <th>Confidence</th>
                        </tr>
                    </thead>
                    <tbody>
                        {relationships_html}
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Threats Table -->
        <div class="panel">
            <div class="panel-header">
                <h2>Detected Threats &amp; Anomalies</h2>
            </div>
            <div class="table-scroll">
                <table>
                    <thead>
                        <tr>
                            <th style="width:80px">Risk</th>
                            <th style="width:100px">Severity</th>
                            <th style="width:90px">Source</th>
                            <th style="width:200px">Timestamp</th>
                            <th>Description</th>
                            <th style="width:120px">MITRE ATT&CK</th>
                        </tr>
                    </thead>
                    <tbody>
                        {threats_html}
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Timeline Table -->
        <div class="panel">
            <div class="panel-header">
                <h2>Unified Forensic Timeline</h2>
                <span class="mono" style="color:var(--text-muted)">{total_events} event(s){' - showing first 100' if total_events > 100 else ''}</span>
            </div>
            <div class="table-scroll">
                <table>
                    <thead>
                        <tr>
                            <th style="width:50px">#</th>
                            <th style="width:200px">Timestamp</th>
                            <th style="width:90px">Source</th>
                            <th style="width:160px">Event Type</th>
                            <th>Description</th>
                            <th style="width:70px">Risk</th>
                        </tr>
                    </thead>
                    <tbody>
                        {timeline_html if timeline_html else '<tr><td colspan="6" class="empty-state">No timeline events recorded.</td></tr>'}
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Footer -->
        <div class="footer">
            Hybrid Memory &amp; Disk Forensics Framework &bull; Air-Gapped Case Export<br>
            Generated: {gen_timestamp} &bull; Case ID: {self.case_id}<br>
            <em>This dashboard parses the strictly formatted CASE_EXPORT JSON offline.</em>
        </div>
    </div>
</body>
</html>"""

        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        logger.info("HTML Case Dashboard saved to: %s", html_path)
        return str(html_path)
