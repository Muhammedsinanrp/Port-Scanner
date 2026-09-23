"""
Export generators for JSON, CSV, and standalone HTML reports.
"""

import csv
import datetime
import html
import json
from pathlib import Path
from typing import Any, Dict


def export_json(scan_data: Dict[str, Any], output_path: str) -> None:
    """Save scan data as structured JSON."""
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(scan_data, f, indent=2, default=str)


def export_csv(scan_data: Dict[str, Any], output_path: str) -> None:
    """Save open ports as spreadsheet-friendly CSV."""
    ports = scan_data.get("ports", [])
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Port", "Protocol", "State", "Service", "Banner", "Latency (ms)"])
        for p in ports:
            writer.writerow([
                p.get("port"),
                p.get("protocol", "tcp"),
                p.get("state", "open"),
                p.get("service", "unknown"),
                p.get("banner", ""),
                p.get("latency_ms", "N/A"),
            ])


def export_html(scan_data: Dict[str, Any], output_path: str) -> None:
    """Generate a sleek, standalone dark-mode HTML security report."""
    target = html.escape(str(scan_data.get("target", "Unknown")))
    target_ip = html.escape(str(scan_data.get("target_ip", target)))
    timestamp = scan_data.get("timestamp", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    scan_engine = html.escape(str(scan_data.get("engine", "Hybrid Async/Nmap")))
    scan_duration = scan_data.get("duration_sec", 0)

    ports = scan_data.get("ports", [])
    open_count = len(ports)
    vulns = scan_data.get("vulnerabilities", [])
    vuln_count = len(vulns)

    crit_count = sum(1 for v in vulns if v.get("severity") == "CRITICAL")
    high_count = sum(1 for v in vulns if v.get("severity") == "HIGH")
    med_count = sum(1 for v in vulns if v.get("severity") == "MEDIUM")

    ssl_info = scan_data.get("ssl_cert")
    http_info = scan_data.get("http_info")
    dns_info = scan_data.get("dns", {})

    # Build Port Rows
    port_rows_html = []
    for p in ports:
        port_num = p.get("port")
        service = html.escape(str(p.get("service", "unknown")))
        banner = html.escape(str(p.get("banner", "None")))
        latency = f"{p.get('latency_ms', '—')} ms" if p.get("latency_ms") is not None else "—"
        
        # Scripts
        scripts = p.get("scripts", {})
        scripts_html = ""
        if scripts:
            scripts_html = "<div class='script-box'>" + "".join(
                f"<div class='script-item'><strong>{html.escape(k)}:</strong> <pre>{html.escape(v)}</pre></div>"
                for k, v in scripts.items()
            ) + "</div>"

        port_rows_html.append(f"""
        <tr>
            <td><span class="badge port-badge">{port_num}</span></td>
            <td><span class="badge state-open">OPEN</span></td>
            <td><strong>{service}</strong></td>
            <td class="banner-cell"><code>{banner}</code>{scripts_html}</td>
            <td>{latency}</td>
        </tr>
        """)

    # Build Vulnerabilities HTML
    vuln_cards_html = []
    for v in vulns:
        sev = v.get("severity", "INFO")
        title = html.escape(str(v.get("title", "")))
        desc = html.escape(str(v.get("description", "")))
        port = v.get("port", "Host")
        evidence = html.escape(str(v.get("evidence", "")))
        cve = html.escape(str(v.get("cve", "")))

        cve_tag = f"<span class='cve-badge'>{cve}</span>" if cve else ""

        vuln_cards_html.append(f"""
        <div class="vuln-card sev-{sev.lower()}">
            <div class="vuln-header">
                <span class="badge sev-badge-{sev.lower()}">{sev}</span>
                <span class="vuln-port">Port {port}</span>
                <h3>{title}</h3>
                {cve_tag}
            </div>
            <p class="vuln-desc">{desc}</p>
            {f'<div class="vuln-evidence"><strong>Evidence:</strong> <code>{evidence}</code></div>' if evidence else ''}
        </div>
        """)

    html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report - {target}</title>
    <style>
        :root {{
            --bg-base: #0a0e17;
            --bg-card: #121826;
            --bg-card-hover: #192236;
            --border: #1e293b;
            --primary: #38bdf8;
            --accent: #6366f1;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --danger: #ef4444;
            --warning: #f59e0b;
            --success: #10b981;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; }}
        body {{ background-color: var(--bg-base); color: var(--text-main); padding: 2rem; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{ display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 2rem; border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; }}
        h1 {{ font-size: 2rem; color: #fff; display: flex; align-items: center; gap: 0.75rem; }}
        .target-sub {{ color: var(--text-muted); font-size: 0.95rem; margin-top: 0.25rem; }}
        .header-meta {{ text-align: right; color: var(--text-muted); font-size: 0.85rem; }}
        .stat-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
        .stat-card {{ background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 1.25rem; text-align: center; }}
        .stat-num {{ font-size: 2.25rem; font-weight: 700; color: var(--primary); }}
        .stat-label {{ color: var(--text-muted); font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; }}
        .stat-danger {{ color: var(--danger); }}
        .stat-warning {{ color: var(--warning); }}
        .stat-success {{ color: var(--success); }}
        
        .section-box {{ background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem; margin-bottom: 2rem; }}
        h2 {{ font-size: 1.3rem; margin-bottom: 1rem; color: var(--primary); display: flex; align-items: center; gap: 0.5rem; }}
        
        table {{ width: 100%; border-collapse: collapse; margin-top: 0.5rem; }}
        th, td {{ padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid var(--border); }}
        th {{ background: #0f172a; color: var(--text-muted); font-size: 0.85rem; text-transform: uppercase; }}
        tr:hover {{ background: var(--bg-card-hover); }}
        code {{ background: #0f172a; padding: 0.2rem 0.4rem; border-radius: 4px; font-family: 'Consolas', monospace; font-size: 0.88rem; color: #38bdf8; word-break: break-all; }}
        
        .badge {{ display: inline-block; padding: 0.25rem 0.6rem; border-radius: 6px; font-size: 0.8rem; font-weight: 600; }}
        .port-badge {{ background: #1e293b; color: #38bdf8; }}
        .state-open {{ background: rgba(16, 185, 129, 0.15); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.3); }}
        .sev-badge-critical {{ background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.4); }}
        .sev-badge-high {{ background: rgba(249, 115, 22, 0.2); color: #f97316; border: 1px solid rgba(249, 115, 22, 0.4); }}
        .sev-badge-medium {{ background: rgba(245, 158, 11, 0.2); color: #f59e0b; border: 1px solid rgba(245, 158, 11, 0.4); }}
        .cve-badge {{ background: #312e81; color: #a5b4fc; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.75rem; margin-left: auto; }}
        
        .vuln-card {{ background: #0f172a; border-left: 4px solid var(--border); border-radius: 8px; padding: 1rem; margin-bottom: 1rem; }}
        .sev-critical {{ border-left-color: var(--danger); }}
        .sev-high {{ border-left-color: #f97316; }}
        .sev-medium {{ border-left-color: var(--warning); }}
        .vuln-header {{ display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.5rem; flex-wrap: wrap; }}
        .vuln-port {{ font-weight: bold; color: var(--primary); font-size: 0.9rem; }}
        .vuln-desc {{ color: #cbd5e1; font-size: 0.9rem; margin-bottom: 0.5rem; }}
        .vuln-evidence {{ font-size: 0.85rem; color: var(--text-muted); background: #090d16; padding: 0.5rem; border-radius: 4px; }}
        
        .recon-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 1rem; }}
        .recon-box {{ background: #0f172a; border: 1px solid var(--border); border-radius: 8px; padding: 1rem; font-size: 0.9rem; }}
        .script-box {{ margin-top: 0.5rem; font-size: 0.8rem; background: #090d16; padding: 0.5rem; border-radius: 4px; }}
        .script-item pre {{ white-space: pre-wrap; font-family: monospace; color: #94a3b8; font-size: 0.75rem; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>🛡️ Network Port & Vulnerability Scan</h1>
                <div class="target-sub">Target: <strong>{target}</strong> ({target_ip})</div>
            </div>
            <div class="header-meta">
                <div>Engine: <strong>{scan_engine}</strong></div>
                <div>Generated: {timestamp}</div>
                <div>Scan Time: {scan_duration:.2f}s</div>
            </div>
        </header>

        <div class="stat-grid">
            <div class="stat-card">
                <div class="stat-num stat-success">{open_count}</div>
                <div class="stat-label">Open Ports</div>
            </div>
            <div class="stat-card">
                <div class="stat-num stat-danger">{crit_count + high_count}</div>
                <div class="stat-label">Critical / High Alerts</div>
            </div>
            <div class="stat-card">
                <div class="stat-num stat-warning">{med_count}</div>
                <div class="stat-label">Medium Risks</div>
            </div>
            <div class="stat-card">
                <div class="stat-num">{scan_duration:.1f}s</div>
                <div class="stat-label">Total Duration</div>
            </div>
        </div>

        <div class="section-box">
            <h2>🔌 Open Ports & Running Services</h2>
            {f"""<table>
                <thead>
                    <tr>
                        <th style="width: 100px;">Port</th>
                        <th style="width: 100px;">State</th>
                        <th style="width: 180px;">Service</th>
                        <th>Service Banner / Fingerprint</th>
                        <th style="width: 100px;">Latency</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(port_rows_html)}
                </tbody>
            </table>""" if port_rows_html else "<p style='color: var(--text-muted);'>No open ports detected in the scanned range.</p>"}
        </div>

        {f"""<div class="section-box">
            <h2>⚠️ Security Findings & Vulnerabilities ({vuln_count})</h2>
            {''.join(vuln_cards_html)}
        </div>""" if vuln_cards_html else ""}

        <div class="section-box">
            <h2>🌐 Reconnaissance & Technology Intelligence</h2>
            <div class="recon-grid">
                <div class="recon-box">
                    <strong>📡 DNS Records:</strong>
                    <ul style="margin-top: 0.5rem; margin-left: 1.2rem; color: #cbd5e1;">
                        <li>IPs: {', '.join(dns_info.get('ip_addresses', [])) or 'None'}</li>
                        <li>Reverse PTR: {dns_info.get('reverse_ptr') or 'None'}</li>
                        <li>MX Records: {len(dns_info.get('mx_records', []))} found</li>
                        <li>NS Records: {len(dns_info.get('ns_records', []))} found</li>
                    </ul>
                </div>
                {f'''<div class="recon-box">
                    <strong>🔒 SSL/TLS Certificate:</strong>
                    <ul style="margin-top: 0.5rem; margin-left: 1.2rem; color: #cbd5e1;">
                        <li>Version: {ssl_info.get('tls_version', 'Unknown')}</li>
                        <li>Cipher: {ssl_info.get('cipher_suite', 'Unknown')}</li>
                        <li>Valid To: {ssl_info.get('not_after', 'Unknown')} ({ssl_info.get('days_until_expiration', '—')} days left)</li>
                    </ul>
                </div>''' if ssl_info else ''}
                {f'''<div class="recon-box">
                    <strong>🌐 Web Application Details:</strong>
                    <ul style="margin-top: 0.5rem; margin-left: 1.2rem; color: #cbd5e1;">
                        <li>Status: {http_info.get('status_code', 'Unknown')}</li>
                        <li>Title: {html.escape(http_info.get('title', 'None'))}</li>
                        <li>Server: {html.escape(http_info.get('server', 'Unknown'))}</li>
                    </ul>
                </div>''' if http_info else ''}
            </div>
        </div>
    </div>
</body>
</html>
"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_template)
