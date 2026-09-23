"""
Cyberpunk Flask Web Dashboard for Network Port & Vulnerability Scanner.
"""

import os
import threading
import time
import uuid
from typing import Any, Dict
from flask import Flask, jsonify, render_template, request, send_file
from flask_cors import CORS

from core.async_engine import AsyncScanner, parse_port_range
from core.config import find_nmap_executable
from core.exporter import export_csv, export_html, export_json
from core.nmap_engine import NmapEngine
from core.recon import get_dns_records, inspect_http_service, inspect_ssl_cert, ping_host
from core.vuln_checker import analyze_vulnerabilities

app = Flask(__name__)
CORS(app)

# In-memory storage for scans
SCANS: Dict[str, Dict[str, Any]] = {}


@app.route("/")
def index():
    nmap_path = find_nmap_executable()
    return render_template("index.html", nmap_available=bool(nmap_path), nmap_path=nmap_path or "")


@app.route("/api/status")
def api_status():
    nmap_path = find_nmap_executable()
    return jsonify({
        "status": "online",
        "nmap_available": bool(nmap_path),
        "nmap_path": nmap_path,
    })


def run_background_scan(scan_id: str, target: str, port_spec: str, mode: str, concurrency: int, timeout: float):
    scan_entry = SCANS[scan_id]
    scan_entry["status"] = "running"
    scan_entry["progress"] = 5
    scan_entry["logs"].append(f"Starting scan on target {target} (mode: {mode})...")

    start_time = time.perf_counter()

    try:
        # 1. Ping
        ping_info = ping_host(target)
        scan_entry["ping"] = ping_info
        if ping_info["alive"]:
            scan_entry["logs"].append(f"Target host is responsive (latency: {ping_info.get('rtt_ms')} ms).")
        else:
            scan_entry["logs"].append("Target ICMP ping timed out. Continuing with port probes...")

        # 2. DNS
        dns_info = get_dns_records(target)
        scan_entry["dns"] = dns_info
        if dns_info.get("ip_addresses"):
            scan_entry["target_ip"] = dns_info["ip_addresses"][0]
            scan_entry["logs"].append(f"Resolved to {scan_entry['target_ip']}")

        scan_entry["progress"] = 15

        # 3. Ports Scan
        ports = parse_port_range(port_spec)
        scan_entry["total_ports"] = len(ports)
        open_ports = []
        nmap_engine = NmapEngine()

        if mode in ("nmap", "vuln") and nmap_engine.is_available():
            scan_entry["logs"].append(f"Running deep Nmap scan with profile '{mode}'...")
            nmap_res = nmap_engine.run_scan(
                target=target,
                ports=port_spec,
                profile="vuln" if mode == "vuln" else "service",
                timeout_sec=180
            )
            if nmap_res.get("hosts"):
                open_ports = nmap_res["hosts"][0].get("ports", [])
            scan_entry["progress"] = 80
        else:
            scan_entry["logs"].append(f"Launching Native Async Engine across {len(ports)} ports...")
            import asyncio

            def on_progress(completed: int, total: int, port_data: Any):
                # Update progress between 15% and 80%
                pct = 15 + int((completed / max(1, total)) * 65)
                scan_entry["progress"] = min(80, pct)
                scan_entry["scanned_count"] = completed
                if port_data:
                    open_ports.append(port_data)
                    scan_entry["open_ports"] = list(open_ports)
                    scan_entry["logs"].append(f"Discovered Port {port_data['port']}: {port_data['service']}")

            scanner = AsyncScanner(
                target=target,
                ports=ports,
                timeout=timeout,
                concurrency=concurrency,
                progress_callback=on_progress,
            )
            # Run scanner in fresh event loop
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            open_ports = loop.run_until_complete(scanner.run_scan())
            loop.close()

            # If hybrid 'all' mode
            if mode == "all" and open_ports and nmap_engine.is_available():
                scan_entry["logs"].append("Enriching open ports with Nmap scripts & service detection...")
                ports_arg = ",".join(str(p["port"]) for p in open_ports)
                try:
                    nmap_res = nmap_engine.run_scan(target=target, ports=ports_arg, profile="vuln", timeout_sec=120)
                    if nmap_res.get("hosts"):
                        nmap_ports = nmap_res["hosts"][0].get("ports", [])
                        n_map = {p["port"]: p for p in nmap_ports}
                        for p in open_ports:
                            if p["port"] in n_map:
                                if n_map[p["port"]].get("banner"):
                                    p["banner"] = n_map[p["port"]]["banner"]
                                if n_map[p["port"]].get("scripts"):
                                    p["scripts"] = n_map[p["port"]]["scripts"]
                except Exception as e:
                    scan_entry["logs"].append(f"Nmap enrichment notice: {e}")

        scan_entry["open_ports"] = open_ports
        scan_entry["progress"] = 85

        # 4. Reconnaissance (SSL & HTTP)
        open_set = {p["port"] for p in open_ports}
        for p in [443, 8443]:
            if p in open_set:
                scan_entry["logs"].append(f"Inspecting SSL certificate on port {p}...")
                scan_entry["ssl_cert"] = inspect_ssl_cert(target, port=p)
                break

        for p in [80, 443, 8080, 8000, 8443]:
            if p in open_set:
                scan_entry["logs"].append(f"Fingerprinting HTTP application on port {p}...")
                scan_entry["http_info"] = inspect_http_service(target, port=p, use_ssl=(p in (443, 8443)))
                break

        scan_entry["progress"] = 95

        # 5. Vulnerability Heuristics
        scan_entry["logs"].append("Analyzing port banners for vulnerabilities and misconfigurations...")
        vulns = analyze_vulnerabilities(open_ports)
        scan_entry["vulnerabilities"] = vulns

        duration = time.perf_counter() - start_time
        scan_entry["duration_sec"] = round(duration, 2)
        scan_entry["progress"] = 100
        scan_entry["status"] = "completed"
        scan_entry["logs"].append(f"Scan complete in {scan_entry['duration_sec']}s. Found {len(open_ports)} open ports and {len(vulns)} alerts.")

    except Exception as e:
        scan_entry["status"] = "error"
        scan_entry["error"] = str(e)
        scan_entry["logs"].append(f"Error during scan: {e}")


@app.route("/api/scan", methods=["POST"])
def start_scan():
    data = request.get_json(silent=True) or request.form.to_dict() or {}
    target = data.get("target", "").strip()
    if not target:
        return jsonify({"error": "Target IP or hostname is required"}), 400

    port_spec = data.get("ports", "top-100")
    mode = data.get("mode", "fast")
    concurrency = int(data.get("concurrency", 400))
    timeout = float(data.get("timeout", 1.0))

    scan_id = str(uuid.uuid4())[:8]
    SCANS[scan_id] = {
        "id": scan_id,
        "target": target,
        "target_ip": target,
        "ports_spec": port_spec,
        "mode": mode,
        "status": "pending",
        "progress": 0,
        "total_ports": 0,
        "scanned_count": 0,
        "open_ports": [],
        "vulnerabilities": [],
        "logs": [],
        "dns": {},
        "ssl_cert": None,
        "http_info": None,
        "ping": {},
        "duration_sec": 0,
    }

    thread = threading.Thread(
        target=run_background_scan,
        args=(scan_id, target, port_spec, mode, concurrency, timeout),
        daemon=True,
    )
    thread.start()

    return jsonify({"scan_id": scan_id, "status": "started"})


@app.route("/api/scan/<scan_id>")
def get_scan(scan_id):
    scan = SCANS.get(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(scan)


@app.route("/api/export/<scan_id>/<fmt>")
def export_scan(scan_id, fmt):
    scan = SCANS.get(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    target_name = "".join(c if c.isalnum() else "_" for c in scan["target"])
    os.makedirs("exports", exist_ok=True)

    scan_payload = {
        "target": scan["target"],
        "target_ip": scan.get("target_ip", scan["target"]),
        "engine": scan["mode"].upper(),
        "duration_sec": scan.get("duration_sec", 0),
        "ports": scan.get("open_ports", []),
        "vulnerabilities": scan.get("vulnerabilities", []),
        "dns": scan.get("dns", {}),
        "ssl_cert": scan.get("ssl_cert"),
        "http_info": scan.get("http_info"),
    }

    if fmt == "json":
        file_path = f"exports/scan_{target_name}_{scan_id}.json"
        export_json(scan_payload, file_path)
        return send_file(file_path, as_attachment=True, download_name=f"scan_{target_name}.json")
    elif fmt == "csv":
        file_path = f"exports/scan_{target_name}_{scan_id}.csv"
        export_csv(scan_payload, file_path)
        return send_file(file_path, as_attachment=True, download_name=f"scan_{target_name}.csv")
    elif fmt == "html":
        file_path = f"exports/scan_{target_name}_{scan_id}.html"
        export_html(scan_payload, file_path)
        return send_file(file_path, as_attachment=True, download_name=f"scan_{target_name}.html")
    else:
        return jsonify({"error": "Unsupported format"}), 400


if __name__ == "__main__":
    print(f"Starting Network Security Web Dashboard on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
