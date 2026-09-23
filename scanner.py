#!/usr/bin/env python3
"""
Advanced Network Port & Vulnerability Scanner
Inspired by Muhammedsinanrp/Port-Scanner, supercharged with Nmap,
Asyncio multi-threading, Deep Reconnaissance, and Heuristic Vulnerability Detection.
"""

import argparse
import asyncio
import datetime
import os
import sys
import time
from typing import Any, Dict, List

# Core modules
from core.async_engine import AsyncScanner, parse_port_range
from core.config import find_nmap_executable
from core.exporter import export_csv, export_html, export_json
from core.nmap_engine import NmapEngine
from core.recon import get_dns_records, inspect_http_service, inspect_ssl_cert, ping_host
from core.vuln_checker import analyze_vulnerabilities

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Rich CLI formatting
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
    from rich.table import Table
    from rich.text import Text
    console = Console(legacy_windows=False)
    HAS_RICH = True
except Exception:
    HAS_RICH = False
    console = None


BANNER_TEXT = """
 [bold cyan]+-----------------------------------------------------------------+[/bold cyan]
 [bold cyan]|[/bold cyan]   [bold white]POWERFUL NETWORK PORT & VULNERABILITY SCANNER[/bold white]                 [bold cyan]|[/bold cyan]
 [bold cyan]|[/bold cyan]   [dim]Enhanced Multi-Engine Port Scanner | Nmap Integration | Recon[/dim]   [bold cyan]|[/bold cyan]
 [bold cyan]+-----------------------------------------------------------------+[/bold cyan]
"""


def print_banner():
    if HAS_RICH:
        console.print(BANNER_TEXT)
    else:
        print("=" * 65)
        print("  POWERFUL NETWORK PORT & VULNERABILITY SCANNER")
        print("  Enhanced Multi-Engine Port Scanner | Nmap Integration | Recon")
        print("=" * 65)


def print_status(msg: str, status: str = "info"):
    colors = {"info": "cyan", "success": "green", "warning": "yellow", "error": "red"}
    color = colors.get(status, "white")
    if HAS_RICH:
        console.print(f"[{color}][*][/{color}] {msg}")
    else:
        print(f"[*] {msg}")


def interactive_wizard() -> Dict[str, Any]:
    """Interactive wizard for users running without arguments."""
    print_banner()
    if HAS_RICH:
        console.print("[bold yellow]Interactive Mode Activated[/bold yellow]\n")

    target = input("Enter target IP or Domain [e.g. 127.0.0.1 or scanme.nmap.org]: ").strip()
    while not target:
        target = input("Target cannot be empty. Enter target: ").strip()

    print("\nPort Range Options:")
    print("  1) Common Ports (Top 100)")
    print("  2) Standard 1-1024 (Original Default)")
    print("  3) Full 1-65535 (Complete Scan)")
    print("  4) Custom (e.g. 80,443,8080 or 1-500)")
    port_choice = input("Select option [1-4, default: 2]: ").strip() or "2"

    if port_choice == "1":
        port_spec = "top-100"
    elif port_choice == "3":
        port_spec = "1-65535"
    elif port_choice == "4":
        port_spec = input("Enter custom port range: ").strip() or "1-1024"
    else:
        port_spec = "1-1024"

    nmap_path = find_nmap_executable()
    nmap_status = f"[green]Detected ({nmap_path})[/green]" if (HAS_RICH and nmap_path) else ("Detected" if nmap_path else "Not found")

    print(f"\nScanning Engine (Nmap Status: {nmap_status}):")
    print("  1) Ultra-Fast Async Engine (Native Python, 400+ workers)")
    if nmap_path:
        print("  2) Nmap Service & Version Detection (-sV)")
        print("  3) Nmap NSE Vulnerability Scan (--script vuln)")
        print("  4) Hybrid Full Recon (Async + Nmap + SSL + Web + Vuln)")
    else:
        print("  2) Native Async + Deep Banner & Vulnerability Heuristics")

    mode_choice = input("Select engine mode [1-4, default: 1]: ").strip() or "1"
    mode_map = {"1": "fast", "2": "nmap" if nmap_path else "fast", "3": "vuln", "4": "all"}
    mode = mode_map.get(mode_choice, "fast")

    save_report = input("\nSave scan report? (html/json/csv/n) [default: html]: ").strip().lower() or "html"
    output_file = None
    if save_report in ("html", "json", "csv"):
        safe_target = "".join(c if c.isalnum() else "_" for c in target)
        output_file = f"scan_report_{safe_target}.{save_report}"

    return {
        "target": target,
        "ports": port_spec,
        "mode": mode,
        "concurrency": 400,
        "timeout": 1.0,
        "output": output_file,
        "no_dns": False,
        "no_recon": False,
    }


def execute_scan(config: Dict[str, Any]) -> Dict[str, Any]:
    """Coordinate multi-engine scanning and reconnaissance."""
    target = config["target"]
    port_spec = config["ports"]
    mode = config["mode"]
    concurrency = config.get("concurrency", 400)
    timeout = config.get("timeout", 1.0)
    output_path = config.get("output")
    start_time = time.perf_counter()

    scan_data: Dict[str, Any] = {
        "target": target,
        "target_ip": target,
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "engine": mode.upper(),
        "ports": [],
        "vulnerabilities": [],
        "dns": {},
        "ssl_cert": None,
        "http_info": None,
        "duration_sec": 0.0,
    }

    print_status(f"Initiating target reconnaissance for [bold]{target}[/bold]...", "info")

    # 1. Host Ping & Reachability
    ping_info = ping_host(target)
    if ping_info["alive"]:
        rtt_str = f"{ping_info['rtt_ms']} ms" if ping_info['rtt_ms'] else "OK"
        print_status(f"Host is UP (Latency: {rtt_str})", "success")
    else:
        print_status("Host ping did not respond (may block ICMP). Proceeding with port scan...", "warning")

    # 2. DNS Reconnaissance
    if not config.get("no_dns", False):
        dns_res = get_dns_records(target)
        scan_data["dns"] = dns_res
        if dns_res.get("ip_addresses"):
            scan_data["target_ip"] = dns_res["ip_addresses"][0]
            print_status(f"Target resolved to IPv4: {scan_data['target_ip']}", "info")
            if dns_res.get("reverse_ptr"):
                print_status(f"Reverse DNS (PTR): {dns_res['reverse_ptr']}", "info")

    # 3. Port Scanning Phase
    port_list = parse_port_range(port_spec)
    print_status(f"Scanning [bold]{len(port_list)}[/bold] ports with mode=[bold]{mode.upper()}[/bold]...", "info")

    open_ports: List[Dict[str, Any]] = []
    nmap_engine = NmapEngine()

    if mode in ("nmap", "vuln") and nmap_engine.is_available():
        profile = "vuln" if mode == "vuln" else "service"
        print_status(f"Executing deep Nmap scan (profile: {profile}). This may take a moment...", "info")
        try:
            nmap_res = nmap_engine.run_scan(target=target, ports=port_spec, profile=profile, timeout_sec=180)
            if nmap_res.get("hosts"):
                host_data = nmap_res["hosts"][0]
                open_ports = host_data.get("ports", [])
            print_status(f"Nmap scan finished. Found {len(open_ports)} open ports.", "success")
        except Exception as e:
            print_status(f"Nmap scan failed: {e}. Falling back to Native Async Engine...", "warning")
            mode = "fast"

    if mode in ("fast", "all") or not open_ports:
        # Native High-Speed Async Engine
        if HAS_RICH:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                MofNCompleteColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                console=console,
            ) as progress:
                scan_task = progress.add_task("[cyan]Scanning ports...", total=len(port_list))

                def on_progress(completed: int, total: int, port_data: Any):
                    progress.update(scan_task, completed=completed)
                    if port_data:
                        progress.console.print(
                            f"  [green][+][/green] Port [bold cyan]{port_data['port']}[/bold cyan] is open | "
                            f"Service: [bold white]{port_data['service']}[/bold white] | "
                            f"[dim]{port_data.get('banner', '')[:60]}[/dim]"
                        )

                scanner = AsyncScanner(
                    target=target,
                    ports=port_list,
                    timeout=timeout,
                    concurrency=concurrency,
                    progress_callback=on_progress,
                )
                open_ports = asyncio.run(scanner.run_scan())
        else:
            def on_progress(completed: int, total: int, port_data: Any):
                if port_data:
                    print(f"  [+] Port {port_data['port']} is open | Service: {port_data['service']} | {port_data.get('banner', '')[:60]}")

            scanner = AsyncScanner(
                target=target,
                ports=port_list,
                timeout=timeout,
                concurrency=concurrency,
                progress_callback=on_progress,
            )
            open_ports = asyncio.run(scanner.run_scan())

        # If 'all' mode and Nmap is available, run Nmap deep version & script scan ONLY on discovered open ports
        if mode == "all" and open_ports and nmap_engine.is_available():
            discovered_ports_str = ",".join(str(p["port"]) for p in open_ports)
            print_status(f"Running Nmap deep version & script scan on discovered ports ({discovered_ports_str})...", "info")
            try:
                nmap_res = nmap_engine.run_scan(target=target, ports=discovered_ports_str, profile="vuln", timeout_sec=120)
                if nmap_res.get("hosts"):
                    nmap_ports = nmap_res["hosts"][0].get("ports", [])
                    # Merge nmap info with async ports
                    nmap_dict = {p["port"]: p for p in nmap_ports}
                    for p in open_ports:
                        if p["port"] in nmap_dict:
                            np = nmap_dict[p["port"]]
                            if np.get("banner"):
                                p["banner"] = np["banner"]
                            if np.get("scripts"):
                                p["scripts"] = np["scripts"]
            except Exception as e:
                print_status(f"Deep Nmap enrichment skipped: {e}", "warning")

    scan_data["ports"] = open_ports

    # 4. Deep Recon on Open Web / SSL Ports
    if not config.get("no_recon", False):
        open_port_nums = {p["port"] for p in open_ports}
        # SSL Check on 443 or 8443
        for ssl_p in [443, 8443]:
            if ssl_p in open_port_nums:
                print_status(f"Inspecting SSL/TLS certificate on port {ssl_p}...", "info")
                cert_info = inspect_ssl_cert(target, port=ssl_p)
                if cert_info:
                    scan_data["ssl_cert"] = cert_info
                break

        # HTTP tech inspection on 80, 8080, 443, 8000
        for web_p in [80, 443, 8080, 8000, 8443]:
            if web_p in open_port_nums:
                print_status(f"Fingerprinting Web Application on port {web_p}...", "info")
                http_res = inspect_http_service(target, port=web_p, use_ssl=(web_p in (443, 8443)))
                if http_res:
                    scan_data["http_info"] = http_res
                break

    # 5. Vulnerability & Exposure Analysis
    print_status("Evaluating security exposure and known vulnerabilities...", "info")
    vulns = analyze_vulnerabilities(open_ports)
    scan_data["vulnerabilities"] = vulns

    scan_duration = time.perf_counter() - start_time
    scan_data["duration_sec"] = scan_duration

    # 6. Display Formatted Output
    display_results(scan_data)

    # 7. Exporting
    if output_path:
        out_lower = output_path.lower()
        if out_lower.endswith(".html"):
            export_html(scan_data, output_path)
            print_status(f"Interactive HTML Report generated: [bold green]{output_path}[/bold green]", "success")
        elif out_lower.endswith(".json"):
            export_json(scan_data, output_path)
            print_status(f"Structured JSON Export saved: [bold green]{output_path}[/bold green]", "success")
        elif out_lower.endswith(".csv"):
            export_csv(scan_data, output_path)
            print_status(f"CSV Spreadsheet saved: [bold green]{output_path}[/bold green]", "success")

    return scan_data


def display_results(scan_data: Dict[str, Any]):
    """Render terminal report with Rich."""
    target = scan_data["target"]
    ports = scan_data.get("ports", [])
    vulns = scan_data.get("vulnerabilities", [])
    duration = scan_data.get("duration_sec", 0.0)

    if HAS_RICH:
        # Ports Table
        table = Table(title=f"Scan Summary for {target} ({len(ports)} open ports in {duration:.2f}s)", show_header=True, header_style="bold cyan")
        table.add_column("Port", style="bold green", width=10)
        table.add_column("State", width=8)
        table.add_column("Service", style="bold white", width=16)
        table.add_column("Banner / Details", style="dim", min_width=30)
        table.add_column("Latency", justify="right", width=12)

        for p in ports:
            p_num = str(p.get("port"))
            p_state = p.get("state", "open").upper()
            p_svc = p.get("service", "unknown")
            p_banner = p.get("banner", "None") or "None"
            latency = f"{p.get('latency_ms', '—')} ms" if p.get("latency_ms") is not None else "—"

            # Add NSE script summary if present
            scripts = p.get("scripts", {})
            if scripts:
                script_summary = " | NSE: " + ", ".join(scripts.keys())
                p_banner += script_summary

            table.add_row(p_num, p_state, p_svc, p_banner[:70], latency)

        console.print("\n")
        console.print(table)

        # Vulnerabilities Panel
        if vulns:
            console.print("\n")
            vuln_table = Table(title=f"[!] Security Findings ({len(vulns)})", show_header=True, header_style="bold red")
            vuln_table.add_column("Sev", width=10)
            vuln_table.add_column("Port", width=8)
            vuln_table.add_column("Title & Description")

            for v in vulns:
                sev = v.get("severity", "INFO")
                sev_color = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "blue"}.get(sev, "white")
                vuln_table.add_row(
                    f"[{sev_color}]{sev}[/{sev_color}]",
                    str(v.get("port", "Host")),
                    f"[bold]{v.get('title')}[/bold]\n[dim]{v.get('description')}[/dim]"
                )
            console.print(vuln_table)
    else:
        print("\n" + "=" * 50)
        print(f"Scan Summary for {target} ({len(ports)} open ports in {duration:.2f}s)")
        print("=" * 50)
        for p in ports:
            print(f"Port {p.get('port')}/tcp: {p.get('service')} | {p.get('banner', 'No banner')}")
        if vulns:
            print("\nSecurity Findings:")
            for v in vulns:
                print(f"[{v.get('severity')}] Port {v.get('port')}: {v.get('title')}")


def main():
    parser = argparse.ArgumentParser(
        description="Powerful Multi-Engine Network Port & Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-t", "--target", help="Target IP address or domain name")
    parser.add_argument(
        "-p", "--ports", default="1-1024",
        help="Port specification: 'top-100', '1-1024', '1-65535', or comma-separated list '80,443,8080'"
    )
    parser.add_argument(
        "-m", "--mode", choices=["fast", "nmap", "vuln", "all"], default="fast",
        help="Scan mode: fast (async connect), nmap (service/version), vuln (NSE scripts), all (hybrid deep)"
    )
    parser.add_argument("-c", "--concurrency", type=int, default=400, help="Concurrency limit for async engine (default: 400)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Connection timeout in seconds (default: 1.0)")
    parser.add_argument("-o", "--output", help="Export path (.html, .json, or .csv)")
    parser.add_argument("--no-dns", action="store_true", help="Skip DNS records gathering")
    parser.add_argument("--no-recon", action="store_true", help="Skip HTTP & SSL deep inspection")
    parser.add_argument("--web", action="store_true", help="Launch Web GUI Dashboard")

    args = parser.parse_args()

    if args.web:
        import web_app
        print_status("Starting Cyber Web Dashboard...", "success")
        web_app.app.run(host="127.0.0.1", port=5000, debug=False)
        return

    # If no target specified, enter interactive wizard
    if not args.target:
        config = interactive_wizard()
    else:
        print_banner()
        config = {
            "target": args.target,
            "ports": args.ports,
            "mode": args.mode,
            "concurrency": args.concurrency,
            "timeout": args.timeout,
            "output": args.output,
            "no_dns": args.no_dns,
            "no_recon": args.no_recon,
        }

    execute_scan(config)


if __name__ == "__main__":
    main()
