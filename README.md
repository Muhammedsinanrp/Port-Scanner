# ⚡ AegisScan - Powerful Multi-Engine Network Port & Vulnerability Scanner

[![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://python.org)
[![Nmap Ready](https://img.shields.io/badge/Nmap-v7.80%20Integrated-green.svg)](https://nmap.org)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)
[![Interface](https://img.shields.io/badge/UI-Rich%20CLI%20%2B%20Web%20Dashboard-cyan.svg)](#-interfaces)

An enterprise-grade, high-performance network reconnaissance and vulnerability scanner. Upgraded from [Muhammedsinanrp/Port-Scanner](https://github.com/Muhammedsinanrp/Port-Scanner) into an extensible multi-engine platform powered by **asynchronous socket multiplexing**, deep **Nmap NSE scripts**, **smart protocol banner probing**, **SSL/TLS certificate inspection**, **heuristic CVE exposure detection**, and a **modern Cyberpunk Web Dashboard**.

---

## 🚀 Key Features

### 1. Dual Scanning Engines
- **Ultra-Fast Native Async Engine (`asyncio`)**:
  - Scans thousands of ports in seconds using non-blocking asynchronous socket multiplexing.
  - Zero external dependencies required for fast TCP scanning.
  - Semaphore-managed concurrency (configurable up to 2000 workers).
- **Deep Nmap Engine**:
  - Embedded portable Nmap binary included (`bin/nmap-7.80/nmap.exe`).
  - Automatically locates system Nmap or uses embedded distribution.
  - Deep service and version detection (`-sV --version-intensity 5`).
  - Comprehensive NSE vulnerability scripts execution (`--script vuln`).
  - Operating system fingerprinting and raw XML output parsing.

### 2. Deep Reconnaissance & Intelligence
- **Active Protocol Probing & Smart Banners**:
  - Automatically dispatches protocol handshakes for SSH, HTTP/HTTPS, FTP, SMTP, Redis, MySQL, Telnet, Memcached, and MongoDB.
- **SSL/TLS Certificate Inspector**:
  - Interrogates TLS certificates on ports 443/8443 (Subject, Issuer, Validity window, Cipher suites, and Expiration countdown).
- **Web Application Fingerprinting**:
  - Extracts HTML `<title>`, `Server` headers, `X-Powered-By`, and evaluates security headers (`HSTS`, `CSP`, `X-Frame-Options`).
- **DNS & Subdomain Mapping**:
  - Resolves IPv4, IPv6, Reverse PTR, MX, NS, and TXT records.

### 3. Heuristic Vulnerability & Exposure Analysis
- Evaluates banner signatures against known critical CVEs (e.g. vsftpd 2.3.4 backdoor `CVE-2011-2523`, ProFTPD backdoor, Apache path traversals `CVE-2021-41773`, OpenSSH `regreSSHion` / `Terrapin`, and unauthenticated Redis/Docker/MongoDB exposures).
- Severity categorization: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, and `INFO`.

### 4. Dual User Interfaces
- **Rich Terminal CLI**: Interactive color-coded tables, live progress bars, and streaming discovery alerts.
- **Cyberpunk Web GUI Dashboard**: Modern glassmorphic browser dashboard featuring real-time scan metrics, live port tables, and instant export buttons.

### 5. Multi-Format Reporting
- **Standalone HTML Report**: Self-contained, responsive dark-mode report with print/PDF styling.
- **JSON Data**: Structured payload for automation and security pipelines.
- **CSV Spreadsheet**: Clean table for spreadsheet analysis.

---

## 📁 Repository Structure

```
Network/
├── scanner.py                # Main CLI application (flags & interactive wizard)
├── port_scanner.py           # Backward-compatible entrypoint
├── web_app.py                # Flask Web Dashboard backend
├── bin/
│   └── nmap-7.80/            # Embedded portable Nmap binary and 590+ NSE scripts
├── core/
│   ├── __init__.py
│   ├── config.py             # Port databases, protocol probe payloads, Nmap locator
│   ├── async_engine.py       # Ultra-fast native asyncio scanner & banner grabber
│   ├── nmap_engine.py        # Nmap executor, NSE runner, and XML parser
│   ├── recon.py              # DNS, Ping, SSL cert inspection, HTTP tech detection
│   ├── vuln_checker.py       # Heuristic CVE and service exposure analyzer
│   └── exporter.py           # HTML, JSON, and CSV report generators
├── templates/
│   └── index.html            # Cyberpunk glassmorphic Web GUI template
├── static/
│   ├── css/style.css         # Dark neon theme & responsive styles
│   └── js/app.js             # Live scan polling & DOM updater
├── tests/
│   └── test_scanner.py       # Comprehensive unit & integration test suite
├── requirements.txt          # Python dependencies
└── README.md                 # Project documentation
```

---

## 🛠️ Installation & Setup

1. **Clone or Navigate to the Repository**:
   ```bash
   cd Network
   ```

2. **Install Python Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Verify Test Suite**:
   ```bash
   python -m unittest discover tests
   ```

---

## 💻 Usage Guide

### 1. Interactive CLI Mode (Recommended for Beginners)
Simply run without arguments to start the interactive wizard:
```bash
python scanner.py
```
*(Or use `python port_scanner.py` for backward compatibility).*

### 2. Command-Line Arguments
```bash
# Fast scan top 100 ports on a target
python scanner.py -t scanme.nmap.org -p top-100 -m fast

# Deep scan ports 1-1024 and export an interactive HTML report
python scanner.py -t 192.168.1.1 -p 1-1024 -m fast -o report.html

# Run Nmap Service & Version detection (-sV)
python scanner.py -t 192.168.1.1 -p 80,443,8080 -m nmap

# Run Nmap NSE Vulnerability Scripts
python scanner.py -t target.local -p 21,22,80,443 -m vuln -o vuln_report.html

# Full Hybrid Scan (Async speed + Nmap deep enrichment + SSL/HTTP recon)
python scanner.py -t example.com -p 1-1000 -m all -o full_audit.json
```

#### Available CLI Options:
| Flag | Description | Default |
|------|-------------|---------|
| `-t, --target` | Target IP address or hostname | Interactive Prompt |
| `-p, --ports` | Port specification (`top-100`, `1-1024`, `80,443`, `all`) | `1-1024` |
| `-m, --mode` | Scan mode: `fast`, `nmap`, `vuln`, `all` | `fast` |
| `-c, --concurrency` | Maximum concurrent async workers | `400` |
| `--timeout` | Socket connection timeout in seconds | `1.0` |
| `-o, --output` | Export file path (`.html`, `.json`, or `.csv`) | None |
| `--no-dns` | Skip DNS enumeration | `False` |
| `--no-recon` | Skip HTTP and SSL deep inspection | `False` |
| `--web` | Launch the Cyberpunk Web Dashboard | `False` |

---

### 3. Launching the Web GUI Dashboard

Start the web dashboard with either:
```bash
python web_app.py
# or
python scanner.py --web
```
Open your browser at **[http://127.0.0.1:5000](http://127.0.0.1:5000)** to access the interface:
- Real-time progress bar and live counters.
- Quick Preset chips (`Localhost`, `scanme.nmap.org`, `Dev Web Ports`).
- Real-time open port matrix with protocol banners and NSE script details.
- Security findings cards with severity ratings (`CRITICAL`, `HIGH`, `MEDIUM`).
- Instant one-click exports in HTML, JSON, or CSV.

---

## 🔒 Security & Legal Disclaimer
This tool is designed strictly for authorized educational purposes, network administration, security research, and vulnerability assessments on systems you own or have explicit permission to test. Unauthorized port scanning may violate computer crime laws and network policies.
