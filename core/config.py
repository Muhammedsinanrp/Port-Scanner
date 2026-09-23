"""
Configuration and constants for Network Port & Vulnerability Scanner.
"""

import os
import shutil
from pathlib import Path

# Base directories
BASE_DIR = Path(__file__).resolve().parent.parent
BIN_DIR = BASE_DIR / "bin"
NMAP_EMBEDDED_DIR = BIN_DIR / "nmap-7.80"

# Standard known ports and services
COMMON_SERVICES = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    88: "Kerberos",
    110: "POP3",
    111: "RPCBind",
    123: "NTP",
    135: "MSRPC",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP-Trap",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB/Microsoft-DS",
    465: "SMTPS",
    514: "Syslog",
    587: "SMTP-Submission",
    636: "LDAPS",
    873: "Rsync",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS5",
    1433: "MS-SQL",
    1521: "Oracle-DB",
    2049: "NFS",
    2181: "ZooKeeper",
    2375: "Docker-Plain",
    2376: "Docker-TLS",
    3306: "MySQL",
    3389: "RDP",
    5000: "UPnP/Flask-Dev",
    5432: "PostgreSQL",
    5672: "RabbitMQ",
    5900: "VNC",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
    6379: "Redis",
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    9000: "SonarQube/PHP-FPM",
    9092: "Kafka",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}

# Top 100 most common ports in network reconnaissance
TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723,
    3306, 3389, 5900, 8080, 20, 26, 587, 88, 179, 389, 465, 514, 515, 636, 873,
    902, 1080, 1194, 1433, 1434, 1521, 1900, 2049, 2082, 2083, 2086, 2087, 2181,
    2222, 2375, 2376, 3000, 3128, 3268, 3269, 4000, 4443, 5000, 5060, 5061, 5432,
    5672, 5984, 5985, 5986, 6000, 6379, 7001, 7070, 7474, 8000, 8008, 8081, 8088,
    8090, 8443, 8500, 8888, 9000, 9090, 9092, 9200, 9300, 9418, 9999, 10000, 11211,
    15672, 27017, 27018, 28017, 49152, 49153, 49154, 50000, 50070
]

# Probing payloads to elicit informative banners
PROBE_PAYLOADS = {
    80: b"HEAD / HTTP/1.0\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n\r\n",
    8000: b"HEAD / HTTP/1.0\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n\r\n",
    443: b"HEAD / HTTP/1.0\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n\r\n",
    21: b"", # FTP sends banner on connect
    22: b"", # SSH sends banner on connect
    23: b"", # Telnet
    25: b"EHLO scan.local\r\n",
    587: b"EHLO scan.local\r\n",
    110: b"", # POP3 sends greeting
    143: b"A1 CAPABILITY\r\n",
    6379: b"*1\r\n$4\r\nPING\r\nINFO server\r\n",
    3306: b"", # MySQL sends initial handshake packet
    11211: b"version\r\n",
    27017: b"\x3a\x00\x00\x00\xa7\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00",
}


def find_nmap_executable() -> str | None:
    """
    Search for nmap binary in local embedded bin, system PATH, and standard Windows directories.
    """
    # 1. Embedded bin directory inside project
    embedded_nmap = NMAP_EMBEDDED_DIR / ("nmap.exe" if os.name == "nt" else "nmap")
    if embedded_nmap.exists() and os.access(embedded_nmap, os.X_OK | os.R_OK):
        return str(embedded_nmap)

    # 2. System PATH
    system_nmap = shutil.which("nmap")
    if system_nmap:
        return system_nmap

    # 3. Common Windows Program Files locations
    if os.name == "nt":
        candidates = [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
            r"D:\Program Files (x86)\Nmap\nmap.exe",
            r"D:\Program Files\Nmap\nmap.exe",
        ]
        for c in candidates:
            if os.path.exists(c):
                return c

    return None


def download_embedded_nmap(target_dir: Path = NMAP_EMBEDDED_DIR) -> bool:
    """Download official standalone portable Nmap into local bin directory."""
    import urllib.request
    import zipfile
    import shutil

    if target_dir.exists():
        return True

    url = "https://nmap.org/dist/nmap-7.80-win32.zip"
    bin_parent = target_dir.parent
    bin_parent.mkdir(parents=True, exist_ok=True)
    temp_zip = bin_parent / "nmap_temp.zip"

    try:
        print(f"[*] Downloading portable Nmap from {url}...")
        urllib.request.urlretrieve(url, temp_zip)
        with zipfile.ZipFile(temp_zip, 'r') as zip_ref:
            zip_ref.extractall(bin_parent)
        if temp_zip.exists():
            temp_zip.unlink()
        return True
    except Exception as e:
        print(f"[!] Failed to auto-download Nmap: {e}")
        if temp_zip.exists():
            temp_zip.unlink()
        return False

