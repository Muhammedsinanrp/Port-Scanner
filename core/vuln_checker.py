"""
Vulnerability and Heuristic Security Analysis Engine.
"""

from typing import Any, Dict, List


VULN_SIGNATURES = [
    {
        "pattern": "vsftpd 2.3.4",
        "title": "vsftpd 2.3.4 Backdoor Vulnerability (CVE-2011-2523)",
        "severity": "CRITICAL",
        "description": "Contains a notorious malicious backdoor triggered by a smile emoji in the username, spawning an interactive root shell on port 6200.",
        "cve": "CVE-2011-2523",
    },
    {
        "pattern": "proftpd 1.3.3c",
        "title": "ProFTPD 1.3.3c Compromised Source Backdoor",
        "severity": "CRITICAL",
        "description": "Distribution archive was compromised with a root backdoor triggered with 'HELP ACIDBITCHEZ'.",
        "cve": "OSVDB-69562",
    },
    {
        "pattern": "Apache/2.4.49",
        "title": "Apache HTTP Server Path Traversal & RCE (CVE-2021-41773)",
        "severity": "CRITICAL",
        "description": "Allows remote path traversal and arbitrary code execution via forged URL requests.",
        "cve": "CVE-2021-41773",
    },
    {
        "pattern": "Apache/2.4.50",
        "title": "Apache HTTP Server Incomplete Fix Path Traversal (CVE-2021-42013)",
        "severity": "CRITICAL",
        "description": "Bypass for CVE-2021-41773 allowing remote path traversal and command execution.",
        "cve": "CVE-2021-42013",
    },
    {
        "pattern": "OpenSSH_9.2",
        "title": "OpenSSH regreSSHion Vulnerability (CVE-2024-6387)",
        "severity": "HIGH",
        "description": "Signal handler race condition in OpenSSH's server (sshd) allows remote code execution as root on glibc-based systems.",
        "cve": "CVE-2024-6387",
    },
    {
        "pattern": "OpenSSH_8.",
        "title": "OpenSSH Terrapin Attack Vulnerability (CVE-2023-48795)",
        "severity": "MEDIUM",
        "description": "Prefix truncation attack that manipulates sequence numbers during the SSH handshake.",
        "cve": "CVE-2023-48795",
    },
    {
        "pattern": "OpenSSH_7.",
        "title": "Legacy OpenSSH Version Detected",
        "severity": "MEDIUM",
        "description": "OpenSSH 7.x series has reached end-of-life and contains known user enumeration and cryptographic weaknesses.",
        "cve": "CVE-2018-15473",
    },
]

PORT_EXPOSURE_RISKS = {
    23: {
        "title": "Unencrypted Telnet Service Exposed",
        "severity": "HIGH",
        "description": "Telnet transmits credentials and all terminal sessions in plaintext over the wire. Replace with SSH (port 22).",
    },
    21: {
        "title": "Plaintext FTP Service Exposed",
        "severity": "MEDIUM",
        "description": "Standard FTP transmits user passwords in cleartext. Upgrade to FTPS (TLS) or SFTP.",
    },
    445: {
        "title": "Direct SMB File Sharing Exposed",
        "severity": "HIGH",
        "description": "Direct exposure of SMB (port 445) is a primary attack vector for network ransomware and lateral movement (e.g. EternalBlue).",
    },
    2375: {
        "title": "Unauthenticated Docker Daemon Socket",
        "severity": "CRITICAL",
        "description": "Docker REST API exposed without TLS authentication allows trivial root container escape and host takeover.",
    },
    6379: {
        "title": "Redis Database Port Exposed",
        "severity": "HIGH",
        "description": "Redis instances without robust password protection or bound to 0.0.0.0 are vulnerable to unauthorized data access and SSH key injection.",
    },
    27017: {
        "title": "MongoDB Database Port Exposed",
        "severity": "HIGH",
        "description": "MongoDB instance exposed to network. Verify that strong authentication (SCRAM-SHA-256) and TLS are enforced.",
    },
    11211: {
        "title": "Memcached Port Exposed (DDoS Amplification Vector)",
        "severity": "HIGH",
        "description": "Memcached exposed on public networks can be exploited as a massive UDP/TCP amplification vector for DDoS attacks.",
    },
    3389: {
        "title": "Remote Desktop Protocol (RDP) Exposed",
        "severity": "MEDIUM",
        "description": "Exposing RDP directly to public networks attracts automated credential brute-force attacks and BlueKeep exploits. Protect with a VPN or MFA gateway.",
    },
    5900: {
        "title": "VNC Remote Desktop Exposed",
        "severity": "MEDIUM",
        "description": "VNC protocols frequently have weak password limits (8 characters) and lack encryption. Tunnel through SSH or VPN.",
    },
}


def analyze_vulnerabilities(open_ports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Scan open ports, service banners, and configurations for security vulnerabilities."""
    findings = []

    for port_info in open_ports:
        port = port_info.get("port")
        banner = port_info.get("banner", "") or ""
        service = port_info.get("service", "") or ""

        # 1. Port exposure risk check
        if port in PORT_EXPOSURE_RISKS:
            risk = PORT_EXPOSURE_RISKS[port]
            findings.append({
                "port": port,
                "title": risk["title"],
                "severity": risk["severity"],
                "description": risk["description"],
                "evidence": f"Port {port} ({service}) is actively open.",
            })

        # 2. Signature pattern matching on banner text
        for sig in VULN_SIGNATURES:
            if sig["pattern"].lower() in banner.lower():
                findings.append({
                    "port": port,
                    "title": sig["title"],
                    "severity": sig["severity"],
                    "description": sig["description"],
                    "cve": sig.get("cve"),
                    "evidence": f"Found signature '{sig['pattern']}' in banner: {banner}",
                })

    # Deduplicate findings by title and port
    seen = set()
    deduped = []
    for item in findings:
        key = (item["port"], item["title"])
        if key not in seen:
            seen.add(key)
            deduped.append(item)

    # Sort by severity (CRITICAL > HIGH > MEDIUM > LOW > INFO)
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    deduped.sort(key=lambda x: severity_order.get(x["severity"], 5))

    return deduped
