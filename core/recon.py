"""
Reconnaissance & Intelligence Suite: DNS, SSL/TLS, and HTTP Fingerprinting.
"""

import datetime
import socket
import ssl
import subprocess
import urllib.parse
from typing import Any, Dict, List, Optional
import requests

try:
    import dns.resolver
    import dns.reversename
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


def ping_host(target: str, timeout_sec: int = 2) -> Dict[str, Any]:
    """Test host reachability via system ping or TCP probe."""
    result = {"alive": False, "rtt_ms": None, "method": "ping"}
    try:
        # Windows ping flag is -n 1 -w <ms>
        cmd = ["ping", "-n", "1", "-w", str(int(timeout_sec * 1000)), target]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout_sec + 1)
        if res.returncode == 0:
            result["alive"] = True
            for line in res.stdout.splitlines():
                if "time=" in line.lower() or "time<" in line.lower():
                    parts = line.split("time")
                    if len(parts) > 1:
                        time_part = parts[1].replace("=", "").replace("<", "").strip().split("ms")[0].strip()
                        try:
                            result["rtt_ms"] = float(time_part)
                        except ValueError:
                            pass
            return result
    except Exception:
        pass

    # Fallback to TCP probe on port 80/443
    for test_port in [80, 443, 22, 53]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            start = datetime.datetime.now()
            s.connect((target, test_port))
            rtt = (datetime.datetime.now() - start).total_seconds() * 1000
            s.close()
            return {"alive": True, "rtt_ms": round(rtt, 2), "method": f"tcp/{test_port}"}
        except Exception:
            continue

    return result


def get_dns_records(target: str) -> Dict[str, Any]:
    """Gather DNS records (A, AAAA, MX, NS, TXT, CNAME, PTR)."""
    dns_data: Dict[str, Any] = {
        "ip_addresses": [],
        "reverse_ptr": None,
        "mx_records": [],
        "ns_records": [],
        "txt_records": [],
        "cname": None,
    }

    # Basic system resolution
    try:
        addrs = socket.gethostbyname_ex(target)
        dns_data["ip_addresses"] = addrs[2]
        dns_data["canonical_hostname"] = addrs[0]
    except Exception:
        pass

    # Reverse PTR
    try:
        if dns_data["ip_addresses"]:
            primary_ip = dns_data["ip_addresses"][0]
            ptr_name = socket.gethostbyaddr(primary_ip)[0]
            dns_data["reverse_ptr"] = ptr_name
    except Exception:
        pass

    # Check if target is a pure IP address
    is_ip = False
    try:
        socket.inet_aton(target)
        is_ip = True
    except socket.error:
        is_ip = False

    # Advanced resolution if dnspython is available and target is a domain name
    if DNS_AVAILABLE and not is_ip:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 1.5
        resolver.lifetime = 2.0

        for rtype, key in [
            ("MX", "mx_records"),
            ("NS", "ns_records"),
            ("TXT", "txt_records"),
            ("CNAME", "cname"),
        ]:
            try:
                answers = resolver.resolve(target, rtype)
                if key == "cname":
                    dns_data[key] = str(answers[0].target)
                else:
                    dns_data[key] = [str(r.to_text()) for r in answers]
            except Exception:
                pass

    return dns_data


def inspect_ssl_cert(host: str, port: int = 443, timeout: float = 3.0) -> Optional[Dict[str, Any]]:
    """Retrieve and parse SSL/TLS certificate details."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                cipher = ssock.cipher()
                version = ssock.version()

                # In CERT_NONE mode, binary_form is needed to parse fields reliably if empty
                if not cert:
                    bin_cert = ssock.getpeercert(binary_form=True)
                    if bin_cert:
                        # Re-parse if possible or fallback
                        pass

                info: Dict[str, Any] = {
                    "tls_version": version,
                    "cipher_suite": cipher[0] if cipher else "Unknown",
                    "subject": dict(x[0] for x in cert.get("subject", [])) if cert else {},
                    "issuer": dict(x[0] for x in cert.get("issuer", [])) if cert else {},
                    "not_before": cert.get("notBefore", "") if cert else "",
                    "not_after": cert.get("notAfter", "") if cert else "",
                    "san": [entry[1] for entry in cert.get("subjectAltName", [])] if cert else [],
                }

                # Calculate expiration
                if info["not_after"]:
                    try:
                        exp_date = datetime.datetime.strptime(info["not_after"], "%b %d %H:%M:%S %Y %Z")
                        days_left = (exp_date - datetime.datetime.utcnow()).days
                        info["days_until_expiration"] = days_left
                        info["is_expired"] = days_left < 0
                    except Exception:
                        info["days_until_expiration"] = None
                        info["is_expired"] = False

                return info
    except Exception:
        return None


def inspect_http_service(host: str, port: int = 80, use_ssl: bool = False, timeout: float = 4.0) -> Optional[Dict[str, Any]]:
    """Analyze HTTP/HTTPS endpoints for tech stacks, titles, and headers."""
    scheme = "https" if (use_ssl or port in (443, 8443)) else "http"
    url = f"{scheme}://{host}:{port}/"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PortScanner/2.0 (Security Recon)",
        "Accept": "*/*",
    }

    try:
        resp = requests.get(url, headers=headers, timeout=timeout, verify=False, allow_redirects=True)
        # Extract title
        title = ""
        text = resp.text[:10000]
        if "<title>" in text.lower():
            start = text.lower().find("<title>") + 7
            end = text.lower().find("</title>", start)
            if end > start:
                title = text[start:end].strip()

        # Security headers audit
        sec_headers = {
            "Strict-Transport-Security": resp.headers.get("Strict-Transport-Security", "Missing"),
            "Content-Security-Policy": "Present" if "Content-Security-Policy" in resp.headers else "Missing",
            "X-Frame-Options": resp.headers.get("X-Frame-Options", "Missing"),
            "X-Content-Type-Options": resp.headers.get("X-Content-Type-Options", "Missing"),
        }

        return {
            "url": url,
            "status_code": resp.status_code,
            "title": title,
            "server": resp.headers.get("Server", "Unknown"),
            "powered_by": resp.headers.get("X-Powered-By", ""),
            "content_type": resp.headers.get("Content-Type", ""),
            "security_headers": sec_headers,
        }
    except Exception:
        return None
