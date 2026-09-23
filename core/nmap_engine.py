"""
Deep Nmap Integration Engine and NSE Script Parser.
"""

import os
import subprocess
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional
from core.config import find_nmap_executable


class NmapEngine:
    """
    Wrapper for running Nmap scans and parsing structured XML results.
    """

    def __init__(self, nmap_path: Optional[str] = None):
        self.nmap_path = nmap_path or find_nmap_executable()

    def is_available(self) -> bool:
        """Check whether Nmap binary is present and executable."""
        if not self.nmap_path:
            return False
        return os.path.exists(self.nmap_path)

    def run_scan(
        self,
        target: str,
        ports: Optional[str] = None,
        profile: str = "quick",
        extra_args: Optional[List[str]] = None,
        timeout_sec: int = 120,
    ) -> Dict[str, Any]:
        """
        Execute an Nmap scan and return structured dictionary results.
        
        Profiles:
        - 'quick': Fast connect scan (-sT -F -T4)
        - 'service': Deep service and version detection (-sT -sV)
        - 'vuln': Service detection + NSE vulnerability scripts (-sT -sV --script vuln)
        - 'aggressive': Aggressive scan with OS detection (-sT -A)
        - 'custom': Uses extra_args directly
        """
        if not self.is_available():
            raise FileNotFoundError(
                "Nmap executable was not found. Please ensure Nmap is installed or in PATH."
            )

        cmd = [self.nmap_path, target, "-oX", "-"]

        # On non-elevated Windows, enforce -sT (TCP Connect) to avoid raw socket Npcap requirement
        default_tcp_mode = "-sT"

        if profile == "quick":
            cmd.extend([default_tcp_mode, "-F", "-T4", "--open"])
        elif profile == "service":
            cmd.extend([default_tcp_mode, "-sV", "--version-intensity", "5", "-T4", "--open"])
        elif profile == "vuln":
            cmd.extend([default_tcp_mode, "-sV", "--script", "vuln", "-T4", "--open"])
        elif profile == "aggressive":
            cmd.extend([default_tcp_mode, "-A", "-T4", "--open"])

        if ports and profile != "quick":
            cmd.extend(["-p", str(ports)])

        if extra_args:
            cmd.extend(extra_args)

        # Execute process
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_sec,
        )

        return self._parse_nmap_xml(proc.stdout, proc.stderr)

    def _parse_nmap_xml(self, xml_content: str, stderr_content: str) -> Dict[str, Any]:
        """Parse Nmap XML output into a clean structured dictionary."""
        result: Dict[str, Any] = {
            "success": True,
            "hosts": [],
            "raw_stderr": stderr_content,
            "total_open_ports": 0,
        }

        if not xml_content.strip():
            result["success"] = False
            result["error"] = "Empty XML output from Nmap."
            return result

        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError as e:
            result["success"] = False
            result["error"] = f"Failed to parse Nmap XML: {e}"
            return result

        for host_elem in root.findall("host"):
            host_info: Dict[str, Any] = {
                "addresses": [],
                "hostnames": [],
                "status": "unknown",
                "ports": [],
                "os_matches": [],
            }

            # Status
            status_elem = host_elem.find("status")
            if status_elem is not None:
                host_info["status"] = status_elem.get("state", "unknown")

            # Addresses
            for addr in host_elem.findall("address"):
                host_info["addresses"].append({
                    "addr": addr.get("addr"),
                    "type": addr.get("addrtype"),
                })

            # Hostnames
            hostnames_elem = host_elem.find("hostnames")
            if hostnames_elem is not None:
                for hn in hostnames_elem.findall("hostname"):
                    host_info["hostnames"].append(hn.get("name"))

            # Ports
            ports_elem = host_elem.find("ports")
            if ports_elem is not None:
                for port_elem in ports_elem.findall("port"):
                    state_elem = port_elem.find("state")
                    state = state_elem.get("state") if state_elem is not None else "unknown"

                    # Only capture open or open|filtered ports
                    if "open" not in state:
                        continue

                    port_id = int(port_elem.get("portid", 0))
                    proto = port_elem.get("protocol", "tcp")

                    service_elem = port_elem.find("service")
                    svc_name = service_elem.get("name", "unknown") if service_elem is not None else "unknown"
                    product = service_elem.get("product", "") if service_elem is not None else ""
                    version = service_elem.get("version", "") if service_elem is not None else ""
                    extrainfo = service_elem.get("extrainfo", "") if service_elem is not None else ""

                    banner = " ".join(filter(None, [product, version, extrainfo])).strip()

                    # NSE scripts output for this port
                    scripts = {}
                    for script_elem in port_elem.findall("script"):
                        s_id = script_elem.get("id")
                        s_out = script_elem.get("output", "")
                        scripts[s_id] = s_out

                    host_info["ports"].append({
                        "port": port_id,
                        "protocol": proto,
                        "state": state,
                        "service": svc_name,
                        "banner": banner,
                        "scripts": scripts,
                    })

            # OS matches
            os_elem = host_elem.find("os")
            if os_elem is not None:
                for match in os_elem.findall("osmatch"):
                    host_info["os_matches"].append({
                        "name": match.get("name"),
                        "accuracy": match.get("accuracy"),
                    })

            result["total_open_ports"] += len(host_info["ports"])
            result["hosts"].append(host_info)

        return result
