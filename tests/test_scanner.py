"""
Unit and integration tests for Network Port & Vulnerability Scanner.
"""

import asyncio
import json
import os
import socket
import tempfile
import threading
import time
import unittest

from core.async_engine import AsyncScanner, parse_port_range
from core.config import find_nmap_executable
from core.exporter import export_csv, export_html, export_json
from core.nmap_engine import NmapEngine
from core.vuln_checker import analyze_vulnerabilities


class TestPortParser(unittest.TestCase):
    def test_single_port(self):
        ports = parse_port_range("80")
        self.assertEqual(ports, [80])

    def test_port_range(self):
        ports = parse_port_range("20-25")
        self.assertEqual(ports, [20, 21, 22, 23, 24, 25])

    def test_comma_list(self):
        ports = parse_port_range("80, 443, 8080")
        self.assertEqual(ports, [80, 443, 8080])

    def test_mixed_spec(self):
        ports = parse_port_range("22, 80-82, 443")
        self.assertEqual(ports, [22, 80, 81, 82, 443])

    def test_top_100_preset(self):
        ports = parse_port_range("top-100")
        self.assertGreater(len(ports), 80)
        self.assertIn(80, ports)
        self.assertIn(443, ports)


class TestNmapDetection(unittest.TestCase):
    def test_nmap_binary_found(self):
        nmap_path = find_nmap_executable()
        self.assertIsNotNone(nmap_path, "Nmap executable should be located")
        engine = NmapEngine(nmap_path)
        self.assertTrue(engine.is_available())


class TestVulnerabilityChecker(unittest.TestCase):
    def test_vsftpd_backdoor_detection(self):
        open_ports = [
            {"port": 21, "service": "FTP", "banner": "220 (vsFTPd 2.3.4)"}
        ]
        vulns = analyze_vulnerabilities(open_ports)
        self.assertTrue(any("CVE-2011-2523" in v.get("cve", "") for v in vulns))
        self.assertEqual(vulns[0]["severity"], "CRITICAL")

    def test_telnet_exposure_warning(self):
        open_ports = [
            {"port": 23, "service": "Telnet", "banner": "Welcome to router"}
        ]
        vulns = analyze_vulnerabilities(open_ports)
        self.assertTrue(any("Telnet" in v.get("title", "") for v in vulns))


class TestAsyncScannerLocal(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Start a dummy TCP server on an open ephemeral port
        cls.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cls.server_sock.bind(("127.0.0.1", 0))
        cls.server_port = cls.server_sock.getsockname()[1]
        cls.server_sock.listen(5)
        cls.running = True

        def server_worker():
            while cls.running:
                try:
                    cls.server_sock.settimeout(0.5)
                    client, _ = cls.server_sock.accept()
                    client.sendall(b"SSH-2.0-MockServer_1.0\r\n")
                    client.close()
                except socket.timeout:
                    continue
                except Exception:
                    break

        cls.thread = threading.Thread(target=server_worker, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.running = False
        try:
            cls.server_sock.close()
        except Exception:
            pass

    def test_local_scan_open_port(self):
        scanner = AsyncScanner(
            target="127.0.0.1",
            ports=[self.server_port, 65530],
            timeout=1.0,
            concurrency=10,
        )
        results = asyncio.run(scanner.run_scan())
        open_port_ids = [r["port"] for r in results]
        self.assertIn(self.server_port, open_port_ids)


class TestExporters(unittest.TestCase):
    def setUp(self):
        self.sample_data = {
            "target": "127.0.0.1",
            "target_ip": "127.0.0.1",
            "engine": "FAST",
            "duration_sec": 1.25,
            "ports": [
                {"port": 80, "state": "open", "service": "HTTP", "banner": "Apache/2.4", "latency_ms": 5.2}
            ],
            "vulnerabilities": [
                {"port": 80, "title": "Test Alert", "severity": "HIGH", "description": "Sample test"}
            ],
            "dns": {"ip_addresses": ["127.0.0.1"], "reverse_ptr": "localhost"},
        }

    def test_export_json_and_html(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            json_file = os.path.join(tmpdir, "report.json")
            html_file = os.path.join(tmpdir, "report.html")
            csv_file = os.path.join(tmpdir, "report.csv")

            export_json(self.sample_data, json_file)
            self.assertTrue(os.path.exists(json_file))
            with open(json_file) as f:
                loaded = json.load(f)
                self.assertEqual(loaded["target"], "127.0.0.1")

            export_html(self.sample_data, html_file)
            self.assertTrue(os.path.exists(html_file))
            with open(html_file, encoding="utf-8") as f:
                content = f.read()
                self.assertIn("127.0.0.1", content)
                self.assertIn("Test Alert", content)

            export_csv(self.sample_data, csv_file)
            self.assertTrue(os.path.exists(csv_file))


if __name__ == "__main__":
    unittest.main()
