"""
High-Performance Asynchronous Port Scanner and Banner Grabbing Engine.
"""

import asyncio
import socket
import time
from typing import Callable, Dict, List, Optional, Tuple
from core.config import COMMON_SERVICES, PROBE_PAYLOADS


class AsyncScanner:
    """
    Ultra-fast asyncio-based TCP connect scanner with smart banner grabbing.
    """

    def __init__(
        self,
        target: str,
        ports: List[int],
        timeout: float = 1.0,
        concurrency: int = 400,
        progress_callback: Optional[Callable[[int, int, Optional[dict]], None]] = None,
    ):
        self.target = target
        self.ports = ports
        self.timeout = timeout
        self.concurrency = concurrency
        self.progress_callback = progress_callback
        self.results: List[dict] = []
        self._semaphore = asyncio.Semaphore(concurrency)
        self._completed_count = 0
        self._total_count = len(ports)
        self._target_ip = ""

    async def resolve_target(self) -> str:
        """Resolve hostname to IPv4 address."""
        loop = asyncio.get_running_loop()
        try:
            addr_info = await loop.getaddrinfo(
                self.target, None, family=socket.AF_INET, type=socket.SOCK_STREAM
            )
            self._target_ip = addr_info[0][4][0]
            return self._target_ip
        except Exception as e:
            # Fallback to direct string if already an IP
            self._target_ip = self.target
            return self.target

    async def _grab_banner(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int) -> str:
        """Elicit and parse service banner."""
        banner = ""
        try:
            # If protocol needs a probe payload, send it
            payload = PROBE_PAYLOADS.get(port, b"")
            if payload:
                writer.write(payload)
                await writer.drain()

            # Read banner with a short timeout
            data = await asyncio.wait_for(reader.read(1024), timeout=1.2)
            if data:
                # Clean banner of non-printable or control characters
                banner = data.decode("utf-8", errors="replace").strip()
                # Keep first 3 lines or 150 chars max for clean display
                lines = [line.strip() for line in banner.splitlines() if line.strip()]
                if lines:
                    banner = " | ".join(lines[:3])[:200]
        except Exception:
            banner = ""
        return banner

    async def _scan_single_port(self, port: int) -> Optional[dict]:
        """Scan a single port and grab banner if open."""
        async with self._semaphore:
            start_time = time.perf_counter()
            conn_result = None

            try:
                connect_task = asyncio.open_connection(self._target_ip, port)
                reader, writer = await asyncio.wait_for(connect_task, timeout=self.timeout)
                latency = round((time.perf_counter() - start_time) * 1000, 2)

                # Banner extraction
                banner = await self._grab_banner(reader, writer, port)

                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

                service_name = COMMON_SERVICES.get(port, "unknown")
                conn_result = {
                    "port": port,
                    "state": "open",
                    "service": service_name,
                    "banner": banner,
                    "latency_ms": latency,
                }
            except asyncio.TimeoutError:
                # Filtered / no response
                conn_result = None
            except ConnectionRefusedError:
                # Closed port
                conn_result = None
            except OSError:
                # Unreachable / socket error
                conn_result = None
            except Exception:
                conn_result = None
            finally:
                self._completed_count += 1
                if self.progress_callback:
                    self.progress_callback(self._completed_count, self._total_count, conn_result)

            return conn_result

    async def run_scan(self) -> List[dict]:
        """Execute concurrent scanning across all target ports."""
        await self.resolve_target()
        self._completed_count = 0
        self.results = []

        tasks = [asyncio.create_task(self._scan_single_port(port)) for port in self.ports]
        scanned = await asyncio.gather(*tasks, return_exceptions=True)

        for res in scanned:
            if isinstance(res, dict) and res.get("state") == "open":
                self.results.append(res)

        # Sort results by port number ascending
        self.results.sort(key=lambda x: x["port"])
        return self.results


def parse_port_range(port_spec: str) -> List[int]:
    """
    Parse flexible port specifications:
    - 'top-100' or 'common'
    - '80'
    - '1-1024'
    - '80,443,8080,8443'
    - '1-100,443,8000-8080'
    """
    spec = str(port_spec).strip().lower()
    if not spec or spec == "default" or spec == "1-1024":
        return list(range(1, 1025))
    if spec in ("top-100", "top100", "fast"):
        from core.config import TOP_100_PORTS
        return sorted(list(set(TOP_100_PORTS)))
    if spec in ("all", "1-65535", "full"):
        return list(range(1, 65536))

    ports = set()
    parts = spec.split(",")
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                start_p, end_p = part.split("-", 1)
                start_i = max(1, int(start_p.strip()))
                end_i = min(65535, int(end_p.strip()))
                if start_i <= end_i:
                    ports.update(range(start_i, end_i + 1))
            except ValueError:
                continue
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
            except ValueError:
                continue

    return sorted(list(ports)) if ports else list(range(1, 1025))
