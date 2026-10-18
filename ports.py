import asyncio
import socket
from typing import List, Optional
from surfacesentry.core.models import PortService

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 
    1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9200, 27017
]

PORT_SERVICE_MAP = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    2049: "nfs", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
    5900: "vnc", 6379: "redis", 8000: "http-alt", 8080: "http-proxy",
    8443: "https-alt", 9200: "elasticsearch", 27017: "mongodb"
}

class PortScanner:
    def __init__(self, ports: Optional[List[int]] = None, timeout: float = 2.0, concurrency: int = 100):
        self.ports = ports if ports is not None else COMMON_PORTS
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(concurrency)

    async def scan_host(self, host: str) -> List[PortService]:
        tasks = [self._check_port(host, port) for port in self.ports]
        results = await asyncio.gather(*tasks)
        return [res for res in results if res is not None]

    async def _check_port(self, host: str, port: int) -> Optional[PortService]:
        async with self.semaphore:
            try:
                # Attempt async socket connection
                conn = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
                
                service_name = PORT_SERVICE_MAP.get(port, "unknown")
                banner = await self._grab_banner(reader, writer, port)

                writer.close()
                await writer.wait_closed()

                is_tls = port in (443, 8443, 993, 995)
                return PortService(
                    port=port,
                    protocol="tcp",
                    state="open",
                    service=service_name,
                    banner=banner,
                    tls_enabled=is_tls
                )
            except Exception:
                return None

    async def _grab_banner(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int) -> Optional[str]:
        try:
            # For HTTP ports, send a quick HEAD request
            if port in (80, 8000, 8080):
                writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                await writer.drain()

            data = await asyncio.wait_for(reader.read(1024), timeout=1.5)
            if data:
                line = data.decode("utf-8", errors="ignore").splitlines()
                if line:
                    return line[0].strip()[:100]
        except Exception:
            pass
        return None
