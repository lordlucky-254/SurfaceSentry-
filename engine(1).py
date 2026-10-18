import asyncio
import uuid
from datetime import datetime
from typing import Optional, Tuple, List
from surfacesentry.core.models import ScanSnapshot, Asset, PortService, DiffReport
from surfacesentry.core.differ import DiffEngine
from surfacesentry.core.storage import Storage
from surfacesentry.modules.subdomains import SubdomainEnumerator
from surfacesentry.modules.ports import PortScanner
from surfacesentry.modules.tls_cert import TLSInspector
from surfacesentry.modules.http_probe import HTTPProber
from surfacesentry.plugins.manager import PluginManager

class SurfaceSentryEngine:
    def __init__(
        self,
        storage: Optional[Storage] = None,
        ports: Optional[List[int]] = None,
        concurrency: int = 50,
        rate_limit_delay: float = 0.05
    ):
        self.storage = storage or Storage()
        self.sub_enum = SubdomainEnumerator(concurrency=concurrency)
        self.port_scanner = PortScanner(ports=ports, concurrency=concurrency)
        self.tls_inspector = TLSInspector()
        self.http_prober = HTTPProber()
        self.plugin_manager = PluginManager()
        self.diff_engine = DiffEngine()
        self.rate_limit_delay = rate_limit_delay

    async def scan_domain(self, domain: str, passive_only: bool = False) -> Tuple[ScanSnapshot, DiffReport]:
        scan_id = f"scan_{uuid.uuid4().hex[:12]}"
        now = datetime.utcnow().isoformat()
        snapshot = ScanSnapshot(scan_id=scan_id, domain=domain, created_at=now)

        # 1. Subdomain Discovery
        subdomains = await self.sub_enum.enumerate(domain)

        # 2. Asset Analysis
        for sub in subdomains:
            asset = Asset(subdomain=sub, first_seen=now, last_seen=now)

            if not passive_only:
                # Port scanning
                open_ports = await self.port_scanner.scan_host(sub)
                asset.ports = open_ports

                # TLS Inspection & HTTP Probing
                for p in open_ports:
                    if p.tls_enabled:
                        cert_info = await asyncio.to_thread(self.tls_inspector.inspect, sub, p.port)
                        if cert_info:
                            p.cert_subject = cert_info.get("subject")
                            p.cert_expiry = cert_info.get("expiry")
                            p.cert_days_left = cert_info.get("days_left")

                    if p.port in (80, 443, 8080, 8443):
                        probe_res = await asyncio.to_thread(self.http_prober.probe, sub, p.port)
                        if probe_res.get("status"):
                            asset.http_status = probe_res["status"]
                        if probe_res.get("title"):
                            asset.http_title = probe_res["title"]
                        for tech in probe_res.get("technologies", []):
                            if tech not in asset.technologies:
                                asset.technologies.append(tech)

                # Execute Security Plugins
                findings = await asyncio.to_thread(self.plugin_manager.run_all, asset)
                asset.findings = findings

            snapshot.assets[sub] = asset
            if self.rate_limit_delay > 0:
                await asyncio.sleep(self.rate_limit_delay)

        # 3. Retrieve prior baseline and compute delta
        base_snapshot = self.storage.get_latest_snapshot(domain)
        diff_report = self.diff_engine.diff(base_snapshot, snapshot)

        # 4. Save current snapshot to DB
        self.storage.save_snapshot(snapshot)

        return snapshot, diff_report
