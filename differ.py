from datetime import datetime
from typing import Optional, List, Dict
from surfacesentry.core.models import ScanSnapshot, DiffReport, DeltaItem

class DiffEngine:
    """
    Computes precise delta reports between two attack surface snapshots:
    - New or decommissioned subdomains
    - Newly opened or closed ports
    - Service banner and technology drift
    - TLS certificate expiration thresholds (< 14 days)
    - Security plugin findings
    """

    def __init__(self, cert_expiry_warning_days: int = 14):
        self.cert_expiry_warning_days = cert_expiry_warning_days

    def diff(self, base_snapshot: Optional[ScanSnapshot], current_snapshot: ScanSnapshot) -> DiffReport:
        domain = current_snapshot.domain
        report = DiffReport(
            domain=domain,
            base_scan_id=base_snapshot.scan_id if base_snapshot else None,
            target_scan_id=current_snapshot.scan_id,
            generated_at=datetime.utcnow().isoformat(),
        )

        curr_assets = current_snapshot.assets

        # If there's no base snapshot, every asset is fresh
        if base_snapshot is None:
            for sub, asset in curr_assets.items():
                report.new_subdomains.append(sub)
                for port in asset.ports:
                    report.new_open_ports.append(
                        DeltaItem(
                            category="PORT",
                            change_type="ADDED",
                            asset=sub,
                            summary=f"Open port {port.port}/{port.protocol} ({port.service}) discovered",
                            details={"port": port.port, "service": port.service, "banner": port.banner}
                        )
                    )
                    if port.cert_days_left is not None and port.cert_days_left <= self.cert_expiry_warning_days:
                        report.cert_warnings.append(
                            DeltaItem(
                                category="CERTIFICATE",
                                change_type="WARNING",
                                asset=sub,
                                summary=f"TLS certificate for port {port.port} expires in {port.cert_days_left} days",
                                details={"expiry": port.cert_expiry, "days_left": port.cert_days_left}
                            )
                        )
                for finding in asset.findings:
                    report.new_findings.append(
                        DeltaItem(
                            category="FINDING",
                            change_type="ADDED",
                            asset=sub,
                            summary=f"[{finding.severity}] {finding.title}",
                            details=finding.to_dict()
                        )
                    )
            report.calculate_total()
            return report

        base_assets = base_snapshot.assets

        # 1. Subdomain deltas
        base_subs = set(base_assets.keys())
        curr_subs = set(curr_assets.keys())

        for new_sub in sorted(curr_subs - base_subs):
            report.new_subdomains.append(new_sub)

        for rem_sub in sorted(base_subs - curr_subs):
            report.removed_subdomains.append(rem_sub)

        # 2. Port & Service deltas on common subdomains
        for sub in sorted(curr_subs & base_subs):
            b_asset = base_assets[sub]
            c_asset = curr_assets[sub]

            b_ports = {p.port: p for p in b_asset.ports}
            c_ports = {p.port: p for p in c_asset.ports}

            # Newly opened ports
            for p_num in sorted(set(c_ports.keys()) - set(b_ports.keys())):
                p = c_ports[p_num]
                report.new_open_ports.append(
                    DeltaItem(
                        category="PORT",
                        change_type="ADDED",
                        asset=sub,
                        summary=f"New open port {p.port}/{p.protocol} ({p.service}) detected",
                        details={"port": p.port, "service": p.service, "banner": p.banner}
                    )
                )

            # Newly closed ports
            for p_num in sorted(set(b_ports.keys()) - set(c_ports.keys())):
                p = b_ports[p_num]
                report.closed_ports.append(
                    DeltaItem(
                        category="PORT",
                        change_type="REMOVED",
                        asset=sub,
                        summary=f"Port {p.port}/{p.protocol} is no longer open",
                        details={"port": p.port, "previous_service": p.service}
                    )
                )

            # Modified service banner or cert
            for p_num in sorted(set(b_ports.keys()) & set(c_ports.keys())):
                c_p = c_ports[p_num]
                b_p = b_ports[p_num]
                if c_p.banner and b_p.banner and c_p.banner != b_p.banner:
                    report.new_open_ports.append(
                        DeltaItem(
                            category="SERVICE",
                            change_type="MODIFIED",
                            asset=sub,
                            summary=f"Service banner on {p_num} changed from '{b_p.banner[:30]}' to '{c_p.banner[:30]}'",
                            details={"port": p_num, "old": b_p.banner, "new": c_p.banner}
                        )
                    )

        # 3. New ports on newly discovered subdomains
        for new_sub in sorted(curr_subs - base_subs):
            c_asset = curr_assets[new_sub]
            for p in c_asset.ports:
                report.new_open_ports.append(
                    DeltaItem(
                        category="PORT",
                        change_type="ADDED",
                        asset=new_sub,
                        summary=f"Open port {p.port}/{p.protocol} ({p.service}) on new host",
                        details={"port": p.port, "service": p.service, "banner": p.banner}
                    )
                )

        # 4. Certificate expiration checks across all current assets
        for sub, asset in curr_assets.items():
            for port in asset.ports:
                if port.cert_days_left is not None and port.cert_days_left <= self.cert_expiry_warning_days:
                    report.cert_warnings.append(
                        DeltaItem(
                            category="CERTIFICATE",
                            change_type="WARNING",
                            asset=sub,
                            summary=f"Certificate on port {port.port} expires in {port.cert_days_left} days",
                            details={"expiry": port.cert_expiry, "days_left": port.cert_days_left}
                        )
                    )

        # 5. Security findings diff
        for sub, asset in curr_assets.items():
            base_finding_titles = set()
            if sub in base_assets:
                base_finding_titles = {f.title for f in base_assets[sub].findings}

            for finding in asset.findings:
                if finding.title not in base_finding_titles:
                    report.new_findings.append(
                        DeltaItem(
                            category="FINDING",
                            change_type="ADDED",
                            asset=sub,
                            summary=f"[{finding.severity}] {finding.title}",
                            details=finding.to_dict()
                        )
                    )

        report.calculate_total()
        return report
