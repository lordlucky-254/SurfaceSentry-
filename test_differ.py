import pytest
from surfacesentry.core.models import ScanSnapshot, Asset, PortService, Finding
from surfacesentry.core.differ import DiffEngine

def test_diff_initial_scan():
    differ = DiffEngine()
    snap = ScanSnapshot(scan_id="scan_1", domain="example.com", created_at="2026-10-18T10:00:00")
    snap.assets["api.example.com"] = Asset(
        subdomain="api.example.com",
        ports=[PortService(port=443, service="https", cert_days_left=5)]
    )

    report = differ.diff(None, snap)
    assert "api.example.com" in report.new_subdomains
    assert len(report.new_open_ports) == 1
    assert len(report.cert_warnings) == 1
    assert report.total_changes == 3

def test_diff_new_subdomain_and_port():
    differ = DiffEngine()
    # Baseline scan
    base = ScanSnapshot(scan_id="scan_1", domain="example.com", created_at="2026-10-18T10:00:00")
    base.assets["example.com"] = Asset(
        subdomain="example.com",
        ports=[PortService(port=80, service="http")]
    )

    # Subsequent scan with new port 443 and new subdomain dev.example.com
    current = ScanSnapshot(scan_id="scan_2", domain="example.com", created_at="2026-10-18T11:00:00")
    current.assets["example.com"] = Asset(
        subdomain="example.com",
        ports=[
            PortService(port=80, service="http"),
            PortService(port=443, service="https")
        ]
    )
    current.assets["dev.example.com"] = Asset(
        subdomain="dev.example.com",
        ports=[PortService(port=8080, service="http-proxy")]
    )

    report = differ.diff(base, current)
    assert report.new_subdomains == ["dev.example.com"]
    assert len(report.new_open_ports) == 2  # 443 on example.com and 8080 on dev.example.com
    assert report.removed_subdomains == []
    assert report.closed_ports == []

def test_diff_closed_port():
    differ = DiffEngine()
    base = ScanSnapshot(scan_id="scan_1", domain="example.com", created_at="2026-10-18T10:00:00")
    base.assets["example.com"] = Asset(
        subdomain="example.com",
        ports=[PortService(port=22, service="ssh")]
    )

    current = ScanSnapshot(scan_id="scan_2", domain="example.com", created_at="2026-10-18T11:00:00")
    current.assets["example.com"] = Asset(
        subdomain="example.com",
        ports=[]
    )

    report = differ.diff(base, current)
    assert len(report.closed_ports) == 1
    assert report.closed_ports[0].details["port"] == 22
