from surfacesentry.core.models import Asset, PortService, Finding, ScanSnapshot

def test_model_serialization_roundtrip():
    finding = Finding(
        plugin_name="security_headers",
        severity="MEDIUM",
        title="Missing CSP",
        description="No CSP found",
        target="https://example.com"
    )
    port = PortService(port=443, service="https", banner="nginx")
    asset = Asset(
        subdomain="example.com",
        ports=[port],
        findings=[finding]
    )
    snapshot = ScanSnapshot(
        scan_id="s123",
        domain="example.com",
        created_at="2026-10-18T10:00:00",
        assets={"example.com": asset}
    )

    data = snapshot.to_dict()
    reconstructed = ScanSnapshot.from_dict(data)

    assert reconstructed.scan_id == "s123"
    assert "example.com" in reconstructed.assets
    assert reconstructed.assets["example.com"].ports[0].port == 443
    assert reconstructed.assets["example.com"].findings[0].title == "Missing CSP"
