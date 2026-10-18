import os
import pytest
from surfacesentry.core.models import ScanSnapshot, Asset, PortService
from surfacesentry.core.storage import Storage

def test_storage_lifecycle(tmp_path):
    db_file = str(tmp_path / "test.db")
    storage = Storage(db_path=db_file)

    snap = ScanSnapshot(scan_id="scan_abc", domain="testcorp.local", created_at="2026-10-18T12:00:00")
    snap.assets["admin.testcorp.local"] = Asset(
        subdomain="admin.testcorp.local",
        ports=[PortService(port=443, service="https")]
    )

    storage.save_snapshot(snap)

    # Retrieve snapshot
    retrieved = storage.get_latest_snapshot("testcorp.local")
    assert retrieved is not None
    assert retrieved.scan_id == "scan_abc"
    assert "admin.testcorp.local" in retrieved.assets
    assert retrieved.assets["admin.testcorp.local"].ports[0].port == 443

    # Check scan list
    scans = storage.list_scans("testcorp.local")
    assert len(scans) == 1
    assert scans[0]["scan_id"] == "scan_abc"
