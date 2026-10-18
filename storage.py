import sqlite3
import json
from typing import Optional, List, Dict
from surfacesentry.core.models import ScanSnapshot, Asset

class Storage:
    """
    SQLite-backed repository for historical scans, snapshots, and asset inventory.
    """

    def __init__(self, db_path: str = "surfacesentry.db"):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    domain TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    asset_count INTEGER NOT NULL,
                    data_json TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS assets (
                    subdomain TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    data_json TEXT NOT NULL,
                    PRIMARY KEY (subdomain, domain)
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain)")
            conn.commit()

    def save_snapshot(self, snapshot: ScanSnapshot):
        data_json = json.dumps(snapshot.to_dict())
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO scans (scan_id, domain, created_at, asset_count, data_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (snapshot.scan_id, snapshot.domain, snapshot.created_at, len(snapshot.assets), data_json)
            )

            # Update asset inventory
            for sub, asset in snapshot.assets.items():
                asset_json = json.dumps(asset.to_dict())
                conn.execute(
                    """
                    INSERT INTO assets (subdomain, domain, first_seen, last_seen, data_json)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(subdomain, domain) DO UPDATE SET
                        last_seen = excluded.last_seen,
                        data_json = excluded.data_json
                    """,
                    (sub, snapshot.domain, asset.first_seen, asset.last_seen, asset_json)
                )
            conn.commit()

    def get_latest_snapshot(self, domain: str) -> Optional[ScanSnapshot]:
        with self._get_connection() as conn:
            cur = conn.execute(
                "SELECT data_json FROM scans WHERE domain = ? ORDER BY created_at DESC LIMIT 1",
                (domain,)
            )
            row = cur.fetchone()
            if not row:
                return None
            data = json.loads(row["data_json"])
            return ScanSnapshot.from_dict(data)

    def get_snapshot(self, scan_id: str) -> Optional[ScanSnapshot]:
        with self._get_connection() as conn:
            cur = conn.execute(
                "SELECT data_json FROM scans WHERE scan_id = ?",
                (scan_id,)
            )
            row = cur.fetchone()
            if not row:
                return None
            data = json.loads(row["data_json"])
            return ScanSnapshot.from_dict(data)

    def list_scans(self, domain: Optional[str] = None) -> List[Dict]:
        with self._get_connection() as conn:
            if domain:
                cur = conn.execute(
                    "SELECT scan_id, domain, created_at, asset_count FROM scans WHERE domain = ? ORDER BY created_at DESC",
                    (domain,)
                )
            else:
                cur = conn.execute(
                    "SELECT scan_id, domain, created_at, asset_count FROM scans ORDER BY created_at DESC"
                )
            return [dict(row) for row in cur.fetchall()]
