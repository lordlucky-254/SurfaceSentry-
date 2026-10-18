from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import List, Dict, Optional, Any

@dataclass
class PortService:
    port: int
    protocol: str = "tcp"
    state: str = "open"  # open, closed, filtered
    service: str = "unknown"
    banner: Optional[str] = None
    tls_enabled: bool = False
    cert_subject: Optional[str] = None
    cert_expiry: Optional[str] = None
    cert_days_left: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PortService":
        return cls(**data)

@dataclass
class Finding:
    plugin_name: str
    severity: str  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    title: str
    description: str
    target: str
    evidence: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        return cls(**data)

@dataclass
class Asset:
    subdomain: str
    ip_addresses: List[str] = field(default_factory=list)
    cnames: List[str] = field(default_factory=list)
    ports: List[PortService] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    http_status: Optional[int] = None
    http_title: Optional[str] = None
    findings: List[Finding] = field(default_factory=list)
    first_seen: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    last_seen: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "subdomain": self.subdomain,
            "ip_addresses": self.ip_addresses,
            "cnames": self.cnames,
            "ports": [p.to_dict() for p in self.ports],
            "technologies": self.technologies,
            "http_status": self.http_status,
            "http_title": self.http_title,
            "findings": [f.to_dict() for f in self.findings],
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Asset":
        ports = [PortService.from_dict(p) for p in data.get("ports", [])]
        findings = [Finding.from_dict(f) for f in data.get("findings", [])]
        return cls(
            subdomain=data["subdomain"],
            ip_addresses=data.get("ip_addresses", []),
            cnames=data.get("cnames", []),
            ports=ports,
            technologies=data.get("technologies", []),
            http_status=data.get("http_status"),
            http_title=data.get("http_title"),
            findings=findings,
            first_seen=data.get("first_seen", datetime.utcnow().isoformat()),
            last_seen=data.get("last_seen", datetime.utcnow().isoformat()),
        )

@dataclass
class ScanSnapshot:
    scan_id: str
    domain: str
    created_at: str
    assets: Dict[str, Asset] = field(default_factory=dict)  # keyed by subdomain

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "domain": self.domain,
            "created_at": self.created_at,
            "assets": {k: v.to_dict() for k, v in self.assets.items()}
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanSnapshot":
        assets = {k: Asset.from_dict(v) for k, v in data.get("assets", {}).items()}
        return cls(
            scan_id=data["scan_id"],
            domain=data["domain"],
            created_at=data["created_at"],
            assets=assets
        )

@dataclass
class DeltaItem:
    category: str  # SUBDOMAIN, PORT, SERVICE, FINDING, CERTIFICATE
    change_type: str  # ADDED, REMOVED, MODIFIED
    asset: str
    summary: str
    details: Dict[str, Any] = field(default_factory=dict)

@dataclass
class DiffReport:
    domain: str
    base_scan_id: Optional[str]
    target_scan_id: str
    generated_at: str
    new_subdomains: List[str] = field(default_factory=list)
    removed_subdomains: List[str] = field(default_factory=list)
    new_open_ports: List[DeltaItem] = field(default_factory=list)
    closed_ports: List[DeltaItem] = field(default_factory=list)
    cert_warnings: List[DeltaItem] = field(default_factory=list)
    new_findings: List[DeltaItem] = field(default_factory=list)
    total_changes: int = 0

    def calculate_total(self):
        self.total_changes = (
            len(self.new_subdomains)
            + len(self.removed_subdomains)
            + len(self.new_open_ports)
            + len(self.closed_ports)
            + len(self.cert_warnings)
            + len(self.new_findings)
        )
        return self.total_changes
