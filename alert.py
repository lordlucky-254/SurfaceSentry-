import json
import urllib.request
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from surfacesentry.core.models import DiffReport

console = Console()

class AlertDispatcher:
    def __init__(self, webhook_url: Optional[str] = None):
        self.webhook_url = webhook_url

    def print_diff_report(self, report: DiffReport):
        console.print(Panel(
            f"[bold cyan]Attack Surface Delta Report[/bold cyan]\n"
            f"Domain: [bold yellow]{report.domain}[/bold yellow] | "
            f"Changes Detected: [bold red if report.total_changes > 0 else green]{report.total_changes}[/]\n"
            f"Baseline: {report.base_scan_id or 'Initial Scan'} -> Current: {report.target_scan_id}",
            expand=False
        ))

        if report.new_subdomains:
            table = Table(title="Newly Discovered Subdomains", style="cyan")
            table.add_column("Subdomain", style="bold green")
            for sub in report.new_subdomains:
                table.add_row(sub)
            console.print(table)

        if report.removed_subdomains:
            table = Table(title="Decommissioned Subdomains", style="dim")
            table.add_column("Subdomain", style="bold red")
            for sub in report.removed_subdomains:
                table.add_row(sub)
            console.print(table)

        if report.new_open_ports:
            table = Table(title="New Open Ports / Services", style="yellow")
            table.add_column("Host")
            table.add_column("Port/Service", style="bold red")
            table.add_column("Summary")
            for item in report.new_open_ports:
                table.add_row(item.asset, f"{item.details.get('port')}/{item.details.get('service')}", item.summary)
            console.print(table)

        if report.closed_ports:
            table = Table(title="Closed Ports", style="magenta")
            table.add_column("Host")
            table.add_column("Port")
            table.add_column("Summary")
            for item in report.closed_ports:
                table.add_row(item.asset, str(item.details.get("port")), item.summary)
            console.print(table)

        if report.cert_warnings:
            table = Table(title="TLS Certificate Warnings", style="bold red")
            table.add_column("Host")
            table.add_column("Days Left")
            table.add_column("Summary")
            for item in report.cert_warnings:
                table.add_row(item.asset, str(item.details.get("days_left")), item.summary)
            console.print(table)

        if report.new_findings:
            table = Table(title="Security Plugin Findings", style="bold red")
            table.add_column("Severity")
            table.add_column("Host")
            table.add_column("Title")
            for item in report.new_findings:
                sev = item.details.get("severity", "INFO")
                color = "red" if sev in ("CRITICAL", "HIGH") else ("yellow" if sev == "MEDIUM" else "blue")
                table.add_row(f"[{color}]{sev}[/]", item.asset, item.summary)
            console.print(table)

        if report.total_changes == 0:
            console.print("[bold green][✓] Attack surface baseline unchanged. No anomalies detected.[/bold green]")

    def send_webhook(self, report: DiffReport) -> bool:
        if not self.webhook_url or report.total_changes == 0:
            return False

        payload = {
            "text": f"🚨 *Attack Surface Alert for {report.domain}*",
            "domain": report.domain,
            "total_changes": report.total_changes,
            "new_subdomains": report.new_subdomains,
            "new_open_ports": [p.summary for p in report.new_open_ports],
            "cert_warnings": [c.summary for c in report.cert_warnings],
            "new_findings": [f.summary for f in report.new_findings],
            "generated_at": report.generated_at
        }

        try:
            req = urllib.request.Request(
                self.webhook_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                return resp.status in (200, 204)
        except Exception:
            return False
