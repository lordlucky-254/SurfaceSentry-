#!/usr/bin/env python3
import argparse
import asyncio
import sys
import json
from surfacesentry.core.engine import SurfaceSentryEngine
from surfacesentry.core.storage import Storage
from surfacesentry.core.differ import DiffEngine
from surfacesentry.notifications.alert import AlertDispatcher, console
from rich.table import Table

def parse_args():
    parser = argparse.ArgumentParser(
        prog="surfacesentry",
        description="SurfaceSentry: Automated External Attack Surface Monitoring Platform"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # scan command
    scan_p = subparsers.add_parser("scan", help="Run attack surface discovery on target domain")
    scan_p.add_argument("domain", help="Target domain (e.g. example.com)")
    scan_p.add_argument("--passive", action="store_true", help="Passive enumeration only (no port scanning)")
    scan_p.add_argument("--concurrency", type=int, default=50, help="Max concurrent tasks (default: 50)")
    scan_p.add_argument("--webhook", type=str, help="Webhook URL for delta notifications (Slack/Discord)")
    scan_p.add_argument("--export", type=str, help="Export scan snapshot to JSON file")

    # diff command
    diff_p = subparsers.add_parser("diff", help="Compare two historical scans")
    diff_p.add_argument("domain", help="Target domain")
    diff_p.add_argument("--base", type=str, help="Base scan ID (defaults to previous scan)")
    diff_p.add_argument("--target", type=str, help="Target scan ID (defaults to latest scan)")

    # history command
    hist_p = subparsers.add_parser("history", help="List scan history for a domain")
    hist_p.add_argument("domain", nargs="?", help="Filter by target domain")

    # export command
    exp_p = subparsers.add_parser("export", help="Export latest scan or inventory")
    exp_p.add_argument("domain", help="Target domain")
    exp_p.add_argument("--output", "-o", default="surface_export.json", help="Output file path")

    return parser.parse_args()

def handle_scan(args):
    console.print(f"[bold cyan]🔍 Launching Attack Surface Scan for:[/bold cyan] [bold yellow]{args.domain}[/bold yellow]")
    engine = SurfaceSentryEngine(concurrency=args.concurrency)
    dispatcher = AlertDispatcher(webhook_url=args.webhook)

    snapshot, diff_report = asyncio.run(engine.scan_domain(args.domain, passive_only=args.passive))

    console.print(f"\n[green]✓ Scan complete! Scan ID: {snapshot.scan_id}[/green]")
    console.print(f"Discovered [bold]{len(snapshot.assets)}[/bold] live subdomains.\n")

    dispatcher.print_diff_report(diff_report)

    if args.webhook:
        success = dispatcher.send_webhook(diff_report)
        if success:
            console.print("[green]✓ Webhook alert sent successfully.[/green]")

    if args.export:
        with open(args.export, "w") as f:
            json.dump(snapshot.to_dict(), f, indent=2)
        console.print(f"[green]✓ Snapshot exported to {args.export}[/green]")

def handle_diff(args):
    storage = Storage()
    scans = storage.list_scans(args.domain)
    if len(scans) < 2 and (not args.base or not args.target):
        console.print("[yellow]At least two scans are required to compute a diff. Run additional scans first.[/yellow]")
        return

    base_id = args.base or scans[1]["scan_id"]
    target_id = args.target or scans[0]["scan_id"]

    base_snap = storage.get_snapshot(base_id)
    target_snap = storage.get_snapshot(target_id)

    if not base_snap or not target_snap:
        console.print("[red]Error: Specified scan ID was not found.[/red]")
        return

    differ = DiffEngine()
    report = differ.diff(base_snap, target_snap)
    dispatcher = AlertDispatcher()
    dispatcher.print_diff_report(report)

def handle_history(args):
    storage = Storage()
    scans = storage.list_scans(args.domain)
    if not scans:
        console.print("[yellow]No scans found in database.[/yellow]")
        return

    table = Table(title=f"Scan History ({args.domain or 'All Domains'})")
    table.add_column("Scan ID", style="cyan")
    table.add_column("Domain", style="yellow")
    table.add_column("Created At", style="magenta")
    table.add_column("Assets", style="green")

    for s in scans:
        table.add_row(s["scan_id"], s["domain"], s["created_at"], str(s["asset_count"]))

    console.print(table)

def handle_export(args):
    storage = Storage()
    snapshot = storage.get_latest_snapshot(args.domain)
    if not snapshot:
        console.print(f"[red]No snapshot found for domain {args.domain}[/red]")
        return

    with open(args.output, "w") as f:
        json.dump(snapshot.to_dict(), f, indent=2)
    console.print(f"[green]✓ Saved asset snapshot for {args.domain} to {args.output}[/green]")

def main():
    args = parse_args()
    if args.command == "scan":
        handle_scan(args)
    elif args.command == "diff":
        handle_diff(args)
    elif args.command == "history":
        handle_history(args)
    elif args.command == "export":
        handle_export(args)

if __name__ == "__main__":
    main()
