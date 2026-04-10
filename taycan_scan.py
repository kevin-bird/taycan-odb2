#!/usr/bin/env python3
"""
Taycan DoIP Diagnostic Tool — ECU Scanner

Scan all known ECUs for DTCs (Diagnostic Trouble Codes) and basic
identification. Similar to MapEV Diag but cross-platform.

The scanner connects to each known ECU address via the DoIP gateway,
reads identification DIDs, and pulls any stored fault codes.

Usage:
    python taycan_scan.py
    python taycan_scan.py --ip 169.254.10.10
    python taycan_scan.py --ip 169.254.10.10 --discover
    python taycan_scan.py --ip 169.254.10.10 --clear   # clear DTCs (careful!)
"""

import time
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from doip_helpers import (
    create_doip_client,
    read_did_ascii,
    read_did_safe,
    format_hex,
    console,
)
from doipclient import DoIPClient
from doipclient.connectors import DoIPClientUDSConnector
from udsoncan.client import Client as UDSClient
from udsoncan.exceptions import NegativeResponseException, TimeoutException
from udsoncan.services import DiagnosticSessionControl

import config


def scan_ecu(
    gateway_ip: str,
    ecu_address: int,
    ecu_name: str,
    ecu_desc: str,
) -> dict:
    """
    Scan a single ECU: read identification and DTCs.
    Returns a dict with results or error info.
    """
    result = {
        "address": ecu_address,
        "name": ecu_name,
        "description": ecu_desc,
        "reachable": False,
        "ident": {},
        "dtcs": [],
        "error": None,
    }

    try:
        doip = DoIPClient(
            gateway_ip,
            ecu_address,
            client_logical_address=config.TESTER_ADDRESS,
            tcp_port=config.DOIP_PORT,
        )
        conn = DoIPClientUDSConnector(doip)

        uds_config = {
            "request_timeout": 2.0,
            "p2_timeout": 1.0,
            "p2_star_timeout": 3.0,
        }

        with UDSClient(conn, config=uds_config) as client:
            result["reachable"] = True

            # Read key identification DIDs
            for did in [0xF187, 0xF188, 0xF191, 0xF18C]:
                raw = read_did_safe(client, did)
                if raw is not None:
                    if isinstance(raw, bytes):
                        try:
                            text = raw.decode("ascii").strip("\x00").strip()
                            if all(32 <= ord(c) < 127 for c in text):
                                result["ident"][did] = text
                            else:
                                result["ident"][did] = raw.hex(" ")
                        except (UnicodeDecodeError, ValueError):
                            result["ident"][did] = raw.hex(" ")
                    else:
                        result["ident"][did] = str(raw)

            # Read DTCs (Service 0x19, Sub-function 0x02 = reportDTCByStatusMask)
            try:
                resp = client.get_dtc_by_status_mask(config.DTC_STATUS_MASK_ALL)
                if resp.valid and resp.positive:
                    dtc_list = getattr(resp.service_data, "dtcs", [])
                    for dtc in dtc_list:
                        result["dtcs"].append({
                            "id": dtc.id if hasattr(dtc, "id") else str(dtc),
                            "status": dtc.status.get_byte_as_int()
                            if hasattr(dtc, "status")
                            else 0,
                        })
            except NegativeResponseException:
                # Some ECUs don't support DTC reading in default session
                pass
            except (TimeoutException, Exception):
                pass

        doip.close()

    except (ConnectionRefusedError, TimeoutError, OSError):
        result["error"] = "unreachable"
    except Exception as e:
        result["error"] = str(e)

    return result


def discover_ecus(gateway_ip: str) -> list[int]:
    """
    Brute-force scan for reachable ECU addresses.
    Tries connecting to each address in the scan range.
    """
    found = []
    total = (config.ECU_SCAN_RANGE_END - config.ECU_SCAN_RANGE_START) // config.ECU_SCAN_STEP

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning ECU addresses...", total=total)

        for addr in range(
            config.ECU_SCAN_RANGE_START,
            config.ECU_SCAN_RANGE_END,
            config.ECU_SCAN_STEP,
        ):
            progress.update(task, description=f"Scanning {format_hex(addr)}...")
            try:
                doip = DoIPClient(
                    gateway_ip,
                    addr,
                    client_logical_address=config.TESTER_ADDRESS,
                    tcp_port=config.DOIP_PORT,
                )
                conn = DoIPClientUDSConnector(doip)
                uds_cfg = {"request_timeout": 1.0, "p2_timeout": 0.5}

                with UDSClient(conn, config=uds_cfg) as client:
                    # Try reading active session — minimal, universal DID
                    raw = read_did_safe(client, 0xF186)
                    if raw is not None:
                        known = config.KNOWN_ECUS.get(addr)
                        label = f"{known[0]} ({known[1]})" if known else "UNKNOWN"
                        console.print(
                            f"  [green]✓ {format_hex(addr)} — {label}[/]"
                        )
                        found.append(addr)

                doip.close()
            except Exception:
                pass

            progress.advance(task)

    return found


@click.command()
@click.option("--ip", default=config.GATEWAY_IP, help="Gateway IP", show_default=True)
@click.option("--discover", is_flag=True, help="Scan all addresses to find ECUs")
@click.option("--clear", is_flag=True, help="Clear DTCs after reading (use with caution!)")
@click.option("--output", "-o", default=None, help="Save results to text file")
def main(ip: str, discover: bool, clear: bool, output: str):
    """Scan all Taycan ECUs for identification and fault codes."""

    console.print(
        Panel(
            f"[bold]Taycan ECU Scanner[/bold]\n"
            f"Gateway: {ip}",
            border_style="cyan",
        )
    )

    # Determine which ECUs to scan
    if discover:
        console.print("\n[bold]Phase 1: ECU Address Discovery[/bold]")
        console.print(
            f"Scanning {format_hex(config.ECU_SCAN_RANGE_START)} → "
            f"{format_hex(config.ECU_SCAN_RANGE_END)}...\n"
        )
        found_addrs = discover_ecus(ip)
        console.print(f"\n[bold]Found {len(found_addrs)} ECUs[/bold]\n")

        # Merge discovered addresses with known ECUs
        ecus_to_scan = {}
        for addr in found_addrs:
            if addr in config.KNOWN_ECUS:
                ecus_to_scan[addr] = config.KNOWN_ECUS[addr]
            else:
                ecus_to_scan[addr] = ("UNK", f"Unknown ECU at {format_hex(addr)}")
    else:
        ecus_to_scan = config.KNOWN_ECUS

    # Scan each ECU
    console.print(f"\n[bold]Scanning {len(ecus_to_scan)} ECUs...[/bold]\n")
    results = []
    start_time = time.time()

    for addr, (name, desc) in ecus_to_scan.items():
        console.print(f"  [cyan]{format_hex(addr)} {name}[/]...", end=" ")
        result = scan_ecu(ip, addr, name, desc)

        if result["reachable"]:
            dtc_count = len(result["dtcs"])
            if dtc_count > 0:
                console.print(f"[yellow]✓ {dtc_count} DTC(s)[/]")
            else:
                console.print(f"[green]✓ OK[/]")
        else:
            console.print(f"[dim]— not reachable[/]")

        results.append(result)

    elapsed = time.time() - start_time

    # Summary table
    console.print(f"\n[dim]Scan completed in {elapsed:.1f}s[/]\n")

    # Reachable ECUs
    reachable = [r for r in results if r["reachable"]]
    with_dtcs = [r for r in reachable if r["dtcs"]]

    summary = Table(title="Scan Summary", show_lines=True)
    summary.add_column("ECU", style="cyan", width=8)
    summary.add_column("Description", style="white")
    summary.add_column("Part Number", style="dim")
    summary.add_column("SW Version", style="dim")
    summary.add_column("DTCs", justify="center")

    for r in reachable:
        dtc_count = len(r["dtcs"])
        dtc_str = (
            f"[red bold]{dtc_count}[/]" if dtc_count > 0
            else "[green]0[/]"
        )
        summary.add_row(
            f"{r['name']}\n{format_hex(r['address'])}",
            r["description"],
            r["ident"].get(0xF187, "—"),
            r["ident"].get(0xF188, "—"),
            dtc_str,
        )

    console.print(summary)

    # DTC details
    if with_dtcs:
        console.print(f"\n[bold red]Fault Codes Found:[/bold red]\n")
        for r in with_dtcs:
            console.print(f"  [bold]{r['name']} ({format_hex(r['address'])})[/bold]")
            for dtc in r["dtcs"]:
                # DTC ID is typically a 24-bit value
                dtc_id = dtc["id"]
                status = dtc["status"]
                status_flags = []
                if status & 0x01:
                    status_flags.append("testFailed")
                if status & 0x04:
                    status_flags.append("confirmed")
                if status & 0x08:
                    status_flags.append("pending")
                flags_str = ", ".join(status_flags) if status_flags else "stored"
                console.print(f"    [yellow]DTC {dtc_id} — {flags_str}[/]")
            console.print()
    else:
        console.print("\n[bold green]No fault codes found — vehicle healthy![/bold green]")

    # Save to file
    if output:
        with open(output, "w") as f:
            f.write(f"Taycan ECU Scan Report\n")
            f.write(f"Gateway: {ip}\n")
            f.write(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Duration: {elapsed:.1f}s\n")
            f.write(f"{'=' * 60}\n\n")

            for r in reachable:
                f.write(f"{r['name']} ({format_hex(r['address'])}) — {r['description']}\n")
                for did, val in r["ident"].items():
                    did_name = config.STANDARD_DIDS.get(did, format_hex(did))
                    f.write(f"  {did_name}: {val}\n")
                if r["dtcs"]:
                    f.write(f"  DTCs ({len(r['dtcs'])}):\n")
                    for dtc in r["dtcs"]:
                        f.write(f"    {dtc['id']} (status: 0x{dtc['status']:02X})\n")
                else:
                    f.write(f"  DTCs: none\n")
                f.write("\n")

        console.print(f"\n[dim]Report saved to {output}[/]")

    # Stats
    console.print(
        f"\n[dim]ECUs scanned: {len(ecus_to_scan)} | "
        f"Reachable: {len(reachable)} | "
        f"With faults: {len(with_dtcs)}[/]"
    )


if __name__ == "__main__":
    main()
