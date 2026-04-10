#!/usr/bin/env python3
"""
Taycan DoIP — Fast ECU Address Scanner

Discovers all ECU logical addresses reachable through the DoIP gateway.
Instead of opening a new TCP connection per address (slow), this sends
UDS TesterPresent (0x3E 0x00) through a single gateway connection to
each candidate address. The gateway either routes it and we get a
response, or it returns a DoIP NACK (target unreachable).

This is MUCH faster than the full connection scan — typically finds
all ECUs in under a minute.

Usage:
    python taycan_find_ecus.py
    python taycan_find_ecus.py --start 0x0001 --end 0x5FFF
    python taycan_find_ecus.py --start 0x4000 --end 0x40FF --verbose
"""

import socket
import struct
import time
import json
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn

import config
from doip_helpers import (
    DOIP_VERSION,
    DOIP_VERSION_INV,
    format_hex,
    read_did_safe,
    read_did_ascii,
)

console = Console()

# DoIP payload types
DOIP_ROUTING_ACTIVATION_REQ = 0x0005
DOIP_ROUTING_ACTIVATION_RESP = 0x0006
DOIP_DIAGNOSTIC_MESSAGE = 0x8001
DOIP_DIAGNOSTIC_POSITIVE_ACK = 0x8002
DOIP_DIAGNOSTIC_NEGATIVE_ACK = 0x8003


def build_doip_header(payload_type: int, payload_length: int) -> bytes:
    return struct.pack(">BBHI", DOIP_VERSION, DOIP_VERSION_INV, payload_type, payload_length)


def send_routing_activation(sock, tester_addr: int) -> bool:
    """Send routing activation request and wait for response."""
    # Routing activation: tester address (2) + activation type (1) + reserved (4)
    payload = struct.pack(">HB4s", tester_addr, 0x00, b"\x00" * 4)
    header = build_doip_header(DOIP_ROUTING_ACTIVATION_REQ, len(payload))
    sock.sendall(header + payload)

    try:
        resp = sock.recv(4096)
        if len(resp) >= 9:
            resp_type = struct.unpack(">H", resp[2:4])[0]
            if resp_type == DOIP_ROUTING_ACTIVATION_RESP:
                code = resp[12] if len(resp) > 12 else 0xFF
                return code == 0x10  # routing activation accepted
    except socket.timeout:
        pass
    return False


def send_uds_via_doip(sock, tester_addr: int, target_addr: int, uds_payload: bytes, timeout: float = 0.3) -> bytes | None:
    """
    Send a UDS request wrapped in DoIP diagnostic message and wait for response.
    Returns the UDS response bytes, or None if no response / NACK.
    """
    # DoIP diagnostic message: source (2) + target (2) + UDS payload
    diag_payload = struct.pack(">HH", tester_addr, target_addr) + uds_payload
    header = build_doip_header(DOIP_DIAGNOSTIC_MESSAGE, len(diag_payload))
    sock.sendall(header + diag_payload)

    # Collect responses — gateway may send ACK then diagnostic response
    deadline = time.time() + timeout
    uds_response = None

    while time.time() < deadline:
        try:
            remaining = max(0.01, deadline - time.time())
            sock.settimeout(remaining)
            data = sock.recv(4096)

            if len(data) < 8:
                continue

            resp_type = struct.unpack(">H", data[2:4])[0]

            if resp_type == DOIP_DIAGNOSTIC_NEGATIVE_ACK:
                # Target unreachable — this address doesn't exist
                return None

            if resp_type == DOIP_DIAGNOSTIC_POSITIVE_ACK:
                # Gateway accepted the message, wait for actual response
                continue

            if resp_type == DOIP_DIAGNOSTIC_MESSAGE:
                # This is the UDS response routed back from the ECU
                if len(data) >= 12:
                    uds_response = data[12:]  # skip DoIP header(8) + source(2) + target(2)
                    return uds_response

        except socket.timeout:
            break
        except Exception:
            break

    return uds_response


def identify_ecu(sock, tester_addr: int, target_addr: int) -> dict | None:
    """
    Try to identify an ECU at the given address by reading standard DIDs.
    Returns a dict with ECU info, or None if no response.
    """
    # First: TesterPresent (0x3E 0x00) — lightest possible probe
    resp = send_uds_via_doip(sock, tester_addr, target_addr, b"\x3E\x00", timeout=0.5)
    if resp is None:
        return None

    # Got a response — ECU exists. Now read identification DIDs.
    info = {"address": target_addr, "responds": True}

    # Read ASAM ID (0xF19E) — most useful for matching to MapEV scan
    resp = send_uds_via_doip(sock, tester_addr, target_addr, b"\x22\xF1\x9E", timeout=1.0)
    if resp and len(resp) > 3 and resp[0] == 0x62:
        try:
            info["asam_id"] = resp[3:].decode("ascii", errors="replace").strip("\x00").strip()
        except Exception:
            info["asam_id"] = resp[3:].hex(" ")

    # Read Software Number (0xF187)
    resp = send_uds_via_doip(sock, tester_addr, target_addr, b"\x22\xF1\x87", timeout=1.0)
    if resp and len(resp) > 3 and resp[0] == 0x62:
        try:
            info["sw_number"] = resp[3:].decode("ascii", errors="replace").strip("\x00").strip()
        except Exception:
            info["sw_number"] = resp[3:].hex(" ")

    # Read VIN (0xF190) — only some ECUs store this
    resp = send_uds_via_doip(sock, tester_addr, target_addr, b"\x22\xF1\x90", timeout=1.0)
    if resp and len(resp) > 3 and resp[0] == 0x62:
        try:
            vin = resp[3:].decode("ascii", errors="replace").strip("\x00").strip()
            if len(vin) == 17:
                info["vin"] = vin
        except Exception:
            pass

    return info


@click.command()
@click.option("--ip", default=config.GATEWAY_IP, help="Gateway IP", show_default=True)
@click.option("--start", default="0x0001", help="Start address (hex)", show_default=True)
@click.option("--end", default="0x5FFF", help="End address (hex)", show_default=True)
@click.option("--quick", is_flag=True, help="Only scan likely ranges (faster)")
@click.option("--output", "-o", default="discovered_ecus.json", help="Output file", show_default=True)
@click.option("--verbose", "-v", is_flag=True, help="Print each address as tested")
def main(ip: str, start: str, end: str, quick: bool, output: str, verbose: bool):
    """Discover all ECU addresses reachable through the Taycan DoIP gateway."""

    start_addr = int(start, 16) if start.startswith("0x") else int(start)
    end_addr = int(end, 16) if end.startswith("0x") else int(end)

    console.print(
        Panel(
            f"[bold]Taycan ECU Address Discovery[/bold]\n"
            f"Gateway: {ip} (logical 0x{config.GATEWAY_LOGICAL_ADDRESS:04X})\n"
            f"Method: UDS TesterPresent via single DoIP connection",
            border_style="cyan",
        )
    )

    # Build scan ranges
    if quick:
        ranges = config.ECU_SCAN_RANGES
        console.print("[cyan]Quick mode: scanning known likely ranges[/]")
    else:
        ranges = [(start_addr, end_addr, f"Full sweep {format_hex(start_addr)}-{format_hex(end_addr)}")]

    # Connect to gateway
    console.print(f"\n[cyan]Connecting to gateway at {ip}:{config.DOIP_PORT}...[/]")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(config.TCP_TIMEOUT)

    try:
        sock.connect((ip, config.DOIP_PORT))
    except Exception as e:
        console.print(f"[red]Connection failed: {e}[/]")
        return

    # Routing activation
    if send_routing_activation(sock, config.TESTER_ADDRESS):
        console.print("[green]✓ Routing activation successful[/]")
    else:
        console.print("[red]✗ Routing activation failed[/]")
        sock.close()
        return

    # Scan
    found = []
    start_time = time.time()

    for range_start, range_end, range_name in ranges:
        count = range_end - range_start + 1
        console.print(f"\n[cyan]Scanning {range_name}: {format_hex(range_start)} → {format_hex(range_end)} ({count} addresses)[/]")

        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("•"),
            TextColumn("[green]{task.fields[found_count]} found"),
            TimeRemainingColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning", total=count, found_count=len(found))

            for addr in range(range_start, range_end + 1):
                if verbose:
                    progress.update(task, description=f"Testing {format_hex(addr)}")

                # Quick probe: TesterPresent
                resp = send_uds_via_doip(sock, config.TESTER_ADDRESS, addr, b"\x3E\x00", timeout=0.15)

                if resp is not None:
                    # ECU responded — get identification
                    console.print(f"  [green]✓ {format_hex(addr)} responds — reading ID...[/]")
                    info = identify_ecu(sock, config.TESTER_ADDRESS, addr)
                    if info:
                        found.append(info)
                        asam = info.get("asam_id", "?")
                        sw = info.get("sw_number", "?")
                        console.print(f"    [white]ASAM: {asam}  SW: {sw}[/]")

                        # Check if this is the BECM
                        if "BECM" in asam.upper() or "BECM" in sw.upper():
                            console.print(
                                f"    [bold green]★ This is the Battery ECU (BECM)![/bold green]"
                            )

                progress.update(task, advance=1, found_count=len(found))

    elapsed = time.time() - start_time
    sock.close()

    # Results
    console.print(f"\n[bold]Discovery complete: {len(found)} ECUs found in {elapsed:.1f}s[/bold]\n")

    if found:
        table = Table(title="Discovered ECU Addresses", show_lines=True)
        table.add_column("DoIP Addr", style="cyan", width=10)
        table.add_column("ASAM ID", style="white", max_width=35)
        table.add_column("SW Number", style="dim")
        table.add_column("VIN", style="dim")

        for ecu in sorted(found, key=lambda e: e["address"]):
            table.add_row(
                format_hex(ecu["address"]),
                ecu.get("asam_id", "—"),
                ecu.get("sw_number", "—"),
                ecu.get("vin", "—"),
            )

        console.print(table)

        # Match to MapEV scan
        console.print("\n[bold]Matching to MapEV scan report:[/bold]")
        for ecu in sorted(found, key=lambda e: e["address"]):
            asam = ecu.get("asam_id", "")
            matched = False
            for code, data in config.VEHICLE_ECUS.items():
                if data.get("asam") and asam and data["asam"] in asam:
                    console.print(
                        f"  {format_hex(ecu['address'])} → "
                        f"[white]0x{code:02X} {data['name']}[/]"
                    )
                    matched = True
                    break
            if not matched and asam:
                console.print(f"  {format_hex(ecu['address'])} → [yellow]{asam} (no match in config)[/]")

        # Save
        with open(output, "w") as f:
            json.dump(
                [
                    {
                        "doip_address": format_hex(e["address"]),
                        "asam_id": e.get("asam_id"),
                        "sw_number": e.get("sw_number"),
                        "vin": e.get("vin"),
                    }
                    for e in sorted(found, key=lambda e: e["address"])
                ],
                f,
                indent=2,
            )
        console.print(f"\n[dim]Saved to {output}[/]")

        # Next steps
        becm = [e for e in found if "BECM" in (e.get("asam_id") or "").upper()]
        if becm:
            addr = format_hex(becm[0]["address"])
            console.print(f"\n[bold green]BECM found at {addr}![/bold green]")
            console.print(f"Next: python taycan_enumerate.py --ecu {addr} --start 0xF100 --end 0xF1FF")
            console.print(f"Then: python taycan_enumerate.py --ecu {addr} --start 0x0200 --end 0x0400")
            console.print(f"Then: python taycan_battery.py --bms-address {addr}")
        else:
            console.print("\n[yellow]BECM not identified by ASAM ID — check the table above manually.[/yellow]")
            console.print("Look for an ECU with SW number starting with 9J1915234")

    else:
        console.print("[yellow]No ECUs found. Try wider range or check connection.[/yellow]")


if __name__ == "__main__":
    main()
