#!/usr/bin/env python3
"""
Taycan DoIP Diagnostic Tool — Battery Health Reader

Milestone 4: Read battery SoH, SoC, cell voltages, temperatures,
and other HV battery data from the BMS ECU.

IMPORTANT: The DID addresses for battery data are manufacturer-specific
and need to be confirmed on your vehicle. This script provides:

1. A structured reader for known/suspected battery DIDs
2. A DID probe mode to discover which DIDs the BMS responds to
3. Raw data output for reverse engineering unknown responses

Usage:
    python taycan_battery.py
    python taycan_battery.py --ip 169.254.10.10
    python taycan_battery.py --ip 169.254.10.10 --probe
    python taycan_battery.py --ip 169.254.10.10 --bms-address 0x1066
"""

import time
import json
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from doip_helpers import (
    uds_session,
    read_did_safe,
    read_did_ascii,
    read_did_uint,
    read_did_int,
    format_hex,
)
import config

console = Console()


def read_battery_data(client, bms_address: int) -> dict:
    """
    Read all known/suspected battery DIDs from the BMS.
    Returns a dict of { did: { name, raw_hex, value, unit } }.
    """
    data = {}

    for did, name in config.BATTERY_DIDS.items():
        raw = read_did_safe(client, did)
        entry = {"name": name, "raw": None, "value": None, "unit": ""}

        if raw is not None:
            if isinstance(raw, bytes):
                entry["raw"] = raw.hex(" ")

                # Attempt smart decoding based on DID semantics
                if "SoH" in name or "SoC" in name:
                    # Typically 1 or 2 bytes, scaled by 0.1 or 0.01
                    val = int.from_bytes(raw, "big", signed=False)
                    # Try common scales
                    if val > 10000:
                        entry["value"] = val / 100.0
                    elif val > 1000:
                        entry["value"] = val / 10.0
                    else:
                        entry["value"] = val / 1.0
                    entry["unit"] = "%"

                elif "Voltage" in name and "Cell" not in name:
                    val = int.from_bytes(raw, "big", signed=False)
                    entry["value"] = val / 10.0 if val > 10000 else val / 1.0
                    entry["unit"] = "V"

                elif "Cell Voltage" in name:
                    val = int.from_bytes(raw, "big", signed=False)
                    entry["value"] = val
                    entry["unit"] = "mV"

                elif "Current" in name:
                    val = int.from_bytes(raw, "big", signed=True)
                    entry["value"] = val / 10.0
                    entry["unit"] = "A"

                elif "Power" in name:
                    val = int.from_bytes(raw, "big", signed=True)
                    entry["value"] = val / 10.0
                    entry["unit"] = "kW"

                elif "Temperature" in name or "Temp" in name:
                    val = int.from_bytes(raw, "big", signed=True)
                    entry["value"] = val / 10.0 if abs(val) > 1000 else val
                    entry["unit"] = "°C"

                elif "Capacity" in name or "Energy" in name:
                    val = int.from_bytes(raw, "big", signed=False)
                    entry["value"] = val
                    entry["unit"] = "Wh"

                elif "Count" in name:
                    val = int.from_bytes(raw, "big", signed=False)
                    entry["value"] = val
                    entry["unit"] = ""

                else:
                    val = int.from_bytes(raw, "big", signed=False)
                    entry["value"] = val
            else:
                entry["raw"] = str(raw)
                entry["value"] = raw

        data[did] = entry

    return data


def probe_bms_dids(
    client,
    ranges: list[tuple[int, int, str]] = None,
    progress_callback=None,
) -> dict:
    """
    Probe the BMS for any responding DIDs in the given ranges.
    Returns { did: raw_hex_response } for all positive responses.
    """
    if ranges is None:
        ranges = config.DID_SCAN_RANGES

    found = {}

    for range_start, range_end, range_name in ranges:
        count = range_end - range_start + 1

        for did in range(range_start, range_end + 1):
            raw = read_did_safe(client, did)
            if raw is not None:
                if isinstance(raw, bytes):
                    found[did] = raw.hex(" ")
                else:
                    found[did] = str(raw)

                # Check if this is a known DID
                known_name = config.BATTERY_DIDS.get(
                    did, config.STANDARD_DIDS.get(did, None)
                )
                label = f" ({known_name})" if known_name else ""
                console.print(
                    f"    [green]✓ {format_hex(did)}{label}: "
                    f"{found[did][:50]}[/]"
                )

            if progress_callback:
                progress_callback()

    return found


@click.command()
@click.option("--ip", default=config.GATEWAY_IP, help="Gateway IP", show_default=True)
@click.option(
    "--bms-address", default="0x407B",
    help="BMS ECU logical address (hex)",
    show_default=True,
)
@click.option("--probe", is_flag=True, help="Probe all DID ranges to discover supported DIDs")
@click.option(
    "--probe-range", nargs=2, type=str, default=None,
    help="Custom probe range: --probe-range 0x0200 0x0400",
)
@click.option("--extended", is_flag=True, help="Use extended diagnostic session")
@click.option("--json-out", default=None, help="Save results as JSON")
@click.option("--continuous", is_flag=True, help="Continuously read battery data (Ctrl+C to stop)")
@click.option("--interval", default=2.0, help="Continuous read interval (seconds)", show_default=True)
def main(
    ip: str,
    bms_address: str,
    probe: bool,
    probe_range: tuple | None,
    extended: bool,
    json_out: str | None,
    continuous: bool,
    interval: float,
):
    """Read battery health data from the Taycan BMS."""

    bms_addr = int(bms_address, 16) if bms_address.startswith("0x") else int(bms_address)
    session_type = 0x03 if extended else None  # 0x03 = extendedDiagnosticSession

    console.print(
        Panel(
            f"[bold]Taycan Battery Health Reader[/bold]\n"
            f"Gateway: {ip}  |  BMS: {format_hex(bms_addr)}"
            + (" (extended session)" if extended else ""),
            border_style="green",
        )
    )

    try:
        with uds_session(
            gateway_ip=ip,
            ecu_address=bms_addr,
            session_type=session_type,
        ) as (client, doip):

            # ── Probe mode ──────────────────────────────────────────
            if probe or probe_range:
                console.print("\n[bold]DID Probe Mode[/bold]")
                console.print(
                    "[dim]Scanning for any DIDs that the BMS responds to...\n"
                    "This takes a while — each non-responding DID times out.\n"
                    "Results are printed live.[/dim]\n"
                )

                if probe_range:
                    start = int(probe_range[0], 16) if probe_range[0].startswith("0x") else int(probe_range[0])
                    end = int(probe_range[1], 16) if probe_range[1].startswith("0x") else int(probe_range[1])
                    ranges = [(start, end, "Custom range")]
                else:
                    ranges = config.DID_SCAN_RANGES

                for range_start, range_end, range_name in ranges:
                    console.print(
                        f"  [cyan]Scanning {range_name}: "
                        f"{format_hex(range_start)} → {format_hex(range_end)}[/]"
                    )

                found = probe_bms_dids(client, ranges)

                # Summary
                console.print(f"\n[bold]Probe Results: {len(found)} DIDs found[/bold]\n")

                if found:
                    table = Table(title="Discovered Battery DIDs")
                    table.add_column("DID", style="cyan", width=8)
                    table.add_column("Known Name", style="white")
                    table.add_column("Raw Data (hex)", style="green")

                    for did in sorted(found.keys()):
                        known = config.BATTERY_DIDS.get(
                            did, config.STANDARD_DIDS.get(did, "—")
                        )
                        table.add_row(format_hex(did), known, found[did])

                    console.print(table)

                if json_out:
                    with open(json_out, "w") as f:
                        json.dump(
                            {format_hex(k): v for k, v in sorted(found.items())},
                            f,
                            indent=2,
                        )
                    console.print(f"\n[dim]Probe results saved to {json_out}[/]")

                return

            # ── Standard read mode ──────────────────────────────────
            def do_read():
                data = read_battery_data(client, bms_addr)

                # Filter to only responded DIDs
                responded = {
                    did: entry for did, entry in data.items()
                    if entry["raw"] is not None
                }
                no_response = {
                    did: entry for did, entry in data.items()
                    if entry["raw"] is None
                }

                if responded:
                    table = Table(title="Battery Health Data", show_lines=True)
                    table.add_column("DID", style="cyan", width=8)
                    table.add_column("Parameter", style="white")
                    table.add_column("Value", style="bold green", justify="right")
                    table.add_column("Unit", style="dim")
                    table.add_column("Raw (hex)", style="dim")

                    for did in sorted(responded.keys()):
                        entry = responded[did]
                        val_str = (
                            f"{entry['value']:.1f}"
                            if isinstance(entry["value"], float)
                            else str(entry["value"])
                        ) if entry["value"] is not None else "?"

                        table.add_row(
                            format_hex(did),
                            entry["name"],
                            val_str,
                            entry["unit"],
                            entry["raw"],
                        )

                    console.print(table)

                    # Highlight key metrics
                    for did in [0x028C, 0x028D]:
                        if did in responded and responded[did]["value"] is not None:
                            name = responded[did]["name"]
                            val = responded[did]["value"]
                            unit = responded[did]["unit"]
                            console.print(
                                f"\n  [bold]{name}: {val:.1f}{unit}[/bold]"
                            )
                else:
                    console.print(
                        "\n[yellow]No battery DIDs responded.[/yellow]"
                    )
                    console.print(
                        "The DID addresses may be different on your vehicle.\n"
                        "Try: python taycan_battery.py --probe\n"
                        "Or:  python taycan_battery.py --extended --probe\n"
                        "Or:  python taycan_enumerate.py --ecu "
                        f"{format_hex(bms_addr)}"
                    )

                if no_response and not continuous:
                    console.print(
                        f"\n[dim]{len(no_response)} DIDs did not respond "
                        f"(may need different session or address)[/dim]"
                    )

                return data

            if continuous:
                console.print(
                    "\n[bold]Continuous monitoring mode[/bold] "
                    f"(every {interval}s, Ctrl+C to stop)\n"
                )
                try:
                    while True:
                        console.clear()
                        console.print(
                            f"[dim]{time.strftime('%H:%M:%S')} — "
                            f"BMS {format_hex(bms_addr)} @ {ip}[/dim]\n"
                        )
                        do_read()
                        time.sleep(interval)
                except KeyboardInterrupt:
                    console.print("\n[dim]Monitoring stopped.[/dim]")
            else:
                console.print()
                data = do_read()

                if json_out:
                    export = {}
                    for did, entry in data.items():
                        if entry["raw"] is not None:
                            export[format_hex(did)] = {
                                "name": entry["name"],
                                "value": entry["value"],
                                "unit": entry["unit"],
                                "raw_hex": entry["raw"],
                            }
                    with open(json_out, "w") as f:
                        json.dump(export, f, indent=2)
                    console.print(f"\n[dim]Data saved to {json_out}[/]")

    except ConnectionRefusedError:
        console.print(f"\n[red]Connection refused — BMS at {format_hex(bms_addr)} not reachable[/]")
        console.print("Try a different BMS address or run taycan_scan.py --discover first.")
    except TimeoutError:
        console.print(f"\n[red]Timeout connecting to {ip}[/]")
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/]")


if __name__ == "__main__":
    main()
