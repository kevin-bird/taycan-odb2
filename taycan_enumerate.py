#!/usr/bin/env python3
"""
Taycan DoIP Diagnostic Tool — DID Enumerator

Research tool for discovering which Data Identifiers (DIDs) an ECU supports.
Sweeps a range of DID addresses and logs all positive responses.

This is the key tool for reverse engineering — once you find which DIDs
respond, you can decode the payloads by comparing with known values
(odometer reading, voltage on the dashboard, etc).

Usage:
    python taycan_enumerate.py --ecu 0x1066
    python taycan_enumerate.py --ecu 0x1066 --start 0x0200 --end 0x0400
    python taycan_enumerate.py --ecu 0x1066 --start 0xF100 --end 0xF1FF
    python taycan_enumerate.py --ecu 0x1010 --extended --output gateway_dids.json

Tips:
    - Start with the standard range (0xF100–0xF1FF) to verify connectivity
    - Then sweep manufacturer ranges (0x0100–0x1FFF) for vehicle-specific data
    - Use --extended flag for DIDs only available in extended diagnostic session
    - Compare raw bytes with known values to decode the encoding
    - Run with Wireshark capturing to see the full UDS exchange
"""

import json
import time
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn

from doip_helpers import uds_session, read_did_safe, format_hex
import config

console = Console()


@click.command()
@click.option("--ip", default=config.GATEWAY_IP, help="Gateway IP", show_default=True)
@click.option("--ecu", required=True, help="Target ECU address (hex, e.g. 0x1066)")
@click.option("--start", default="0xF100", help="Start DID (hex)", show_default=True)
@click.option("--end", default="0xF1FF", help="End DID (hex)", show_default=True)
@click.option("--extended", is_flag=True, help="Use extended diagnostic session")
@click.option("--output", "-o", default=None, help="Save results to JSON file")
@click.option("--delay", default=0.05, help="Delay between requests (seconds)", show_default=True)
@click.option("--verbose", "-v", is_flag=True, help="Print each DID as it's tested")
def main(
    ip: str,
    ecu: str,
    start: str,
    end: str,
    extended: bool,
    output: str | None,
    delay: float,
    verbose: bool,
):
    """Enumerate supported DIDs on a Taycan ECU."""

    ecu_addr = int(ecu, 16) if ecu.startswith("0x") else int(ecu)
    start_did = int(start, 16) if start.startswith("0x") else int(start)
    end_did = int(end, 16) if end.startswith("0x") else int(end)
    session_type = 0x03 if extended else None

    # Look up ECU name — try KNOWN_ECUS (legacy) or VEHICLE_ECUS (new format)
    if hasattr(config, "KNOWN_ECUS"):
        ecu_info = config.KNOWN_ECUS.get(ecu_addr, ("?", "Unknown"))
    else:
        # VEHICLE_ECUS is keyed by VAG code, not DoIP address — just show address
        ecu_info = ("?", f"ECU at {format_hex(ecu_addr)}")
    total = end_did - start_did + 1

    console.print(
        Panel(
            f"[bold]Taycan DID Enumerator[/bold]\n"
            f"ECU: {format_hex(ecu_addr)} ({ecu_info[0]} — {ecu_info[1]})\n"
            f"Range: {format_hex(start_did)} → {format_hex(end_did)} ({total} DIDs)\n"
            f"Session: {'extended (0x03)' if extended else 'default (0x01)'}",
            border_style="magenta",
        )
    )

    found = {}
    tested = 0
    start_time = time.time()

    try:
        with uds_session(
            gateway_ip=ip,
            ecu_address=ecu_addr,
            session_type=session_type,
        ) as (client, doip):

            console.print(f"\n[cyan]Enumerating {total} DIDs...[/]\n")

            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TextColumn("•"),
                TextColumn("[green]{task.fields[found_count]} found"),
                TimeRemainingColumn(),
                console=console,
            ) as progress:
                task = progress.add_task(
                    "Scanning",
                    total=total,
                    found_count=0,
                )

                for did in range(start_did, end_did + 1):
                    if verbose:
                        progress.update(
                            task,
                            description=f"Testing {format_hex(did)}",
                        )

                    raw = read_did_safe(client, did)
                    tested += 1

                    if raw is not None:
                        if isinstance(raw, bytes):
                            hex_str = raw.hex(" ")
                            # Also try ASCII decode
                            try:
                                ascii_str = raw.decode("ascii").strip("\x00").strip()
                                if not all(32 <= ord(c) < 127 for c in ascii_str):
                                    ascii_str = None
                            except (UnicodeDecodeError, ValueError):
                                ascii_str = None
                        else:
                            hex_str = str(raw)
                            ascii_str = str(raw)

                        known_name = config.BATTERY_DIDS.get(
                            did, config.STANDARD_DIDS.get(did, None)
                        )

                        found[did] = {
                            "hex": hex_str,
                            "ascii": ascii_str,
                            "bytes": len(raw) if isinstance(raw, bytes) else 0,
                            "known_name": known_name,
                        }

                        # Print discovery inline
                        label = f" [{known_name}]" if known_name else ""
                        console.print(
                            f"  [green]✓ {format_hex(did)}{label}: "
                            f"{hex_str[:60]}"
                            f"{f' → {ascii_str}' if ascii_str else ''}[/]"
                        )

                    progress.update(
                        task,
                        advance=1,
                        found_count=len(found),
                    )

                    if delay > 0:
                        time.sleep(delay)

    except ConnectionRefusedError:
        console.print(f"\n[red]Connection refused to {format_hex(ecu_addr)}[/]")
        return
    except KeyboardInterrupt:
        console.print(f"\n[yellow]Interrupted at {format_hex(start_did + tested)}[/]")
    except Exception as e:
        console.print(f"\n[red]Error at DID {format_hex(start_did + tested)}: {e}[/]")

    elapsed = time.time() - start_time

    # Results table
    console.print(f"\n[bold]Results: {len(found)} DIDs found in {elapsed:.1f}s[/]\n")

    if found:
        table = Table(title=f"Supported DIDs — {ecu_info[0]} ({format_hex(ecu_addr)})")
        table.add_column("DID", style="cyan", width=8)
        table.add_column("Known Name", style="white", max_width=35)
        table.add_column("Size", style="dim", justify="right", width=5)
        table.add_column("Raw Hex", style="green")
        table.add_column("ASCII", style="yellow")

        for did in sorted(found.keys()):
            entry = found[did]
            table.add_row(
                format_hex(did),
                entry["known_name"] or "—",
                f"{entry['bytes']}B",
                entry["hex"][:40] + ("..." if len(entry["hex"]) > 40 else ""),
                entry["ascii"] or "—",
            )

        console.print(table)

    # Save to file
    if output and found:
        export = {
            "ecu_address": format_hex(ecu_addr),
            "ecu_name": ecu_info[0],
            "scan_range": f"{format_hex(start_did)}-{format_hex(end_did)}",
            "session": "extended" if extended else "default",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "dids": {
                format_hex(did): {
                    "hex": entry["hex"],
                    "ascii": entry["ascii"],
                    "bytes": entry["bytes"],
                    "known_name": entry["known_name"],
                }
                for did, entry in sorted(found.items())
            },
        }
        with open(output, "w") as f:
            json.dump(export, f, indent=2)
        console.print(f"\n[dim]Results saved to {output}[/]")

    # Suggest next steps
    if found:
        console.print("\n[bold]Next Steps:[/bold]")
        console.print("  1. Compare raw values with known readings (dashboard, app)")
        console.print("  2. Try --extended flag if you haven't already")
        console.print("  3. Decode multi-byte values: big-endian, scaling factors")
        console.print("  4. Add confirmed DIDs to config.py BATTERY_DIDS")
    else:
        console.print("\n[yellow]No DIDs found in this range.[/yellow]")
        console.print("  Try: --extended (some DIDs need elevated session)")
        console.print("  Try: different --start/--end ranges")
        console.print("  Try: different --ecu address (run taycan_scan.py --discover)")


if __name__ == "__main__":
    main()
