#!/usr/bin/env python3
"""
Taycan DoIP Diagnostic Tool — Read Standard DIDs

Milestone 3: Read VIN and basic ECU identification data.

Connects to the DoIP gateway and reads standard UDS Data Identifiers
from a target ECU (default: gateway itself).

Usage:
    python taycan_read.py --vin
    python taycan_read.py --ip 169.254.10.10 --ecu 0x1010 --all
    python taycan_read.py --ip 169.254.10.10 --ecu 0x1066 --did 0xF190
"""

import click
from rich.console import Console
from rich.panel import Panel

from doip_helpers import (
    uds_session,
    read_did_ascii,
    read_did_safe,
    display_ecu_info,
    format_hex,
)
import config

console = Console()


@click.command()
@click.option("--ip", default=config.GATEWAY_IP, help="Gateway IP address", show_default=True)
@click.option("--ecu", default="0x1010", help="Target ECU logical address (hex)", show_default=True)
@click.option("--vin", is_flag=True, help="Read VIN only (quick test)")
@click.option("--all", "read_all", is_flag=True, help="Read all standard identification DIDs")
@click.option("--did", multiple=True, help="Specific DID(s) to read (hex, e.g. 0xF190)")
def main(ip: str, ecu: str, vin: bool, read_all: bool, did: tuple):
    """Read standard UDS Data Identifiers from a Taycan ECU."""

    ecu_addr = int(ecu, 16) if ecu.startswith("0x") else int(ecu)
    ecu_name = config.KNOWN_ECUS.get(ecu_addr, ("?", "Unknown"))[0]

    console.print(
        Panel(
            f"[bold]Taycan ECU Reader[/bold]\n"
            f"Gateway: {ip}  |  ECU: {format_hex(ecu_addr)} ({ecu_name})",
            border_style="cyan",
        )
    )

    # Determine which DIDs to read
    dids_to_read = []

    if vin:
        dids_to_read = [0xF190]
    elif did:
        dids_to_read = [int(d, 16) if d.startswith("0x") else int(d) for d in did]
    elif read_all:
        dids_to_read = list(config.STANDARD_DIDS.keys())
    else:
        # Default: VIN + key identification DIDs
        dids_to_read = [0xF190, 0xF187, 0xF188, 0xF191, 0xF18C, 0xF197]

    # Connect and read
    try:
        with uds_session(gateway_ip=ip, ecu_address=ecu_addr) as (client, doip):
            results = {}

            for d in dids_to_read:
                did_name = config.STANDARD_DIDS.get(d, f"DID {format_hex(d)}")
                console.print(f"  [dim]Reading {format_hex(d)} ({did_name})...[/]", end="")

                raw = read_did_safe(client, d)
                if raw is not None:
                    # Try ASCII decode first, fall back to hex
                    if isinstance(raw, bytes):
                        try:
                            text = raw.decode("ascii").strip("\x00").strip()
                            if all(32 <= ord(c) < 127 for c in text) and len(text) > 0:
                                results[d] = text
                            else:
                                results[d] = raw.hex(" ")
                        except (UnicodeDecodeError, ValueError):
                            results[d] = raw.hex(" ")
                    else:
                        results[d] = str(raw)
                    console.print(f" [green]{results[d]}[/]")
                else:
                    results[d] = None
                    console.print(f" [dim]not supported[/]")

            # Pretty display
            console.print()
            display_ecu_info(ecu_addr, ecu_name, results)

            # Special VIN callout
            if 0xF190 in results and results[0xF190]:
                console.print(
                    f"\n[bold green]VIN: {results[0xF190]}[/bold green]"
                )

    except ConnectionRefusedError:
        console.print(f"\n[red]Connection refused by {ip}:{config.DOIP_PORT}[/]")
        console.print("Is the ignition ON and the ENET cable connected?")
    except TimeoutError:
        console.print(f"\n[red]Connection timed out to {ip}:{config.DOIP_PORT}[/]")
        console.print("Check network configuration and try discovery first.")
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/]")
        console.print("Run taycan_discover.py first to find the correct gateway IP.")


if __name__ == "__main__":
    main()
