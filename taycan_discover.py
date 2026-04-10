#!/usr/bin/env python3
"""
Taycan DoIP Diagnostic Tool — Gateway Discovery

Milestone 1 & 2: Discover the DoIP gateway on the Taycan's ENET interface.

Sends a DoIP Vehicle Identification Request via UDP broadcast and
displays any responding gateways with their VIN, logical address,
and IP.

Usage:
    python taycan_discover.py
    python taycan_discover.py --timeout 5
    python taycan_discover.py --interface en6
"""

import subprocess
import sys
import click
from rich.console import Console
from rich.panel import Panel

from doip_helpers import discover_gateway, display_discovery_results
import config

console = Console()


def check_interface_config(interface: str | None):
    """Show current network interface configuration for debugging."""
    console.print("\n[bold]Network Interface Check[/bold]")

    if sys.platform == "darwin":
        try:
            result = subprocess.run(
                ["ifconfig"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            lines = result.stdout.split("\n")

            # Find ethernet interfaces with 169.254.x.x addresses
            current_iface = None
            found_link_local = False

            for line in lines:
                if not line.startswith("\t") and ":" in line:
                    current_iface = line.split(":")[0]
                if "169.254." in line and "inet" in line:
                    console.print(
                        f"  [green]✓ {current_iface}: {line.strip()}[/]"
                    )
                    found_link_local = True

            if not found_link_local:
                console.print(
                    "[yellow]  ⚠ No interface found with 169.254.x.x address[/]"
                )
                console.print(
                    f"  Configure with: sudo ifconfig <iface> inet {config.LOCAL_IP} "
                    f"netmask 255.255.0.0 up"
                )
                console.print(
                    "  Find your adapter: networksetup -listallhardwareports"
                )
        except Exception as e:
            console.print(f"[red]  Could not check interfaces: {e}[/]")
    else:
        console.print("  [dim](interface check only implemented for macOS)[/]")


@click.command()
@click.option(
    "--timeout", "-t",
    default=config.UDP_TIMEOUT,
    help="Discovery timeout in seconds",
    show_default=True,
)
@click.option(
    "--broadcast", "-b",
    default=config.BROADCAST_IP,
    help="Broadcast address for discovery",
    show_default=True,
)
@click.option(
    "--interface", "-i",
    default=None,
    help="Network interface name (for diagnostics only)",
)
@click.option(
    "--raw", is_flag=True,
    help="Show raw hex response data",
)
def main(timeout: float, broadcast: str, interface: str | None, raw: bool):
    """Discover DoIP gateways on the local network."""

    console.print(
        Panel(
            "[bold]Taycan DoIP Gateway Discovery[/bold]\n"
            "Sending Vehicle Identification Request via UDP broadcast...",
            border_style="cyan",
        )
    )

    check_interface_config(interface)
    console.print()

    discoveries = discover_gateway(timeout=timeout, broadcast_ip=broadcast)

    if discoveries:
        display_discovery_results(discoveries)

        if raw:
            console.print("\n[bold]Raw Response Data:[/bold]")
            for gw in discoveries:
                console.print(f"  {gw.get('ip', '?')}: {gw.get('raw_hex', '?')}")

        # Print next-steps summary
        gw = discoveries[0]
        ip = gw.get("ip", "?.?.?.?")
        addr = gw.get("logical_address", 0x1010)

        console.print(f"\n[bold green]Gateway found![/bold green]")
        console.print(f"Update config.py with:")
        console.print(f'  GATEWAY_IP = "{ip}"')
        console.print(f"\nNext steps:")
        console.print(f"  python taycan_read.py --ip {ip} --vin")
        console.print(f"  python taycan_scan.py --ip {ip}")
        console.print(f"  python taycan_battery.py --ip {ip}")
    else:
        console.print("\n[bold yellow]No gateways found.[/bold yellow]")
        console.print("\nTroubleshooting:")
        console.print("  1. Is the ENET cable plugged into the OBD-II port?")
        console.print("  2. Is the ignition turned ON (not just accessories)?")
        console.print("  3. Is your Ethernet adapter configured with a 169.254.x.x IP?")
        console.print("  4. Try a different broadcast address: --broadcast 169.254.255.255")
        console.print("  5. Check with Wireshark on the ENET interface for any traffic")


if __name__ == "__main__":
    main()
