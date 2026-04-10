"""
Taycan DoIP Diagnostic Tool — Connection Helpers

Shared utilities for establishing DoIP connections, managing UDS sessions,
and formatting diagnostic data.
"""

import socket
import struct
import time
from contextlib import contextmanager
from typing import Optional

from rich.console import Console
from rich.table import Table

try:
    from doipclient import DoIPClient
    from doipclient.connectors import DoIPClientUDSConnector
    from udsoncan.client import Client as UDSClient
    from udsoncan.exceptions import (
        NegativeResponseException,
        InvalidResponseException,
        UnexpectedResponseException,
        TimeoutException,
    )
    from udsoncan.services import DiagnosticSessionControl
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("Run: pip install -r requirements.txt")
    raise SystemExit(1)

from udsoncan import DidCodec

import config

console = Console()


# ─── Dynamic DID Codec (accept any DID without pre-registration) ──────────

class _RawCodec(DidCodec):
    """Pass-through codec that returns raw bytes for any DID."""
    def decode(self, payload):
        return payload
    def encode(self, value):
        return value
    def __len__(self):
        return 0

class _AnyDidDict(dict):
    """Dict-like that claims to contain every integer DID, returning a raw codec."""
    def __contains__(self, key):
        return isinstance(key, int)
    def __getitem__(self, key):
        if isinstance(key, int):
            return _RawCodec()
        raise KeyError(key)
    def __missing__(self, key):
        if isinstance(key, int):
            return _RawCodec()
        raise KeyError(key)


# ─── DoIP Protocol Constants ────────────────────────────────────────────────

DOIP_VERSION = 0x02
DOIP_VERSION_INV = 0xFD

# Payload types
DOIP_VEHICLE_ID_REQUEST = 0x0001
DOIP_VEHICLE_ID_RESPONSE = 0x0004
DOIP_ROUTING_ACTIVATION_REQUEST = 0x0005
DOIP_ROUTING_ACTIVATION_RESPONSE = 0x0006
DOIP_DIAGNOSTIC_MESSAGE = 0x8001
DOIP_DIAGNOSTIC_ACK = 0x8002
DOIP_DIAGNOSTIC_NACK = 0x8003


# ─── Raw DoIP Discovery (UDP) ───────────────────────────────────────────────

def build_doip_header(payload_type: int, payload: bytes = b"") -> bytes:
    """Build a DoIP generic header (8 bytes) + payload."""
    header = struct.pack(
        ">BBHI",
        DOIP_VERSION,
        DOIP_VERSION_INV,
        payload_type,
        len(payload),
    )
    return header + payload


def parse_vehicle_id_response(data: bytes) -> dict:
    """
    Parse a DoIP Vehicle Identification Response (payload type 0x0004).

    Response structure (after 8-byte header):
      - VIN: 17 bytes (ASCII)
      - Logical Address: 2 bytes (uint16 big-endian)
      - EID (Entity ID / MAC): 6 bytes
      - GID (Group ID): 6 bytes
      - Further Action Required: 1 byte
      - VIN/GID Sync Status: 1 byte (optional)
    """
    if len(data) < 8:
        return {"error": "Response too short"}

    # Skip 8-byte DoIP header
    payload = data[8:]

    result = {}
    if len(payload) >= 17:
        result["vin"] = payload[0:17].decode("ascii", errors="replace")
    if len(payload) >= 19:
        result["logical_address"] = struct.unpack(">H", payload[17:19])[0]
    if len(payload) >= 25:
        result["eid"] = payload[19:25].hex(":")
    if len(payload) >= 31:
        result["gid"] = payload[25:31].hex(":")
    if len(payload) >= 32:
        result["further_action"] = payload[31]
    if len(payload) >= 33:
        result["sync_status"] = payload[32]

    return result


def discover_gateway(
    timeout: float = config.UDP_TIMEOUT,
    broadcast_ip: str = config.BROADCAST_IP,
) -> list[dict]:
    """
    Send a DoIP Vehicle Identification Request via UDP broadcast and
    collect all responses. Returns a list of discovered gateways.
    """
    request = build_doip_header(DOIP_VEHICLE_ID_REQUEST)
    discoveries = []

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(timeout)

    try:
        sock.sendto(request, (broadcast_ip, config.DOIP_PORT))
        console.print(
            f"[cyan]→ Sent DoIP Vehicle ID Request to {broadcast_ip}:{config.DOIP_PORT}[/]"
        )

        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
                info = parse_vehicle_id_response(data)
                info["ip"] = addr[0]
                info["raw_hex"] = data.hex()
                discoveries.append(info)
                console.print(f"[green]← Response from {addr[0]}[/]")
            except socket.timeout:
                break
    finally:
        sock.close()

    return discoveries


# ─── DoIP Client Connection ─────────────────────────────────────────────────

def create_doip_client(
    gateway_ip: str = config.GATEWAY_IP,
    ecu_address: int = 0x1010,
    tester_address: int = config.TESTER_ADDRESS,
    timeout: float = config.TCP_TIMEOUT,
) -> DoIPClient:
    """Create and return a DoIPClient with routing activation."""
    console.print(
        f"[cyan]Connecting to gateway {gateway_ip}:{config.DOIP_PORT} "
        f"(ECU 0x{ecu_address:04X}, tester 0x{tester_address:04X})...[/]"
    )
    client = DoIPClient(
        gateway_ip,
        ecu_address,
        client_logical_address=tester_address,
        tcp_port=config.DOIP_PORT,
        activation_type=0x00,  # Default routing activation
    )
    console.print("[green]✓ DoIP connection established, routing activated[/]")
    return client


@contextmanager
def uds_session(
    gateway_ip: str = config.GATEWAY_IP,
    ecu_address: int = 0x1010,
    tester_address: int = config.TESTER_ADDRESS,
    session_type: Optional[int] = None,
):
    """
    Context manager for a UDS session over DoIP.

    Usage:
        with uds_session(ecu_address=0x1066) as (client, doip):
            resp = client.read_data_by_identifier(0xF190)
    """
    doip = create_doip_client(gateway_ip, ecu_address, tester_address)
    conn = DoIPClientUDSConnector(doip)

    uds_config = {
        "request_timeout": config.UDS_REQUEST_TIMEOUT,
        "p2_timeout": 1.5,
        "p2_star_timeout": 5.0,
        "data_identifiers": _AnyDidDict(),
    }

    try:
        with UDSClient(conn, config=uds_config) as client:
            if session_type is not None:
                console.print(
                    f"[cyan]Switching to session 0x{session_type:02X}...[/]"
                )
                client.change_session(session_type)
                console.print("[green]✓ Session changed[/]")
            yield client, doip
    finally:
        try:
            doip.close()
        except Exception:
            pass


# ─── UDS Helpers ─────────────────────────────────────────────────────────────

def read_did_safe(client: UDSClient, did: int) -> Optional[bytes]:
    """
    Read a DID, returning the raw bytes on success or None on failure.
    Silently handles negative responses (DID not supported, etc).
    """
    try:
        resp = client.read_data_by_identifier(did)
        if resp.valid and resp.positive:
            return resp.service_data.values.get(did)
    except NegativeResponseException:
        return None
    except (InvalidResponseException, UnexpectedResponseException):
        return None
    except (TimeoutException, Exception):
        return None
    return None


def read_did_ascii(client: UDSClient, did: int) -> Optional[str]:
    """Read a DID and decode as ASCII string."""
    data = read_did_safe(client, did)
    if data is not None:
        if isinstance(data, bytes):
            return data.decode("ascii", errors="replace").strip("\x00").strip()
        return str(data)
    return None


def read_did_uint(client: UDSClient, did: int, scale: float = 1.0) -> Optional[float]:
    """Read a DID and interpret as unsigned integer with optional scaling."""
    data = read_did_safe(client, did)
    if data is not None:
        if isinstance(data, bytes):
            value = int.from_bytes(data, byteorder="big", signed=False)
            return value * scale
        return float(data) * scale
    return None


def read_did_int(client: UDSClient, did: int, scale: float = 1.0) -> Optional[float]:
    """Read a DID and interpret as signed integer with optional scaling."""
    data = read_did_safe(client, did)
    if data is not None:
        if isinstance(data, bytes):
            value = int.from_bytes(data, byteorder="big", signed=True)
            return value * scale
        return float(data) * scale
    return None


# ─── Display Helpers ─────────────────────────────────────────────────────────

def format_hex(value: int, width: int = 4) -> str:
    """Format an integer as a hex string with '0x' prefix."""
    return f"0x{value:0{width}X}"


def display_discovery_results(discoveries: list[dict]):
    """Pretty-print DoIP discovery results."""
    if not discoveries:
        console.print("[yellow]No DoIP gateways found.[/]")
        console.print(
            "[dim]Check: cable connected, ignition ON, "
            "Ethernet interface configured in 169.254.x.x range[/]"
        )
        return

    table = Table(title="DoIP Gateway Discovery", show_lines=True)
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="white")

    for i, gw in enumerate(discoveries):
        if i > 0:
            table.add_row("─" * 20, "─" * 40)
        table.add_row("IP Address", gw.get("ip", "?"))
        table.add_row("VIN", gw.get("vin", "?"))
        table.add_row(
            "Logical Address",
            format_hex(gw["logical_address"]) if "logical_address" in gw else "?",
        )
        table.add_row("Entity ID (MAC)", gw.get("eid", "?"))
        table.add_row("Group ID", gw.get("gid", "?"))
        action = gw.get("further_action", "?")
        if action == 0x00:
            table.add_row("Further Action", "None required")
        elif action == 0x10:
            table.add_row("Further Action", "Routing activation required")
        else:
            table.add_row("Further Action", str(action))

    console.print(table)


def display_ecu_info(address: int, name: str, dids: dict[int, Optional[str]]):
    """Pretty-print DID values read from an ECU."""
    table = Table(title=f"ECU: {name} ({format_hex(address)})")
    table.add_column("DID", style="cyan", width=8)
    table.add_column("Name", style="white")
    table.add_column("Value", style="green")

    for did, value in dids.items():
        did_name = config.STANDARD_DIDS.get(did, config.BATTERY_DIDS.get(did, "?"))
        table.add_row(
            format_hex(did),
            did_name,
            str(value) if value is not None else "[dim]—[/]",
        )

    console.print(table)
