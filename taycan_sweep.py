#!/usr/bin/env python3
"""
Taycan DoIP — Live DID Sweeper

Sweep any ECU for supported DIDs with live progress display.
Uses raw TCP sockets (no doipclient), supports extended session,
auto-detects the link-local interface, and saves results to JSON.

Usage:
    python taycan_sweep.py --ecu 0x407C                          # sweep 0x0100-0x2FFF
    python taycan_sweep.py --ecu 0x407C --start 0x0100 --end 0x0500
    python taycan_sweep.py --ecu 0x407C --extended                # extended session
    python taycan_sweep.py --ecu 0x407C --no-extended             # default session only
    python taycan_sweep.py --ecu 0x407C --output results.json
"""

import socket
import struct
import time
import json
import subprocess
import sys
import click


# ─── Constants ────────────────────────────────────────────────────────────

DOIP_VERSION = 0x02
DOIP_VERSION_INV = 0xFD
PAYLOAD_ROUTING_ACTIVATION_REQ = 0x0005
PAYLOAD_ROUTING_ACTIVATION_RESP = 0x0006
PAYLOAD_DIAGNOSTIC_MESSAGE = 0x8001
PAYLOAD_DIAGNOSTIC_POSITIVE_ACK = 0x8002
PAYLOAD_DIAGNOSTIC_NEGATIVE_ACK = 0x8003

GATEWAY_IP = "169.254.217.237"
GATEWAY_PORT = 13400
TESTER_ADDRESS = 0x0E80

# ANSI colors for terminal output
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[32m"
CYAN = "\033[36m"
YELLOW = "\033[33m"
RED = "\033[31m"
MAGENTA = "\033[35m"
BLUE = "\033[34m"


# ─── DoIP Protocol ────────────────────────────────────────────────────────

def build_header(payload_type: int, payload_length: int) -> bytes:
    return struct.pack(">BBHI", DOIP_VERSION, DOIP_VERSION_INV,
                       payload_type, payload_length)


def find_link_local_ip() -> str | None:
    """Find a 169.254.x.x IP on any active interface."""
    try:
        result = subprocess.run(["ifconfig"], capture_output=True,
                                text=True, timeout=5)
        for line in result.stdout.split("\n"):
            if "169.254." in line and "inet " in line:
                parts = line.strip().split()
                if "inet" in parts:
                    idx = parts.index("inet") + 1
                    if idx < len(parts):
                        return parts[idx]
    except Exception:
        pass
    return None


class Sweeper:
    def __init__(self, gateway_ip: str, tester_addr: int = 0x0E80):
        self.gateway_ip = gateway_ip
        self.tester_addr = tester_addr
        self.sock: socket.socket | None = None

    def connect(self) -> bool:
        local_ip = find_link_local_ip()
        if local_ip:
            print(f"  {DIM}Binding to {local_ip}{RESET}")

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(5)
        if local_ip:
            try:
                self.sock.bind((local_ip, 0))
            except OSError:
                pass

        try:
            self.sock.connect((self.gateway_ip, GATEWAY_PORT))
        except Exception as e:
            print(f"  {RED}TCP connect failed: {e}{RESET}")
            return False

        # Routing activation
        payload = struct.pack(">HB4s", self.tester_addr, 0x00, b"\x00" * 4)
        self.sock.sendall(build_header(PAYLOAD_ROUTING_ACTIVATION_REQ,
                                        len(payload)) + payload)
        try:
            resp = self.sock.recv(4096)
            if len(resp) >= 13 and resp[12] == 0x10:
                return True
        except Exception:
            pass
        return False

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    def send_uds(self, target: int, uds: bytes,
                 timeout: float = 0.5) -> bytes | None:
        if not self.sock:
            return None

        payload = struct.pack(">HH", self.tester_addr, target) + uds
        try:
            self.sock.sendall(build_header(PAYLOAD_DIAGNOSTIC_MESSAGE,
                                            len(payload)) + payload)
        except Exception:
            return None

        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                self.sock.settimeout(max(0.01, deadline - time.time()))
                data = self.sock.recv(4096)
                if len(data) < 8:
                    continue
                rtype = struct.unpack(">H", data[2:4])[0]
                if rtype == PAYLOAD_DIAGNOSTIC_NEGATIVE_ACK:
                    return None
                if rtype == PAYLOAD_DIAGNOSTIC_POSITIVE_ACK:
                    continue
                if rtype == PAYLOAD_DIAGNOSTIC_MESSAGE and len(data) >= 12:
                    resp = data[12:]
                    # Handle NRC 0x78 (request pending)
                    if (len(resp) >= 3 and resp[0] == 0x7F
                            and resp[2] == 0x78):
                        deadline = time.time() + timeout
                        continue
                    return resp
            except socket.timeout:
                break
            except Exception:
                break
        return None

    def tester_present(self, target: int, timeout: float = 0.3) -> bool:
        resp = self.send_uds(target, bytes([0x3E, 0x00]), timeout)
        return resp is not None and len(resp) >= 1 and resp[0] == 0x7E

    def change_session(self, target: int, session: int = 0x03,
                       timeout: float = 2.0) -> bool:
        resp = self.send_uds(target, bytes([0x10, session]), timeout)
        return resp is not None and len(resp) >= 1 and resp[0] == 0x50

    def read_did(self, target: int, did: int,
                 timeout: float = 0.5) -> bytes | None:
        uds = bytes([0x22, (did >> 8) & 0xFF, did & 0xFF])
        resp = self.send_uds(target, uds, timeout)
        if resp and len(resp) >= 3 and resp[0] == 0x62:
            return resp[3:]
        return None


# ─── Progress Display ────────────────────────────────────────────────────

def progress_bar(current: int, total: int, width: int = 30) -> str:
    pct = current / total if total > 0 else 0
    filled = int(width * pct)
    bar = "█" * filled + "░" * (width - filled)
    return f"[{GREEN}{bar}{RESET}] {pct * 100:5.1f}%"


def ascii_decode(raw: bytes) -> str | None:
    try:
        text = raw.decode("ascii", errors="replace").strip("\x00").strip()
        if text and all(32 <= ord(c) < 127 for c in text):
            return text
    except Exception:
        pass
    return None


def format_hit(did: int, raw: bytes, max_width: int = 50) -> str:
    hex_str = raw.hex(" ")
    if len(hex_str) > max_width:
        hex_str = hex_str[:max_width] + "..."
    ascii_str = ascii_decode(raw)
    ascii_part = f"  {DIM}→ {ascii_str}{RESET}" if ascii_str else ""
    return f"  {GREEN}✓{RESET} 0x{did:04X} {DIM}[{len(raw):2d}B]{RESET}: {hex_str}{ascii_part}"


# ─── Main Sweep ──────────────────────────────────────────────────────────

@click.command()
@click.option("--ecu", required=True, help="Target ECU address (hex, e.g. 0x407C)")
@click.option("--ip", default=GATEWAY_IP, show_default=True,
              help="Gateway IP address")
@click.option("--start", default="0x0100", show_default=True,
              help="Start DID (hex)")
@click.option("--end", default="0x2FFF", show_default=True,
              help="End DID (hex)")
@click.option("--extended/--no-extended", default=True,
              help="Use extended diagnostic session (0x10 0x03)")
@click.option("--timeout", default=0.3, show_default=True,
              help="DID read timeout (seconds)")
@click.option("--output", "-o", default=None,
              help="Save results to JSON file")
@click.option("--quiet", is_flag=True, help="Hide live hits, show only summary")
def main(ecu, ip, start, end, extended, timeout, output, quiet):
    """Sweep an ECU for supported DIDs with live progress."""

    ecu_addr = int(ecu, 16)
    start_did = int(start, 16)
    end_did = int(end, 16)
    total = end_did - start_did + 1

    print(f"\n{BOLD}{CYAN}Taycan DID Sweeper{RESET}")
    print(f"  ECU:      {BOLD}0x{ecu_addr:04X}{RESET}")
    print(f"  Gateway:  {ip}")
    print(f"  Range:    0x{start_did:04X} → 0x{end_did:04X}  ({total} DIDs)")
    print(f"  Session:  {'extended (0x03)' if extended else 'default (0x01)'}")
    print(f"  Timeout:  {timeout}s")
    print()

    # Connect
    print(f"{CYAN}Connecting to gateway...{RESET}")
    sweep = Sweeper(ip)
    if not sweep.connect():
        print(f"{RED}Connection failed{RESET}")
        sys.exit(1)
    print(f"  {GREEN}✓ Routing activation accepted{RESET}")

    # Probe the ECU
    print(f"{CYAN}Probing ECU 0x{ecu_addr:04X}...{RESET}")
    if not sweep.tester_present(ecu_addr, timeout=1.0):
        print(f"  {RED}✗ ECU not responding{RESET}")
        sweep.close()
        sys.exit(1)
    print(f"  {GREEN}✓ ECU is alive{RESET}")

    # Switch session
    if extended:
        print(f"{CYAN}Switching to extended session...{RESET}")
        if sweep.change_session(ecu_addr, session=0x03):
            print(f"  {GREEN}✓ Extended session active{RESET}")
        else:
            print(f"  {YELLOW}⚠ Extended session failed, using default{RESET}")

    # Sweep
    print(f"\n{BOLD}Sweeping...{RESET}")
    start_time = time.time()
    hits = {}
    last_progress_update = time.time()

    for i, did in enumerate(range(start_did, end_did + 1)):
        # Progress bar (update max every 50ms to avoid flicker)
        now = time.time()
        if now - last_progress_update > 0.05 or i == total - 1:
            elapsed = now - start_time
            rate = (i + 1) / elapsed if elapsed > 0 else 0
            eta = (total - i - 1) / rate if rate > 0 else 0
            bar = progress_bar(i + 1, total)
            status = (f"\r  {bar}  0x{did:04X}  "
                      f"{CYAN}{len(hits)}{RESET} hits  "
                      f"{DIM}{rate:.0f}/s  ETA {eta:.0f}s{RESET}   ")
            sys.stdout.write(status)
            sys.stdout.flush()
            last_progress_update = now

        raw = sweep.read_did(ecu_addr, did, timeout=timeout)
        if raw is not None:
            hits[did] = raw
            if not quiet:
                # Clear progress line and print hit
                sys.stdout.write("\r" + " " * 100 + "\r")
                sys.stdout.flush()
                print(format_hit(did, raw))

        # Keep-alive every 500 DIDs
        if (i + 1) % 500 == 0:
            sweep.tester_present(ecu_addr, timeout=0.2)

    elapsed = time.time() - start_time

    # Final clear
    sys.stdout.write("\r" + " " * 100 + "\r")
    sys.stdout.flush()

    sweep.close()

    # Summary
    print()
    print(f"{BOLD}Sweep complete{RESET}")
    print(f"  Duration:     {elapsed:.1f}s")
    print(f"  DIDs tested:  {total}")
    print(f"  Hits:         {GREEN}{len(hits)}{RESET}")
    print(f"  Hit rate:     {len(hits) / total * 100:.1f}%")

    # Categorize hits
    if hits:
        single_byte = [d for d, r in hits.items() if len(r) == 1]
        two_byte = [d for d, r in hits.items() if len(r) == 2]
        ascii_hits = [d for d, r in hits.items() if ascii_decode(r)]
        large = [d for d, r in hits.items() if len(r) > 20]

        print()
        print(f"  {DIM}Single-byte values: {len(single_byte)}{RESET}")
        print(f"  {DIM}Two-byte values:    {len(two_byte)}{RESET}")
        print(f"  {DIM}ASCII strings:      {len(ascii_hits)}{RESET}")
        print(f"  {DIM}Large blocks (>20B): {len(large)}{RESET}")

        # Flag interesting single-byte values that look like percentages
        print()
        print(f"{BOLD}Percentage candidates (80-100):{RESET}")
        found_pct = False
        for did, raw in sorted(hits.items()):
            if len(raw) == 1 and 80 <= raw[0] <= 100:
                print(f"  {YELLOW}★{RESET} 0x{did:04X} = {raw[0]}")
                found_pct = True
        if not found_pct:
            print(f"  {DIM}(none){RESET}")

    # Save JSON
    if output:
        export = {
            "ecu": f"0x{ecu_addr:04X}",
            "gateway_ip": ip,
            "start_did": f"0x{start_did:04X}",
            "end_did": f"0x{end_did:04X}",
            "extended_session": extended,
            "duration_s": round(elapsed, 2),
            "hit_count": len(hits),
            "hits": {
                f"0x{did:04X}": {
                    "hex": raw.hex(),
                    "size": len(raw),
                    "ascii": ascii_decode(raw),
                }
                for did, raw in sorted(hits.items())
            },
        }
        with open(output, "w") as f:
            json.dump(export, f, indent=2)
        print(f"\n{DIM}Results saved to {output}{RESET}")


if __name__ == "__main__":
    main()
