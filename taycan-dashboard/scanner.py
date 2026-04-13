"""
Taycan Dashboard — Scan Orchestration

Connects to the gateway, reads all ECUs, decodes battery data,
saves results to timestamped JSON files.
"""

import json
import os
import time
from datetime import datetime
from typing import Optional

from doip import DoIPConnection, discover_gateway
import config


SCANS_DIR = os.path.join(os.path.dirname(__file__), "scans")
FAULT_CODES_PATH = os.path.join(os.path.dirname(__file__), "fault_codes.json")

# Load fault code database
_fault_db = {}
_obc_benign = set()
_diagnostic_tips = []
_recalls = {}

def _load_fault_db():
    global _fault_db, _obc_benign, _diagnostic_tips, _recalls
    try:
        with open(FAULT_CODES_PATH) as f:
            data = json.load(f)
        _fault_db = data.get("fault_codes", {})
        _obc_benign = set(data.get("obc_benign_codes", []))
        _diagnostic_tips = data.get("diagnostic_tips", [])
        _recalls = data.get("recalls", {})
    except (FileNotFoundError, json.JSONDecodeError):
        pass

_load_fault_db()


def lookup_dtc(code: str) -> Optional[dict]:
    """Look up a DTC code in the fault database."""
    # Try exact match first, then uppercase, then with/without trailing zeros
    for key in [code, code.upper(), code.rstrip("0") or code]:
        if key in _fault_db:
            return _fault_db[key]
    return None


def _read_powertrain_ecu(conn, addr: int) -> dict:
    """
    Read the interesting DIDs for a powertrain ECU (inverter/OBC/DC-DC/HV Booster).
    Returns dict of {did_int: raw_bytes}. Never raises — returns {} on failure.
    """
    if addr in (0x407C, 0x40B8):
        dids = config.INVERTER_DIDS
    elif addr == 0x4044:
        dids = config.OBC_DIDS
    elif addr == 0x40B7:
        dids = config.DCDC_DIDS
    elif addr == 0x40C7:
        dids = config.HV_BOOSTER_DIDS
    else:
        return {}

    raw_dids = {}
    try:
        # Try extended session for better data; fall back to default if it fails
        conn.change_session(addr, session=0x03, timeout=1.5)
        for did in dids:
            raw = conn.read_did(addr, did, timeout=0.8)
            if raw is not None:
                raw_dids[did] = raw
        # Always return to default session, ignore result
        conn.change_session(addr, session=0x01, timeout=1.5)
    except Exception:
        pass
    return raw_dids


def ensure_scans_dir():
    os.makedirs(SCANS_DIR, exist_ok=True)


def auto_discover(progress_callback=None) -> Optional[dict]:
    """
    Auto-discover the DoIP gateway via UDP broadcast.
    Updates config module globals if found.
    Returns gateway info dict or None.
    """
    if progress_callback:
        progress_callback(0, 0, "Discovering gateway...")

    gw = discover_gateway(timeout=3.0)
    if gw is None:
        # Try the narrower subnet broadcast
        gw = discover_gateway(broadcast_ip="169.254.255.255", timeout=3.0)

    if gw:
        config.GATEWAY_IP = gw["ip"]
        if gw.get("vin"):
            config.VEHICLE_VIN = gw["vin"]
        if gw.get("logical_address"):
            config.GATEWAY_LOGICAL_ADDRESS = gw["logical_address"]

    return gw


def run_scan(gateway_ip: str = None,
             ecu_registry: list[dict] = None,
             progress_callback=None) -> dict:
    """
    Run a full diagnostic scan of all ECUs.
    Auto-discovers the gateway if no IP is provided or the default is a placeholder.

    progress_callback(current, total, message) is called during scan
    for live progress updates.

    Returns the complete scan result dict.
    """
    # Auto-discover gateway if needed
    if gateway_ip is None or gateway_ip == "169.254.10.10":
        gw = auto_discover(progress_callback)
        if gw:
            gateway_ip = gw["ip"]
        elif gateway_ip is None:
            gateway_ip = config.GATEWAY_IP

    if ecu_registry is None:
        ecu_registry = config.load_ecu_registry()

    scan_start = time.time()
    timestamp = datetime.now().isoformat(timespec="seconds")

    result = {
        "timestamp": timestamp,
        "vin": config.VEHICLE_VIN,
        "model": config.VEHICLE_MODEL,
        "year": config.VEHICLE_YEAR,
        "gateway_ip": gateway_ip,
        "scan_duration_ms": 0,
        "connection_ok": False,
        "battery": None,
        "powertrain": None,
        "ecus": [],
        "summary": {
            "ecus_scanned": len(ecu_registry),
            "ecus_reachable": 0,
            "ecus_with_dtcs": 0,
            "total_dtcs": 0,
        },
    }

    # Connect
    conn = DoIPConnection(gateway_ip, config.DOIP_PORT,
                          config.TESTER_ADDRESS, config.TCP_TIMEOUT)
    try:
        conn.connect()
        result["connection_ok"] = True
    except ConnectionError as e:
        result["error"] = str(e)
        result["scan_duration_ms"] = int((time.time() - scan_start) * 1000)
        return result

    try:
        total = len(ecu_registry)
        reachable = 0
        with_dtcs = 0
        total_dtc_count = 0

        for idx, ecu in enumerate(ecu_registry):
            addr = ecu["doip_address"]
            name = ecu["name"]

            if progress_callback:
                progress_callback(idx + 1, total,
                                  f"Scanning {name} (0x{addr:04X})")

            ecu_result = {
                "doip_address": f"0x{addr:04X}",
                "name": name,
                "asam_id": ecu.get("asam_id", ""),
                "reachable": False,
                "sw_number": None,
                "sw_version": None,
                "hw_number": None,
                "hw_version": None,
                "serial": None,
                "vin": None,
                "system_name": None,
                "workshop_id": None,
                "fazit": None,
                "mfg_date": None,
                "dtcs": [],
            }

            # Probe with TesterPresent
            if not conn.tester_present(addr, config.TESTER_PRESENT_TIMEOUT):
                result["ecus"].append(ecu_result)
                continue

            ecu_result["reachable"] = True
            reachable += 1

            # Read identity DIDs
            for did, did_name in config.IDENTITY_DIDS.items():
                raw = conn.read_did(addr, did, config.UDS_TIMEOUT)
                if raw is None:
                    continue

                try:
                    text = raw.decode("ascii", errors="replace").strip("\x00").strip()
                    if not all(32 <= ord(c) < 127 for c in text):
                        text = raw.hex(" ")
                except Exception:
                    text = raw.hex(" ")

                if did == 0xF187:
                    ecu_result["sw_number"] = text
                elif did == 0xF189:
                    ecu_result["sw_version"] = text
                elif did == 0xF191:
                    ecu_result["hw_number"] = text
                elif did == 0xF18C:
                    ecu_result["serial"] = text
                elif did == 0xF190:
                    if len(text) == 17:
                        ecu_result["vin"] = text
                elif did == 0xF197:
                    ecu_result["system_name"] = text
                elif did == 0xF19E:
                    ecu_result["asam_id"] = text
                elif did == 0xF1A3:
                    ecu_result["hw_version"] = text
                elif did == 0xF1AA:
                    ecu_result["workshop_id"] = text
                elif did == 0xF17C:
                    ecu_result["fazit"] = text
                elif did == 0xF18B:
                    ecu_result["mfg_date"] = config.decode_mfg_date(raw)

            # Read DTCs and enrich with fault code descriptions
            dtcs = conn.read_dtcs(addr, 0xFF, config.DTC_TIMEOUT)
            for dtc in dtcs:
                info = lookup_dtc(dtc["code"])
                if info:
                    dtc["description"] = info.get("description", "")
                    dtc["severity"] = info.get("severity", "")
                    dtc["notes"] = info.get("notes", "")
                    dtc["source"] = info.get("source", "")
            ecu_result["dtcs"] = dtcs
            fault_count = sum(1 for d in dtcs if d.get("is_fault"))
            if fault_count > 0:
                with_dtcs += 1
                total_dtc_count += fault_count

            # Battery DIDs (BECM only)
            if addr == config.BECM_ADDRESS:
                battery_raw = {}

                # Read default-session battery DIDs
                for did in config.BATTERY_DIDS:
                    raw = conn.read_did(addr, did, config.UDS_TIMEOUT)
                    battery_raw[did] = raw

                # Switch to extended session for cell-level data
                if conn.change_session(addr, session=0x03, timeout=2.0):
                    if progress_callback:
                        progress_callback(idx + 1, total,
                                          f"Reading cell data (extended session)")

                    # BMS current limits (dynamic/predicted discharge)
                    for did in config.BMS_CURRENT_LIMIT_DIDS:
                        raw = conn.read_did(addr, did, config.UDS_TIMEOUT)
                        if raw is not None:
                            battery_raw[did] = raw

                    # Cell voltage array (0x0667) — 396 bytes historical min/max
                    raw = conn.read_did(addr, config.CELL_ARRAY_DID, 2.0)
                    if raw is not None:
                        battery_raw[config.CELL_ARRAY_DID] = raw

                    # Retry intermittent DIDs in extended session
                    for did in [0x02E1, 0x02FA]:
                        if battery_raw.get(did) is None:
                            raw = conn.read_did(addr, did, config.UDS_TIMEOUT)
                            if raw is not None:
                                battery_raw[did] = raw

                    # Module grid (0x1850-0x1870) — 33 per-module blocks
                    for did in config.MODULE_GRID_DIDS:
                        raw = conn.read_did(addr, did, config.UDS_TIMEOUT)
                        if raw is not None:
                            battery_raw[did] = raw

                    # Return to default session
                    conn.change_session(addr, session=0x01, timeout=2.0)

                result["battery"] = config.decode_battery(battery_raw)

            # Powertrain ECU live telemetry
            # Decode each ECU's data immediately so we never hold bytes in result
            POWERTRAIN_MAP = {
                0x407C: "front_inverter",
                0x40B8: "rear_inverter",
                0x4044: "obc",
                0x40B7: "dcdc",
                0x40C7: "hv_booster",
            }
            if addr in POWERTRAIN_MAP:
                if progress_callback:
                    progress_callback(idx + 1, total,
                                      f"Powertrain telemetry: {name}")
                powertrain_raw = _read_powertrain_ecu(conn, addr)
                if powertrain_raw:
                    if result["powertrain"] is None:
                        result["powertrain"] = {}
                    key = POWERTRAIN_MAP[addr]
                    # Store raw bytes temporarily; decoded at end
                    result["powertrain"][key] = powertrain_raw

            result["ecus"].append(ecu_result)

        result["summary"]["ecus_reachable"] = reachable
        result["summary"]["ecus_with_dtcs"] = with_dtcs
        result["summary"]["total_dtcs"] = total_dtc_count

        # Decode powertrain data — converts bytes to hex strings safe for JSON
        if result["powertrain"]:
            result["powertrain"] = config.decode_powertrain(result["powertrain"])

    except Exception as e:
        # Any unexpected error — convert any dangling bytes so JSON save works
        result["error"] = str(e)
        if result["powertrain"]:
            try:
                result["powertrain"] = config.decode_powertrain(result["powertrain"])
            except Exception:
                result["powertrain"] = None

    finally:
        conn.close()

    result["scan_duration_ms"] = int((time.time() - scan_start) * 1000)
    return result


def save_scan(scan_result: dict) -> str:
    """Save scan result to a timestamped JSON file. Returns the file path."""
    ensure_scans_dir()
    ts = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    filename = f"{ts}.json"
    filepath = os.path.join(SCANS_DIR, filename)

    with open(filepath, "w") as f:
        json.dump(scan_result, f, indent=2, default=str)

    return filepath


def list_scans() -> list[dict]:
    """List all saved scans, newest first. Returns basic metadata."""
    ensure_scans_dir()
    scans = []

    for filename in sorted(os.listdir(SCANS_DIR), reverse=True):
        if not filename.endswith(".json"):
            continue
        filepath = os.path.join(SCANS_DIR, filename)
        try:
            with open(filepath) as f:
                data = json.load(f)
            scans.append({
                "filename": filename,
                "timestamp": data.get("timestamp", ""),
                "soh_percent": (data.get("battery") or {}).get("soh_percent"),
                "soc_percent": (data.get("battery") or {}).get("soc_percent"),
                "ecus_reachable": (data.get("summary") or {}).get("ecus_reachable", 0),
                "total_dtcs": (data.get("summary") or {}).get("total_dtcs", 0),
                "scan_duration_ms": data.get("scan_duration_ms", 0),
            })
        except (json.JSONDecodeError, KeyError):
            continue

    return scans


def load_scan(filename: str) -> Optional[dict]:
    """Load a specific scan file by filename."""
    filepath = os.path.join(SCANS_DIR, filename)
    if not os.path.exists(filepath):
        return None
    try:
        with open(filepath) as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return None


def get_trend_data() -> dict:
    """Extract SoH/SoC trend data from all scans for charting."""
    scans = list_scans()
    timestamps = []
    soh_values = []
    soc_values = []

    for scan in reversed(scans):  # oldest first for charts
        timestamps.append(scan["timestamp"])
        soh_values.append(scan.get("soh_percent"))
        soc_values.append(scan.get("soc_percent"))

    return {
        "timestamps": timestamps,
        "soh": soh_values,
        "soc": soc_values,
    }
