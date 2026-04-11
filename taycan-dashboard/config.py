"""
Taycan Dashboard — Configuration

ECU addresses, DID definitions, scaling factors.
Confirmed on Porsche Taycan J1.1 platform (MY2022).

Update GATEWAY_IP and VEHICLE_* after running discovery on your car.
"""

import json
import os
from typing import Optional

# ─── DoIP Connection ──────────────────────────────────────────────────────
# These are populated by taycan_discover.py — update after first discovery

GATEWAY_IP = "169.254.217.237"         # discovered via UDP broadcast
DOIP_PORT = 13400
TESTER_ADDRESS = 0x0E80
GATEWAY_LOGICAL_ADDRESS = 0x4010

# Timeouts (seconds)
TCP_TIMEOUT = 5.0
UDS_TIMEOUT = 1.0
TESTER_PRESENT_TIMEOUT = 0.3
DTC_TIMEOUT = 2.0

# ─── Vehicle Info ─────────────────────────────────────────────────────────
# Updated automatically after first successful scan

VEHICLE_VIN = ""
VEHICLE_MODEL = "Taycan"
VEHICLE_YEAR = 0
VEHICLE_PLATFORM = "J1.1"
BATTERY_CAPACITY_KWH = 93.4  # Performance Battery Plus (83.7 for standard)

# ─── Key ECU Addresses ───────────────────────────────────────────────────

BECM_ADDRESS = 0x407B  # Battery Energy Control Module

# ─── ASAM ID → Friendly Name Map ─────────────────────────────────────────

ASAM_TO_NAME = {
    "EV_Gatew31xPO513": "Gateway",
    "EV_BECM1982091": "Battery (BECM)",
    "EV_PWR1HIAMSPO513": "Front Inverter",
    "EV_PWR2HIAMSPO513": "Rear Inverter",
    "EV_OBC3Phase1KLOMLBev16B": "On-Board Charger",
    "EV_DCDC400VBasisPREHPO513": "DC-DC Converter",
    "EV_HVChargBoostPREHPO513": "HV Booster",
    "EV_VCU00XXX0209J1909101XX": "Powertrain (VCU)",
    "EV_ESP9BOSCHPO513": "Brakes (ESP)",
    "EV_EPSBOPO68X": "Power Steering (EPS)",
    "EV_ChassContrContiPO513": "Air Suspension",
    "EV_BCM1BOSCHAU651": "Body Control (BCM)",
    "EV_BCM2HellaAU736": "Comfort Module",
    "EV_AirbaVW31SMEAU65x": "Airbag",
    "EV_MUTI": "Infotainment (PCM)",
    "EV_DashBoardLGEPO513": "Instrument Cluster",
    "EV_ACCBOSCHAU65X": "Adaptive Cruise",
    "EV_ZFASAU516": "Front Sensors (ADAS)",
    "EV_ACClimaBHTCPO513": "Climate Control",
    "EV_ThermContrVISAU49X": "Thermal Management",
    "EV_DCU2DriveSideMAXHCONT": "Door Driver",
    "EV_DCU2PasseSideMAXHCONT": "Door Passenger",
    "EV_DCU2RearDriveMAXHCONT": "Door Rear Driver",
    "EV_DCU2RearPasseMAXHCONT": "Door Rear Pass.",
    "EV_DeckLidCONTIAU536": "Deck Lid",
    "EV_LLPGen3LKEBODPO68X": "Light Left",
    "EV_LLPGen3RKEBODPO68X": "Light Right",
    "EV_SCMDriveSideCONTIAU736": "Seat Driver",
    "EV_SCMPasseSideCONTIAU736": "Seat Passenger",
    "EV_ESoundMLBEvoS1NN": "E-Sound",
    "EV_ActuaForIntNoise": "Sound Actuator",
    "EV_AMPMst16C4Gen2BOSE": "BOSE Audio",
    "EV_MASGMarquPO622": "Aerodynamics",
    "EV_Charg1MobilDevicAU651": "Wireless Charger",
    "EV_SMLSKLOAU736": "Steering Column",
    "EV_ConBoxHighAU49X": "Telematics (TCU)",
    "EV_RDKHUFPO68X": "Tire Pressure (TPMS)",
    "EV_BrakeBoostBOSCHPO513": "Brake Boost",
    "EV_GSMWaehlJOPPPO68X": "Gear Selector",
    "EV_OTAFCHarmaPO513": "OTA Update",
}

# ─── Standard UDS Identity DIDs ──────────────────────────────────────────

IDENTITY_DIDS = {
    0xF187: "SW Part Number",
    0xF189: "SW Version",
    0xF18B: "Manufacturing Date",
    0xF18C: "Serial Number",
    0xF190: "VIN",
    0xF191: "HW Part Number",
    0xF1A3: "HW Version",
    0xF197: "System Name",
    0xF19E: "ASAM/ODX ID",
    0xF1AA: "Workshop ID",
    0xF17C: "FAZIT",
}

# ─── Battery DIDs (BECM 0x407B) ──────────────────────────────────────────

BATTERY_DIDS = [
    0x0286,  # SoC (raw, needs remap)
    0x028C,  # SoC display
    0x02B2,  # Charging status
    0x02B3,  # Status flag
    0x02BD,  # Pack telemetry (10 bytes) — voltage/current/power
    0x02CB,  # Temperature pair
    0x0407,  # Module status (16 bytes)
    0x040F,  # Module data (16 bytes)
    0x0410,  # Temperature / module count
    0x02E1,  # Energy counter (intermittent)
    0x02FA,  # Cell data (intermittent)
    0x02CA,  # Counter
    0x02D1,  # Status
    0x03DE,  # Unknown
    0x043F,  # Unknown
    0x0440,  # Config data
    0x04FC,  # Unknown
    0x04FE,  # Unknown
]

# SoH candidates (extended session required)
SOH_CANDIDATE_DIDS = [0x1E1C, 0x1E1E]

# Per-module cell data (extended session required)
# 33 blocks × 43 bytes each — physical module grid with 6 cell pair voltages
MODULE_GRID_DIDS = list(range(0x1850, 0x1871))

# Cell voltage array (extended session, 396 bytes = 198 × uint16)
CELL_ARRAY_DID = 0x0667

# Cell voltage offset for decoding (raw + offset = mV)
CELL_VOLTAGE_OFFSET_MV = 3500

# ─── Powertrain ECU DIDs (from investigation sweep) ──────────────────────
# Extra DIDs to read from specific ECUs for live telemetry display

# Inverter DIDs (both 0x407C front and 0x40B8 rear)
INVERTER_DIDS = [
    0x028D,  # 2 bytes — motor-specific (RPM or torque candidate)
    0x02BD,  # 10 bytes — HV bus telemetry (same as BECM)
    0x02CB,  # Temperature pair
    0x02FF,  # 19 bytes — power electronics state
    0x1FFF,  # Firmware version (ASCII)
]

# OBC (0x4044) DIDs
OBC_DIDS = [
    0x02BD,  # Pack telemetry
    0x15E2,  # Temperature candidate
    0x1557,  # Charge current limit candidate
    0x155A,  # Max power candidate
    0x15EE,  # Session counter
    0x15EF,  # Session counter
    0x15F3,  # Lifetime energy counter
    0x1DDA,  # 5 bytes
    0x1DDB,  # 9 bytes — 3-phase grid voltage candidate
    0x1DD0,  # Temperature candidate
]

# DC-DC Converter (0x40B7) DIDs
DCDC_DIDS = [
    0x02BD,  # Pack telemetry
    0x1100,  # LV bus voltage candidate
    0x1101,  # LV bus current candidate
    0x1550,  # HV bus reading 1
    0x1551,  # HV bus reading 2
    0x1543,  # HV bus reading 3
    0x15E2,  # Temperature candidate
]

# HV Booster (0x40C7) DIDs
HV_BOOSTER_DIDS = [
    0x02BD,  # Pack telemetry
    0x02CB,  # Temperature pair
    0x15E2,  # Temperature candidate
    0x1609,  # Voltage reading
    0x160A,  # Voltage reading
]


def decode_battery(raw_dids: dict[int, Optional[bytes]]) -> dict:
    """
    Decode raw battery DID bytes into meaningful values.
    Returns a dict suitable for the scan JSON.
    """
    result = {
        "soc_percent": None,
        "soc_raw": None,
        "soh_percent": None,
        "soh_raw": None,
        "charging": None,
        "pack_voltage_v": None,
        "pack_current_a": None,
        "pack_power_kw": None,
        "temperature_min_c": None,
        "temperature_max_c": None,
        "pack_telemetry_hex": None,
        "module_status": None,
        "module_data": None,
        "module_grid": None,        # Physical module map with voltages
        "cell_stats": None,          # Pack-wide cell voltage stats
        "raw_dids": {},
    }

    for did, raw in raw_dids.items():
        if raw is not None:
            result["raw_dids"][f"0x{did:04X}"] = raw.hex()

    # SoC (0x0286): 1 byte, raw BMS value remapped to displayed %
    # Raw range ~5 (0% displayed) to ~137 (100% displayed)
    # Formula: displayed = (raw - 5) / 132 * 100, clipped to 0-100
    soc_raw = raw_dids.get(0x0286)
    if soc_raw and len(soc_raw) >= 1:
        result["soc_raw"] = soc_raw[0]
        displayed = (soc_raw[0] - 5) / 132.0 * 100.0
        result["soc_percent"] = round(max(0, min(100, displayed)), 1)

    # SoC display (0x028C): 1 byte, direct percentage (BMS remapped value)
    # This is the display-ready SoC — use as fallback when 0x0286 doesn't respond
    soc_display = raw_dids.get(0x028C)
    if soc_display and len(soc_display) >= 1:
        if result["soc_percent"] is None:
            # 0x0286 didn't respond — use 0x028C as SoC
            result["soc_raw"] = soc_display[0]
            result["soc_percent"] = soc_display[0]

    # Charging status (0x02B2): 1=charging, 0=not
    charge_raw = raw_dids.get(0x02B2)
    if charge_raw and len(charge_raw) >= 1:
        result["charging"] = charge_raw[0] == 1

    # Temperature pair (0x02CB): 2 bytes, min/max
    temp_raw = raw_dids.get(0x02CB)
    if temp_raw and len(temp_raw) >= 2:
        result["temperature_min_c"] = temp_raw[0]
        result["temperature_max_c"] = temp_raw[1]

    # Pack telemetry (0x02BD): 10 bytes — decode voltage, current, power
    # Bytes 0-1: charge current (×0.1A, signed)
    # Bytes 2-3: pack voltage (×0.15V)
    # Byte 5: internal temp (×0.5°C)
    telem_raw = raw_dids.get(0x02BD)
    if telem_raw:
        result["pack_telemetry_hex"] = telem_raw.hex()
        if len(telem_raw) >= 4:
            current_raw = int.from_bytes(telem_raw[0:2], "big", signed=True)
            result["pack_current_a"] = round(current_raw * 0.1, 1)
            voltage_raw = int.from_bytes(telem_raw[2:4], "big")
            result["pack_voltage_v"] = round(voltage_raw * 0.15, 1)
            if result["pack_voltage_v"] and result["pack_current_a"] is not None:
                result["pack_power_kw"] = round(
                    result["pack_voltage_v"] * result["pack_current_a"] / 1000, 1)

    # Module status (0x0407): 16 bytes = 8 × uint16 BE
    mod_status = raw_dids.get(0x0407)
    if mod_status and len(mod_status) >= 16:
        result["module_status"] = [
            int.from_bytes(mod_status[i:i+2], "big")
            for i in range(0, 16, 2)
        ]

    # Module data (0x040F): 16 bytes = 8 × uint16 BE
    mod_data = raw_dids.get(0x040F)
    if mod_data and len(mod_data) >= 16:
        result["module_data"] = [
            int.from_bytes(mod_data[i:i+2], "big")
            for i in range(0, 16, 2)
        ]

    # Module grid (0x1850-0x1870): 33 blocks with physical position and 6 voltages each
    grid = decode_module_grid(raw_dids)
    if grid:
        result["module_grid"] = grid
        result["cell_stats"] = compute_cell_stats(grid)

    # SoH candidates (extended session)
    for did in SOH_CANDIDATE_DIDS:
        raw = raw_dids.get(did)
        if raw and len(raw) >= 2:
            val = int.from_bytes(raw[:2], "big")
            # Candidate: raw / 10 = percent (e.g. 0x035C = 860 → 86.0%)
            soh_candidate = val / 10.0
            if 50 <= soh_candidate <= 110:
                # Tentatively use the first candidate
                if result["soh_percent"] is None:
                    result["soh_percent"] = soh_candidate
                    result["soh_raw"] = val

    return result


def decode_module_grid(raw_dids: dict) -> Optional[list]:
    """
    Decode the per-module data from DIDs 0x1850-0x1870.
    Each 43-byte block has a module ID (row, col) and 6 voltage triplets.
    Returns a list of 33 module dicts with position, voltages, and stats.
    """
    modules = []
    for did in MODULE_GRID_DIDS:
        raw = raw_dids.get(did)
        if not raw or len(raw) < 43:
            continue

        module_id = raw[0]
        row = (module_id >> 4) & 0x0F
        col = module_id & 0x0F

        # Extract the 6 triplets at fixed positions (byte 1, 8, 15, 22, 29, 36)
        triplet_positions = [1, 8, 15, 22, 29, 36]
        voltages_raw = []
        valid = True
        for pos in triplet_positions:
            if pos + 2 >= len(raw):
                valid = False
                break
            # Validate format: 0x91 [val] 0x39
            if raw[pos] != 0x91:
                valid = False
                break
            voltages_raw.append(raw[pos + 1])

        if not valid or len(voltages_raw) != 6:
            continue

        voltages_mv = [v + CELL_VOLTAGE_OFFSET_MV for v in voltages_raw]
        modules.append({
            "did": f"0x{did:04X}",
            "module_id": f"0x{module_id:02X}",
            "row": row,
            "col": col,
            "voltages_mv": voltages_mv,
            "min_mv": min(voltages_mv),
            "max_mv": max(voltages_mv),
            "avg_mv": round(sum(voltages_mv) / len(voltages_mv), 1),
            "spread_mv": max(voltages_mv) - min(voltages_mv),
        })

    return modules if modules else None


def compute_cell_stats(modules: list) -> dict:
    """Compute pack-wide cell statistics from module grid."""
    if not modules:
        return None

    all_voltages = []
    for m in modules:
        all_voltages.extend(m["voltages_mv"])

    if not all_voltages:
        return None

    sorted_mods_by_min = sorted(modules, key=lambda m: m["min_mv"])
    sorted_mods_by_spread = sorted(modules, key=lambda m: m["spread_mv"], reverse=True)

    return {
        "cell_count": len(all_voltages),
        "module_count": len(modules),
        "pack_min_mv": min(all_voltages),
        "pack_max_mv": max(all_voltages),
        "pack_avg_mv": round(sum(all_voltages) / len(all_voltages), 1),
        "pack_spread_mv": max(all_voltages) - min(all_voltages),
        "weakest_module": {
            "position": f"Row {sorted_mods_by_min[0]['row']}, Col {sorted_mods_by_min[0]['col']}",
            "min_mv": sorted_mods_by_min[0]["min_mv"],
            "module_id": sorted_mods_by_min[0]["module_id"],
        },
        "most_imbalanced_module": {
            "position": f"Row {sorted_mods_by_spread[0]['row']}, Col {sorted_mods_by_spread[0]['col']}",
            "spread_mv": sorted_mods_by_spread[0]["spread_mv"],
            "module_id": sorted_mods_by_spread[0]["module_id"],
        },
    }


def decode_powertrain(powertrain: dict) -> dict:
    """
    Decode raw DIDs from powertrain ECUs (inverters, OBC, DC-DC) into
    dashboard-friendly values.
    """
    result = {}

    # Front and rear inverters
    for key in ("front_inverter", "rear_inverter"):
        raw = powertrain.get(key)
        if not raw:
            continue
        ecu = {"raw_dids": {}}
        for did, data in raw.items():
            if isinstance(data, bytes):
                ecu["raw_dids"][f"0x{did:04X}"] = data.hex()
        # 0x028D: 2 bytes — motor-specific metric
        motor_raw = raw.get(0x028D)
        if motor_raw and len(motor_raw) >= 2:
            ecu["motor_metric"] = int.from_bytes(motor_raw[:2], "big")
        # 0x1FFF: firmware version
        fw_raw = raw.get(0x1FFF)
        if fw_raw:
            try:
                fw = fw_raw.decode("ascii", errors="replace").strip("\x00").strip()
                ecu["firmware"] = fw
            except Exception:
                pass
        # 0x02BD: pack telemetry
        telem = raw.get(0x02BD)
        if telem and len(telem) >= 4:
            # Note: inverter telemetry layout may differ; decode as BECM format
            current_raw = int.from_bytes(telem[0:2], "big", signed=True)
            voltage_raw = int.from_bytes(telem[2:4], "big")
            ecu["pack_current_a"] = round(current_raw * 0.1, 1)
            ecu["pack_voltage_v"] = round(voltage_raw * 0.15, 1)
        result[key] = ecu

    # OBC
    obc_raw = powertrain.get("obc")
    if obc_raw:
        obc = {"raw_dids": {}}
        for did, data in obc_raw.items():
            if isinstance(data, bytes):
                obc["raw_dids"][f"0x{did:04X}"] = data.hex()

        # 0x1DDB: 9 bytes — 3-phase grid voltage candidate
        grid = obc_raw.get(0x1DDB)
        if grid and len(grid) >= 9:
            # Bytes 3-4, 5-6, 7-8 = three uint16 values
            v1 = int.from_bytes(grid[3:5], "big")
            v2 = int.from_bytes(grid[5:7], "big")
            v3 = int.from_bytes(grid[7:9], "big")
            obc["grid_raw"] = [v1, v2, v3]

        # 0x15F3: 4 bytes — lifetime energy counter candidate
        lifetime = obc_raw.get(0x15F3)
        if lifetime and len(lifetime) >= 4:
            obc["lifetime_counter"] = int.from_bytes(lifetime, "big")

        # 0x1DD0: temperature candidate
        temp = obc_raw.get(0x1DD0)
        if temp and len(temp) >= 1:
            obc["temperature_c"] = temp[0]

        # 0x15E2: temperature or percent
        status = obc_raw.get(0x15E2)
        if status and len(status) >= 1:
            obc["status_byte"] = status[0]

        result["obc"] = obc

    # HV Booster
    hv_raw = powertrain.get("hv_booster")
    if hv_raw:
        hv = {"raw_dids": {}}
        for did, data in hv_raw.items():
            if isinstance(data, bytes):
                hv["raw_dids"][f"0x{did:04X}"] = data.hex()
        # 0x02BD: pack telemetry
        telem = hv_raw.get(0x02BD)
        if telem and len(telem) >= 4:
            current_raw = int.from_bytes(telem[0:2], "big", signed=True)
            voltage_raw = int.from_bytes(telem[2:4], "big")
            hv["pack_current_a"] = round(current_raw * 0.1, 1)
            hv["pack_voltage_v"] = round(voltage_raw * 0.15, 1)
        # 0x02CB: temperature
        temp = hv_raw.get(0x02CB)
        if temp and len(temp) >= 2:
            hv["temperature_c"] = temp[0]
        result["hv_booster"] = hv

    # DC-DC Converter
    dcdc_raw = powertrain.get("dcdc")
    if dcdc_raw:
        dcdc = {"raw_dids": {}}
        for did, data in dcdc_raw.items():
            if isinstance(data, bytes):
                dcdc["raw_dids"][f"0x{did:04X}"] = data.hex()

        # 0x1550: 10 bytes — HV bus reading 1
        hv1 = dcdc_raw.get(0x1550)
        if hv1 and len(hv1) >= 2:
            hv_raw = int.from_bytes(hv1[:2], "big")
            # Scale ~0.265 → volts (fits 800V HV bus)
            dcdc["hv_voltage_v"] = round(hv_raw * 0.265, 1)

        # 0x1100: 2 bytes — LV bus voltage candidate
        lv = dcdc_raw.get(0x1100)
        if lv and len(lv) >= 2:
            lv_raw = int.from_bytes(lv[:2], "big")
            # Scale ~0.025 → 12V range
            dcdc["lv_voltage_v"] = round(lv_raw * 0.025, 2)

        # 0x15E2: temperature
        temp = dcdc_raw.get(0x15E2)
        if temp and len(temp) >= 1:
            dcdc["temperature_c"] = temp[0]

        result["dcdc"] = dcdc

    return result


def decode_mfg_date(raw: bytes) -> Optional[str]:
    """Decode 3-byte manufacturing date: [YY] [MM] [DD] → YYYY-MM-DD."""
    if raw and len(raw) >= 3:
        year = 2000 + raw[0]
        month = raw[1]
        day = raw[2]
        if 1 <= month <= 12 and 1 <= day <= 31:
            return f"{year}-{month:02d}-{day:02d}"
    return None


# ─── Known DoIP Addresses (Taycan J1.1 platform) ────────────────────────
# These are platform-level — same across all J1.1 vehicles.
# No per-vehicle discovery step needed.

KNOWN_ECUS = [
    (0x400B, "EV_RDKHUFPO68X"),
    (0x400C, "EV_SMLSKLOAU736"),
    (0x400E, "EV_BCM1BOSCHAU651"),
    (0x4010, "EV_Gatew31xPO513"),
    (0x4012, "EV_EPSBOPO68X"),
    (0x4013, "EV_ESP9BOSCHPO513"),
    (0x4014, "EV_DashBoardLGEPO513"),
    (0x4015, "EV_AirbaVW31SMEAU65x"),
    (0x401C, "EV_ActuaForIntNoise"),
    (0x4023, "EV_DeckLidCONTIAU536"),
    (0x4024, "EV_MASGMarquPO622"),
    (0x403B, "EV_BrakeBoostBOSCHPO513"),
    (0x403F, "EV_DCU2RearPasseMAXHCONT"),
    (0x4042, "EV_ThermContrVISAU49X"),
    (0x4044, "EV_OBC3Phase1KLOMLBev16B"),
    (0x4046, "EV_ACClimaBHTCPO513"),
    (0x404A, "EV_DCU2DriveSideMAXHCONT"),
    (0x404B, "EV_DCU2PasseSideMAXHCONT"),
    (0x404C, "EV_SCMDriveSideCONTIAU736"),
    (0x404D, "EV_SCMPasseSideCONTIAU736"),
    (0x404F, "EV_ZFASAU516"),
    (0x4053, "EV_GSMWaehlJOPPPO68X"),
    (0x4057, "EV_ACCBOSCHAU65X"),
    (0x4064, "EV_ESoundMLBEvoS1NN"),
    (0x4067, "EV_ConBoxHighAU49X"),
    (0x406F, "EV_AMPMst16C4Gen2BOSE"),
    (0x4073, "EV_MUTI"),
    (0x4076, "EV_VCU00XXX0209J1909101XX"),
    (0x407B, "EV_BECM1982091"),
    (0x407C, "EV_PWR1HIAMSPO513"),
    (0x4080, "EV_ChassContrContiPO513"),
    (0x4086, "EV_OTAFCHarmaPO513"),
    (0x408B, "EV_BCM2HellaAU736"),
    (0x4096, "EV_LLPGen3LKEBODPO68X"),
    (0x4097, "EV_LLPGen3RKEBODPO68X"),
    (0x40A5, "EV_Charg1MobilDevicAU651"),
    (0x40B7, "EV_DCDC400VBasisPREHPO513"),
    (0x40B8, "EV_PWR2HIAMSPO513"),
    (0x40C7, "EV_HVChargBoostPREHPO513"),
    (0x40F1, "EV_AirbaVW31SMEAU65x"),
]


def load_ecu_registry(json_path: str = None) -> list[dict]:
    """
    Load ECU registry. Tries discovered_ecus.json first (if it exists),
    otherwise uses the built-in KNOWN_ECUS list. No manual discovery step needed.
    """
    # Try loading from discovered_ecus.json (has per-vehicle SW numbers)
    if json_path is None:
        json_path = os.path.join(os.path.dirname(__file__), "..",
                                 "discovered_ecus.json")

    ecus = []
    try:
        with open(json_path) as f:
            raw = json.load(f)
        for entry in raw:
            addr_str = entry.get("doip_address", "0x0000")
            addr = int(addr_str, 16)
            asam = entry.get("asam_id") or ""
            sw = entry.get("sw_number") or ""
            if not asam and sw.startswith("EV_"):
                asam = sw
                sw = ""
            name = ASAM_TO_NAME.get(asam, asam or f"ECU {addr_str}")
            ecus.append({
                "doip_address": addr,
                "doip_address_hex": f"0x{addr:04X}",
                "name": name,
                "asam_id": asam,
                "sw_number": sw,
            })
    except FileNotFoundError:
        # Fall back to built-in address list
        for addr, asam in KNOWN_ECUS:
            name = ASAM_TO_NAME.get(asam, asam)
            ecus.append({
                "doip_address": addr,
                "doip_address_hex": f"0x{addr:04X}",
                "name": name,
                "asam_id": asam,
                "sw_number": "",
            })

    ecus.sort(key=lambda e: e["doip_address"])
    return ecus
