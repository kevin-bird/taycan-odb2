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

GATEWAY_IP = "169.254.10.10"          # discovered via UDP broadcast
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
    0xF197: "System Name",
    0xF19E: "ASAM/ODX ID",
    0xF1AA: "Workshop ID",
}

# ─── Battery DIDs (BECM 0x407B) ──────────────────────────────────────────

BATTERY_DIDS = [
    0x0286,  # SoC
    0x028C,  # SoH
    0x02B2,  # Charging status
    0x02B3,  # Status flag
    0x02BD,  # Pack telemetry (10 bytes)
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
        "temperature_min_c": None,
        "temperature_max_c": None,
        "pack_telemetry_hex": None,
        "module_status": None,
        "module_data": None,
        "raw_dids": {},
    }

    for did, raw in raw_dids.items():
        if raw is not None:
            result["raw_dids"][f"0x{did:04X}"] = raw.hex()

    # SoC (0x0286): 1 byte, scale ×0.75
    soc_raw = raw_dids.get(0x0286)
    if soc_raw and len(soc_raw) >= 1:
        result["soc_raw"] = soc_raw[0]
        result["soc_percent"] = round(soc_raw[0] * 0.75, 2)

    # SoH (0x028C): 1 byte, direct percentage
    soh_raw = raw_dids.get(0x028C)
    if soh_raw and len(soh_raw) >= 1:
        result["soh_raw"] = soh_raw[0]
        result["soh_percent"] = soh_raw[0]

    # Charging status (0x02B2): 1=charging, 0=not
    charge_raw = raw_dids.get(0x02B2)
    if charge_raw and len(charge_raw) >= 1:
        result["charging"] = charge_raw[0] == 1

    # Temperature pair (0x02CB): 2 bytes, min/max
    temp_raw = raw_dids.get(0x02CB)
    if temp_raw and len(temp_raw) >= 2:
        result["temperature_min_c"] = temp_raw[0]
        result["temperature_max_c"] = temp_raw[1]

    # Pack telemetry (0x02BD): 10 bytes raw
    telem_raw = raw_dids.get(0x02BD)
    if telem_raw:
        result["pack_telemetry_hex"] = telem_raw.hex()

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


def load_ecu_registry(json_path: str = None) -> list[dict]:
    """
    Load ECU registry from discovered_ecus.json.
    Returns list of {doip_address: int, name: str, asam_id: str, sw_number: str}.
    """
    if json_path is None:
        json_path = os.path.join(os.path.dirname(__file__), "..",
                                 "discovered_ecus.json")

    try:
        with open(json_path) as f:
            raw = json.load(f)
    except FileNotFoundError:
        return []

    ecus = []
    for entry in raw:
        addr_str = entry.get("doip_address", "0x0000")
        addr = int(addr_str, 16)
        asam = entry.get("asam_id") or ""
        sw = entry.get("sw_number") or ""

        # For 0x4076 the ASAM/SW are swapped in the scan data
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

    # Sort by address
    ecus.sort(key=lambda e: e["doip_address"])
    return ecus
