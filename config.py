"""
Taycan DoIP Diagnostic Tool — Configuration

ECU addresses discovered from a Taycan J1.1 platform.
The "system code" (e.g. 0x19, 0x8C) is the VAG diagnostic address.
The DoIP logical address the gateway routes to is different —
discover via taycan_find_ecus.py.

Update GATEWAY_IP after running taycan_discover.py on your car.
"""

# ─── DoIP Connection ────────────────────────────────────────────────────────

TESTER_ADDRESS = 0x0E80
DOIP_PORT = 13400
GATEWAY_IP = "169.254.10.10"     # Update after running taycan_discover.py
LOCAL_IP = "169.254.10.1"
BROADCAST_IP = "169.254.255.255"

# The DoIP gateway logical address is 0x4010 (not the typical 0x1010).
# This is the address used in DoIP routing activation and as the
# target for diagnostic messages routed through the gateway.
GATEWAY_LOGICAL_ADDRESS = 0x4010

TCP_TIMEOUT = 5.0
UDP_TIMEOUT = 3.0
UDS_REQUEST_TIMEOUT = 5.0


# ─── Vehicle Info ───────────────────────────────────────────────────────────
# Updated after first discovery

VEHICLE_VIN = ""
VEHICLE_MODEL = "Taycan"
VEHICLE_YEAR = 0
VEHICLE_PLATFORM = "J1.1"


# ─── ECU Module Map (Taycan J1.1 Platform) ─────────────────────────────────
#
# VAG system code → ECU metadata. The "doip_addr" field is the DoIP logical
# address discovered by taycan_find_ecus.py. Set to None until confirmed.
# ASAM IDs and workshop IDs are platform-level (same across J1.1 vehicles).

VEHICLE_ECUS = {
    0x19: {"name": "Gateway", "workshop_id": "J533", "asam": "EV_Gatew31xPO513", "doip_addr": 0x4010},
    0x01: {"name": "Engine Control Module 1 (ASG/VCU)", "workshop_id": "ESCP5", "asam": "EV_VCU00XXX0209J1909101XX", "doip_addr": 0x4076},
    0x51: {"name": "Drive Motor Control Module (Front Inv)", "workshop_id": "J841", "asam": "EV_PWR1HIAMSPO513", "doip_addr": 0x407C},
    0xCE: {"name": "Drive Motor Control Module 2 (Rear Inv)", "workshop_id": "J944", "asam": "EV_PWR2HIAMSPO513", "doip_addr": 0x40B8},
    0x8C: {"name": "Battery Energy Control Module (BECM)", "workshop_id": "AX2", "asam": "EV_BECM1982091", "doip_addr": 0x407B},
    0xC6: {"name": "Battery Charger Control Module (OBC)", "workshop_id": "J1050", "asam": "EV_OBC3Phase1KLOMLBev16B", "doip_addr": 0x4044},
    0x81: {"name": "DC/DC Converter HV", "workshop_id": "A48", "asam": "EV_DCDC400VBasisPREHPO513", "doip_addr": 0x40B7},
    0xFF: {"name": "HV Booster", "workshop_id": "J1178", "asam": "EV_HVChargBoostPREHPO513", "doip_addr": 0x40C7},
    0x03: {"name": "Brakes 1 (ESP)", "workshop_id": "J104", "asam": "EV_ESP9BOSCHPO513", "doip_addr": 0x4013},
    0x44: {"name": "Steering Assistance (EPS)", "workshop_id": "J500", "asam": "EV_EPSBOPO68X", "doip_addr": 0x4012},
    0x74: {"name": "Chassis Control (Air Susp)", "workshop_id": "J775", "asam": "EV_ChassContrContiPO513", "doip_addr": 0x4080},
    0x09: {"name": "Central Electrics (BCM)", "workshop_id": "J519", "asam": "EV_BCM1BOSCHAU651", "doip_addr": 0x400E},
    0x46: {"name": "Central Module Comfort", "workshop_id": "J393", "asam": "EV_BCM2HellaAU736", "doip_addr": 0x408B},
    0x15: {"name": "Airbag", "workshop_id": "J234", "asam": "EV_AirbaVW31SMEAU65x", "doip_addr": 0x4015},
    0x5F: {"name": "Information Control Unit 1 (PCM)", "workshop_id": "J794", "asam": "EV_MUTI", "doip_addr": 0x4073},
    0x17: {"name": "Dash Board (Cluster)", "workshop_id": "K", "asam": "EV_DashBoardLGEPO513", "doip_addr": 0x4014},
    0x13: {"name": "Adaptive Cruise Control", "workshop_id": "J428", "asam": "EV_ACCBOSCHAU65X", "doip_addr": 0x4057},
    0xA5: {"name": "Front Sensors ADAS", "workshop_id": "J1121", "asam": "EV_ZFASAU516", "doip_addr": 0x404F},
    0x08: {"name": "Air Conditioning", "workshop_id": "J301", "asam": "EV_ACClimaBHTCPO513", "doip_addr": 0x4046},
    0xC5: {"name": "Thermal Management", "workshop_id": "J1024", "asam": "EV_ThermContrVISAU49X", "doip_addr": 0x4042},
    0x42: {"name": "Door Elec Driver", "workshop_id": "J386", "asam": "EV_DCU2DriveSideMAXHCONT", "doip_addr": 0x404A},
    0x52: {"name": "Door Elec Passenger", "workshop_id": "J387", "asam": "EV_DCU2PasseSideMAXHCONT", "doip_addr": 0x404B},
    0xBB: {"name": "Door Elec Rear Driver", "workshop_id": "J388", "asam": "EV_DCU2RearDriveMAXHCONT", "doip_addr": None},
    0xBC: {"name": "Door Elec Rear Passenger", "workshop_id": "J389", "asam": "EV_DCU2RearPasseMAXHCONT", "doip_addr": 0x403F},
    0x6D: {"name": "Deck Lid", "workshop_id": "J605", "asam": "EV_DeckLidCONTIAU536", "doip_addr": 0x4023},
    0xD6: {"name": "Light Control Left", "workshop_id": "A31", "asam": "EV_LLPGen3LKEBODPO68X", "doip_addr": 0x4096},
    0xD7: {"name": "Light Control Right", "workshop_id": "A27", "asam": "EV_LLPGen3RKEBODPO68X", "doip_addr": 0x4097},
    0x36: {"name": "Seat Adj Driver", "workshop_id": "J136", "asam": "EV_SCMDriveSideCONTIAU736", "doip_addr": 0x404C},
    0x06: {"name": "Seat Adj Passenger", "workshop_id": "J521", "asam": "EV_SCMPasseSideCONTIAU736", "doip_addr": 0x404D},
    0xC0: {"name": "Exterior Noise Actuator", "workshop_id": "-----", "asam": "EV_ESoundMLBEvoS1NN", "doip_addr": 0x4064},
    0xA9: {"name": "Structure-Borne Sound", "workshop_id": "-----", "asam": "EV_ActuaForIntNoise", "doip_addr": 0x401C},
    0x47: {"name": "Sound System (BOSE)", "workshop_id": "J525", "asam": "EV_AMPMst16C4Gen2BOSE", "doip_addr": 0x406F},
    0x6B: {"name": "Aerodynamics Control", "workshop_id": "J223", "asam": "EV_MASGMarquPO622", "doip_addr": 0x4024},
    0xDE: {"name": "Wireless Charger (Qi)", "workshop_id": "J1146", "asam": "EV_Charg1MobilDevicAU651", "doip_addr": 0x40A5},
    0x16: {"name": "Steering Column Elec", "workshop_id": "J527", "asam": "EV_SMLSKLOAU736", "doip_addr": 0x400C},
    0x75: {"name": "Telematics (TCU)", "workshop_id": "J949", "asam": "EV_ConBoxHighAU49X", "doip_addr": 0x4067},
    0x65: {"name": "Tire Pressure (TPMS)", "workshop_id": "J502", "asam": "EV_RDKHUFPO68X", "doip_addr": 0x400B},
}


# ─── Key ECU Shortcuts ─────────────────────────────────────────────────────
# VAG system codes (from MapEV scan) and confirmed DoIP logical addresses

GATEWAY_CODE = 0x19;  GATEWAY_DOIP = 0x4010
ASG_CODE = 0x01       # DoIP addr TBD — not yet matched
BMS_CODE = 0x8C;      BMS_DOIP = 0x407B   # ★ Battery ECU
OBC_CODE = 0xC6;      OBC_DOIP = 0x4044
DCDC_CODE = 0x81;     DCDC_DOIP = 0x40B7
INV_FRONT_CODE = 0x51; INV_FRONT_DOIP = 0x407C
INV_REAR_CODE = 0xCE;  INV_REAR_DOIP = 0x40B8
HV_BOOST_DOIP = 0x40C7
ESP_CODE = 0x03
CLUSTER_CODE = 0x17
PCM_CODE = 0x5F


# ─── Standard UDS DIDs ──────────────────────────────────────────────────────

STANDARD_DIDS = {
    0xF186: "Active Diagnostic Session",
    0xF187: "Spare Part Number",
    0xF188: "ECU Software Version",
    0xF189: "ECU Software Version (alt)",
    0xF18A: "System Supplier Identifier",
    0xF18B: "ECU Manufacturing Date",
    0xF18C: "ECU Serial Number",
    0xF190: "Vehicle Identification Number (VIN)",
    0xF191: "Hardware Version",
    0xF192: "System Supplier ECU HW Number",
    0xF193: "System Supplier ECU HW Version",
    0xF194: "System Supplier ECU SW Number",
    0xF195: "System Supplier ECU SW Version",
    0xF197: "System Name or Engine Type",
    0xF19E: "ASAM/ODX File Identifier",
    0xF1A0: "Manufacturer Specific Data ID",
}


# ─── Battery DIDs (BECM 0x8C — EV_BECM1982091) ────────────────────────────

BATTERY_DIDS = {
    0x028C: "Battery State of Health (SoH %)",
    0x028D: "Battery State of Charge (SoC %)",
    0x028E: "Battery Remaining Capacity (Wh)",
    0x028F: "Battery Design Capacity (Wh)",
    0x0290: "HV Battery Voltage (V)",
    0x0291: "HV Battery Current (A)",
    0x0292: "HV Battery Power (kW)",
    0x0294: "Battery Temp Min (°C)",
    0x0295: "Battery Temp Max (°C)",
    0x0296: "Battery Temp Avg (°C)",
    0x02A0: "Cell Voltage Min (mV)",
    0x02A1: "Cell Voltage Max (mV)",
    0x02A2: "Cell Voltage Delta (mV)",
    0x02B0: "Charge Power Limit (kW)",
    0x02B1: "Discharge Power Limit (kW)",
    0x02B2: "Max Charging Current (A)",
    0x02C0: "Total Energy Charged (kWh)",
    0x02C1: "Total Energy Discharged (kWh)",
    0x02C2: "Charge Cycle Count",
    0x02C3: "Fast Charge Count (DC)",
}


# ─── DID Scan Ranges ────────────────────────────────────────────────────────

DID_SCAN_RANGES = [
    (0x0100, 0x04FF, "Manufacturer-specific (low)"),
    (0x0500, 0x0FFF, "Manufacturer-specific (mid)"),
    (0x1000, 0x1FFF, "Manufacturer-specific (high)"),
    (0xF100, 0xF1FF, "Standard identification"),
    (0xF200, 0xF2FF, "Standard extended"),
]

# Gateway is at 0x4010 — ECUs likely in multiple ranges.
# Scan all plausible ranges. Step=1 because Porsche may use
# odd addresses too.
ECU_SCAN_RANGES = [
    (0x0001, 0x00FF, "Low range (legacy)"),
    (0x1000, 0x1FFF, "Standard range"),
    (0x4000, 0x4FFF, "Porsche/J1 range (gateway lives here)"),
    (0x5000, 0x5FFF, "Extended range"),
]
ECU_SCAN_RANGE_START = 0x0001  # fallback for old scripts
ECU_SCAN_RANGE_END = 0x5FFF
ECU_SCAN_STEP = 1

DTC_STATUS_MASK_ALL = 0xFF
DTC_STATUS_MASK_CURRENT = 0x01
DTC_STATUS_MASK_STORED = 0x04
