# Taycan Diagnostic Dashboard

Open-source diagnostic tool for the Porsche Taycan (J1 / J1.1 platform). Connects via the OBD-II port over Ethernet, reads battery health, fault codes, and ECU data from all 42+ modules, and displays everything in a live browser dashboard.

![Dashboard Screenshot](Taycan.png)

## What it does

- **Battery monitoring** — reads SoC, pack voltage, current, power, temperatures, module balancing status, cell-level voltages (33 modules, 198 cell pairs with physical positions), and charging state directly from the BECM. SoH DID is under investigation.
- **Full ECU scan** — probes all 42 ECUs for identification (SW/HW part numbers, versions, serial numbers, FAZIT, manufacturing dates) and fault codes
- **Fault code lookup** — 69 known Taycan DTCs with descriptions, severity levels, and notes sourced from NHTSA TSBs, forums, and field data
- **Smart DTC filtering** — separates real faults (active/pending/confirmed) from the ~2800 "test not completed" entries that VAG ECUs return
- **Scan history** — every scan auto-saved to JSON with SoH/SoC trend charts over time
- **Auto-discovery** — gateway IP and VIN discovered automatically via UDP broadcast, 40 known ECU addresses built in
- **Live dashboard** — dark-themed browser UI with battery gauges, ECU grid (color-coded by fault severity), and trend charts
- **6 recalls tracked** — cross-references scans against known NHTSA recalls (APB5, ARA4/5, ARB6/7, 23V841)
- **10 diagnostic tips** — expert guidance on HV faults, OBC codes, 12V battery issues, and common fault patterns

## Documentation

- **[TECHNICAL.md](TECHNICAL.md)** — comprehensive reverse-engineering reference for the Taycan J1.1 DoIP protocol. Covers network topology, DoIP message formats, all 42 ECU addresses, BECM battery DID decoding, DTC status byte filtering, scan protocol analysis from pcap captures, and implementation notes.
- **[taycan_fault_codes.json](taycan_fault_codes.json)** — fault code database with 69 DTC definitions, 26 known-benign OBC codes, 6 NHTSA recalls, and 10 diagnostic tips. Sourced from NHTSA TSBs, TaycanForum, Rennlist, and field scan data.

## Hardware required

### ENET OBD-II cable

You need an Ethernet-to-OBD-II cable (ENET cable). This is the same type used for BMW/VAG diagnostics — a standard Ethernet cable with an OBD-II connector on one end.

[ENET OBD-II Cable (Amazon UK)](https://www.amazon.co.uk/dp/B0DYJKMGY3)

Any generic "BMW ENET cable" or "ENET to OBD2" cable will work. The cable connects:
- **OBD-II end** → diagnostic port under the Taycan's dashboard (driver side)
- **RJ45 end** → USB Ethernet adapter on your Mac (or direct Ethernet port)

### USB Ethernet adapter

If your Mac doesn't have an Ethernet port, you'll need a USB-C to Ethernet adapter. Any USB 10/100/1000 adapter works.

## Setup

### 1. Clone the repo

```bash
git clone https://github.com/kevin-bird/taycan-odb2.git
cd taycan-odb2
```

### 2. Create virtual environment and install dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install flask
```

### 3. Configure your network interface

Connect the ENET cable to the OBD-II port and your Mac's Ethernet adapter. Then assign a link-local IP:

```bash
# Find your Ethernet adapter name
networksetup -listallhardwareports

# Configure it (replace en7 with your adapter)
sudo ifconfig en7 inet 169.254.10.1 netmask 255.255.0.0 up
```

### 4. Turn on the car

The ignition must be **ON** (foot on brake + start button), not just accessory mode. The gateway won't respond otherwise.

### 5. Launch the dashboard

```bash
cd taycan-dashboard
source ../.venv/bin/activate
python3 app.py --host 0.0.0.0 --port 8080
```

Open http://localhost:8080 in your browser. Click **Scan Now** to pull live data from the car.

The gateway is auto-discovered — no manual IP configuration needed. All 40 known J1.1 ECU addresses are built in.

To access from another device on the same network, use your Mac's IP instead of localhost.

## Dashboard features

### Battery panel
- **SoH gauge** — shows battery health percentage when available (SoH DID under investigation, currently shows --)
- **SoC gauge** — large circular gauge with color coding, remapped to match car's displayed percentage
- **Pack voltage** — live HV pack voltage (typically ~800V)
- **Current / Power** — charge current (A) and power (kW)
- **Temperature** — battery min/max in celsius
- **Module status** — per-module balancing indicators

### HV system architecture diagram
- SVG schematic showing all HV components and their connections
- Color-coded buses: red = 800V HV, blue = 12V LV, green = Ethernet DoIP
- Shows ECU addresses, external charging ports (AC Grid, DC CCS), and diagnostic tool connection

### Powertrain telemetry
- 5-card row showing live data from Front Inverter, Rear Inverter, OBC, DC-DC Converter, HV Booster
- HV bus voltage/current from each ECU, firmware versions, grid voltage, 12V bus, temperatures

### ECU grid
- All 42 ECUs displayed, sorted by importance (powertrain first, then chassis/safety, then body/comfort)
- Color-coded: green = healthy, amber = stored faults, red = active faults
- Click any ECU for full detail: SW/HW part numbers, versions, serial, FAZIT, manufacturing date

### Battery module map
- Physical pack grid (8 rows x 4 cols + 1 = 33 modules) with per-module cell pair voltages
- Color-coded by health: blue = strongest, green = healthy, amber = below average, red = weakest
- Pack-wide stats bar: min/max voltage, average, spread
- Hover for per-module detail (6 cell pair voltages, spread)

### Fault codes
- Real faults only (filters out ~2800 incomplete self-test entries)
- Each DTC shows description, severity badge, and diagnostic notes from the fault code database
- Grouped by ECU in the summary panel

## CLI tools

The repo also includes standalone CLI tools for direct interaction:

| Tool | Description |
|------|-------------|
| `taycan_discover.py` | UDP broadcast to find the DoIP gateway |
| `taycan_find_ecus.py` | Fast ECU address discovery via single TCP connection |
| `taycan_sweep.py` | Live DID enumerator with progress bar, extended session support |
| `taycan_enumerate.py` | Brute-force DID enumeration on a specific ECU |
| `taycan_scan.py` | Scan all ECUs for identification and DTCs |
| `taycan_battery.py` | Read battery-specific DIDs from the BECM |
| `taycan_read.py` | Read specific DIDs from any ECU |
| `run_investigation.py` | Orchestrated multi-ECU sweep with time estimates |

## Protocol details

The tool communicates using standard automotive protocols:

- **DoIP** (ISO 13400) — Diagnostics over IP, wraps UDS messages in TCP
- **UDS** (ISO 14229) — Unified Diagnostic Services for reading data and faults
- Raw TCP sockets throughout — the `doipclient` Python library hangs on Taycan gateways

See [TECHNICAL.md](TECHNICAL.md) for the full protocol reference including DoIP header formats, routing activation, diagnostic message wrapping, and UDS service details.

### Key Taycan J1.1 findings

- Gateway logical address: `0x4010` (not the typical `0x1010`)
- All ECU addresses are in the `0x40xx` range
- BECM (battery controller) at `0x407B`
- SoC: DID `0x0286`, formula `(raw - 5) / 132 * 100` (remapped to match car display)
- SoH: **not yet found** — candidates 0x1E1C/0x1E1E ruled out (volatile), 0x028C is SoC not SoH
- Pack voltage: DID `0x02BD` bytes 2-3, scale `x0.15V`
- Pack current: DID `0x02BD` bytes 0-1, scale `x0.1A` (signed)
- Temperature: DID `0x02CB`, 2 bytes (min/max celsius)

## Confirmed ECU addresses (Taycan J1.1)

| DoIP | Module | VAG Code |
|------|--------|----------|
| 0x4010 | Gateway | 0x19 |
| 0x407B | Battery (BECM) | 0x8C |
| 0x407C | Front Inverter | 0x51 |
| 0x40B8 | Rear Inverter | 0xCE |
| 0x4076 | Powertrain (VCU) | 0x01 |
| 0x4044 | On-Board Charger | 0xC6 |
| 0x40B7 | DC-DC Converter | 0x81 |
| 0x40C7 | HV Booster | 0xFF |
| 0x4013 | Brakes (ESP) | 0x03 |
| 0x4012 | Power Steering | 0x44 |
| 0x4080 | Air Suspension | 0x74 |
| 0x4015 | Airbag | 0x15 |
| 0x4073 | Infotainment (PCM) | 0x5F |
| 0x4014 | Instrument Cluster | 0x17 |
| 0x4057 | Adaptive Cruise | 0x13 |

Full list of 42 ECUs in [TECHNICAL.md](TECHNICAL.md#3-complete-ecu-address-map).

## File structure

```
taycan-odb2/
├── TECHNICAL.md                # Full protocol reference (800+ lines)
├── taycan_fault_codes.json     # Fault code database (69 DTCs, recalls, tips)
├── taycan_discover.py          # Gateway discovery (UDP)
├── taycan_find_ecus.py         # ECU address scanner
├── taycan_sweep.py             # Live DID enumerator with progress bar
├── taycan_enumerate.py         # DID enumerator (udsoncan-based)
├── taycan_scan.py              # Full ECU scanner
├── taycan_battery.py           # Battery data reader
├── taycan_read.py              # Generic DID reader
├── run_investigation.py        # Multi-ECU sweep orchestrator
├── config.py                   # ECU map, DID definitions
├── doip_helpers.py             # DoIP/UDS library helpers
├── requirements.txt            # Python dependencies
│
└── taycan-dashboard/           # Web dashboard
    ├── app.py                  # Flask backend + API
    ├── doip.py                 # Raw DoIP/UDS protocol (no dependencies)
    ├── config.py               # Dashboard config + battery/powertrain decoding
    ├── scanner.py              # Scan orchestration + fault code lookup
    ├── fault_codes.json        # DTC database
    ├── templates/
    │   └── dashboard.html      # Dashboard UI + HV architecture SVG
    ├── static/
    │   └── dashboard.js        # Frontend logic + charts
    └── scans/                  # Auto-saved scan JSON files
```

## Safety

This tool uses **read-only** diagnostic operations (ReadDataByIdentifier, ReadDTCInformation, TesterPresent). It does not write to ECUs, clear fault codes, flash firmware, or modify any vehicle configuration. Standard UDS session only — no security access or programming sessions.

## Compatibility

Tested on:
- Porsche Taycan J1.1 (pre-facelift, MY2022)
- macOS with USB Ethernet adapter
- Python 3.11+

Should work on any J1 / J1.1 Taycan (2020-2024 pre-facelift). The J1.2 facelift (2025+) may have different ECU addresses — run `taycan_find_ecus.py` to discover them.

## License

MIT
