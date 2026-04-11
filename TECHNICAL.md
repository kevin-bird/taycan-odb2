# Porsche Taycan J1.1 DoIP Diagnostic Protocol — Technical Reference

A comprehensive reverse-engineering guide for communicating with the Porsche Taycan (J1 / J1.1 platform, 2020–2024 pre-facelift) over Ethernet diagnostics.

All findings confirmed on a live vehicle using raw TCP sockets, UDP broadcast discovery, UDS DID enumeration, and Wireshark pcap analysis.

---

## Table of Contents

1. [Network Topology](#1-network-topology)
2. [DoIP Protocol Details](#2-doip-protocol-details)
3. [Complete ECU Address Map](#3-complete-ecu-address-map)
4. [BECM Battery Data](#4-becm-battery-data)
5. [DTC Status Byte Decoding](#5-dtc-status-byte-decoding)
6. [Scan Protocol Analysis](#6-scan-protocol-analysis)
7. [Implementation Notes](#7-implementation-notes)
8. [Open Questions](#8-open-questions)

---

## 1. Network Topology

### Physical Layer

The Taycan's OBD-II port exposes Ethernet on pins 3 and 11 (standard DoIP pinout). A standard "BMW ENET cable" connects this to a laptop's Ethernet port via RJ45. No special hardware, no ELM327, no CAN adapter required.

### IP Configuration

| Node | IP Address | Notes |
|------|-----------|-------|
| Gateway (Taycan) | 169.254.x.x | Link-local, discovered via UDP broadcast |
| Tester (laptop) | 169.254.10.1 (static) | Must be in same 169.254.0.0/16 subnet |
| Subnet mask | 255.255.0.0 | — |
| Broadcast | 169.254.255.255 | For gateway discovery |

The gateway uses a link-local address. The laptop's Ethernet adapter must be configured with a static IP in the same subnet:

```bash
sudo ifconfig en7 inet 169.254.10.1 netmask 255.255.0.0 up
```

**macOS routing note:** If the laptop also has Wi-Fi active, macOS may route 169.254.x.x traffic out the Wi-Fi interface instead of the Ethernet adapter. The fix is to bind sockets to the link-local IP (`169.254.10.1`) so traffic is forced through the correct interface.

### Protocol Stack

```
Ethernet → IPv4 → TCP (port 13400) → DoIP (ISO 13400) → UDS (ISO 14229)
```

All diagnostic communication flows through a single TCP connection to the gateway. The gateway internally routes UDS requests to individual ECUs over FlexRay and CAN buses. One cable, one connection, access to all 42 ECUs.

---

## 2. DoIP Protocol Details

### Gateway Discovery (UDP)

Send a Vehicle Identification Request (payload type `0x0001`) via UDP broadcast to port 13400. The gateway responds with payload type `0x0004`:

| Offset | Length | Content |
|--------|--------|---------|
| 0–7 | 8 bytes | DoIP header |
| 8–24 | 17 bytes | VIN (ASCII) |
| 25–26 | 2 bytes | Gateway logical address (uint16 BE) = `0x4010` |
| 27–32 | 6 bytes | MAC address |
| 33 | 1 byte | Further action required (`0x10` = routing activation needed) |

The gateway also emits ~13 unsolicited Vehicle ID Responses during startup. Any of these can be used for passive discovery without sending a request.

### DoIP Header Format (All Messages)

```
[version: 0x02] [inverse: 0xFD] [payload_type: uint16 BE] [payload_length: uint32 BE]
```

Total header: 8 bytes, always big-endian.

```python
def build_doip_header(payload_type, payload_length):
    return struct.pack(">BBHI", 0x02, 0xFD, payload_type, payload_length)
```

### Routing Activation (TCP)

After establishing a TCP connection to the gateway on port 13400, send a Routing Activation Request before any diagnostic messages:

```
Payload type: 0x0005
Payload: [tester_addr: uint16 BE] [activation_type: 0x00] [reserved: 4 bytes zeros]
```

Example:
```
Header:  02 FD 00 05 00 00 00 07
Payload: 0E 80 00 00 00 00 00
```

Response code `0x10` in byte 12 = routing activation accepted.

```python
payload = struct.pack(">HB4s", 0x0E80, 0x00, b"\x00\x00\x00\x00")
header = build_doip_header(0x0005, len(payload))
sock.sendall(header + payload)
resp = sock.recv(4096)
accepted = (resp[12] == 0x10)
```

### Diagnostic Message Wrapping

Every UDS request/response is wrapped in a DoIP diagnostic message (payload type `0x8001`):

```
[DoIP header: 8 bytes]
[source_address: uint16 BE]  — 0x0E80 for tester, 0x40xx for ECU
[target_address: uint16 BE]  — target ECU or tester
[UDS payload: variable]
```

**Response flow:**
1. Gateway sends Diagnostic Positive Ack (`0x8002`) confirming it accepted the message
2. The actual diagnostic response (`0x8001`) arrives from the target ECU
3. If the target is unreachable, the gateway returns Diagnostic Negative Ack (`0x8003`) instead

**NRC 0x78 handling:** Some ECUs respond with UDS Negative Response `0x7F xx 0x78` (requestCorrectlyReceivedResponsePending). When this occurs, reset the timeout and continue waiting for the real response.

### Functional Addressing (Broadcast)

Address `0xE400` is the DoIP functional addressing target. A TesterPresent (`0x3E 0x00`) sent to `0xE400` causes ALL connected ECUs to respond simultaneously. This is the fastest way to check which ECUs are alive.

### Payload Type Summary

| Type | Direction | Description |
|------|-----------|-------------|
| `0x0001` | Tester → GW (UDP) | Vehicle Identification Request |
| `0x0004` | GW → Tester (UDP) | Vehicle Identification Response |
| `0x0005` | Tester → GW (TCP) | Routing Activation Request |
| `0x0006` | GW → Tester (TCP) | Routing Activation Response |
| `0x8001` | Both (TCP) | Diagnostic Message |
| `0x8002` | GW → Tester (TCP) | Diagnostic Positive Acknowledgement |
| `0x8003` | GW → Tester (TCP) | Diagnostic Negative Acknowledgement |

### Key Addresses

| Address | Role |
|---------|------|
| `0x0E80` | Tester (diagnostic tool) |
| `0x4010` | DoIP Gateway |
| `0xE400` | Functional broadcast (all ECUs respond) |
| `0x40xx` | Individual ECU addresses (see section 3) |

---

## 3. Complete ECU Address Map

42 ECUs confirmed responding. All live in the `0x40xx` range. Discovered via brute-force TesterPresent sweep across `0x4000–0x4FFF` (~30 seconds over a single TCP connection).

### Powertrain and HV System

| DoIP Addr | VAG Code | Name | Workshop ID | ASAM ID |
|-----------|----------|------|-------------|---------|
| `0x4076` | `0x01` | Powertrain Control (VCU/ASG) | ESCP5 | EV_VCU00XXX0209J1909101XX |
| `0x407B` | `0x8C` | Battery Energy Control (BECM) | AX2 | EV_BECM1982091 |
| `0x407C` | `0x51` | Front Inverter (Bosch HIAMS) | J841 | EV_PWR1HIAMSPO513 |
| `0x40B8` | `0xCE` | Rear Inverter (Bosch HIAMS) | J944 | EV_PWR2HIAMSPO513 |
| `0x4044` | `0xC6` | On-Board Charger (OBC) | J1050 | EV_OBC3Phase1KLOMLBev16B |
| `0x40B7` | `0x81` | DC-DC Converter (800V→12V) | A48 | EV_DCDC400VBasisPREHPO513 |
| `0x40C7` | `0xFF` | HV Booster (charge boost) | J1178 | EV_HVChargBoostPREHPO513 |

### Chassis

| DoIP Addr | VAG Code | Name | Workshop ID | ASAM ID |
|-----------|----------|------|-------------|---------|
| `0x4013` | `0x03` | Brakes / ESP | J104 | EV_ESP9BOSCHPO513 |
| `0x4012` | `0x44` | Power Steering (EPS) | J500 | EV_EPSBOPO68X |
| `0x4080` | `0x74` | Air Suspension | J775 | EV_ChassContrContiPO513 |
| `0x403B` | — | Brake Boost | — | EV_BrakeBoostBOSCHPO513 |

### Body and Comfort

| DoIP Addr | VAG Code | Name | Workshop ID | ASAM ID |
|-----------|----------|------|-------------|---------|
| `0x400E` | `0x09` | Body Control Module (BCM) | J519 | EV_BCM1BOSCHAU651 |
| `0x408B` | `0x46` | Comfort Module | J393 | EV_BCM2HellaAU736 |
| `0x4015` | `0x15` | Airbag | J234 | EV_AirbaVW31SMEAU65x |
| `0x40F1` | `0x15` | Airbag (secondary address) | — | EV_AirbaVW31SMEAU65x |
| `0x404A` | `0x42` | Door Electronics Driver | J386 | EV_DCU2DriveSideMAXHCONT |
| `0x404B` | `0x52` | Door Electronics Passenger | J387 | EV_DCU2PasseSideMAXHCONT |
| `0x403F` | `0xBC` | Door Electronics Rear Passenger | J389 | EV_DCU2RearPasseMAXHCONT |
| `0x4023` | `0x6D` | Deck Lid | J605 | EV_DeckLidCONTIAU536 |
| `0x404C` | `0x36` | Seat Adjustment Driver | J136 | EV_SCMDriveSideCONTIAU736 |
| `0x404D` | `0x06` | Seat Adjustment Passenger | J521 | EV_SCMPasseSideCONTIAU736 |
| `0x400C` | `0x16` | Steering Column Electronics | J527 | EV_SMLSKLOAU736 |
| `0x40A5` | `0xDE` | Wireless Charger (Qi) | J1146 | EV_Charg1MobilDevicAU651 |

### Lighting

| DoIP Addr | VAG Code | Name | Workshop ID | ASAM ID |
|-----------|----------|------|-------------|---------|
| `0x4096` | `0xD6` | Light Control Left | A31 | EV_LLPGen3LKEBODPO68X |
| `0x4097` | `0xD7` | Light Control Right | A27 | EV_LLPGen3RKEBODPO68X |
| `0x4767` | — | Light Left (secondary) | — | EV_LLPGen3LKEBODPO68X |
| `0x4768` | — | Light (secondary) | — | — |

### Climate and Thermal

| DoIP Addr | VAG Code | Name | Workshop ID | ASAM ID |
|-----------|----------|------|-------------|---------|
| `0x4046` | `0x08` | Climate Control | J301 | EV_ACClimaBHTCPO513 |
| `0x4042` | `0xC5` | Thermal Management | J1024 | EV_ThermContrVISAU49X |

### Infotainment, ADAS, and Communications

| DoIP Addr | VAG Code | Name | Workshop ID | ASAM ID |
|-----------|----------|------|-------------|---------|
| `0x4073` | `0x5F` | Infotainment (PCM) | J794 | EV_MUTI |
| `0x4014` | `0x17` | Instrument Cluster | K | EV_DashBoardLGEPO513 |
| `0x4057` | `0x13` | Adaptive Cruise Control | J428 | EV_ACCBOSCHAU65X |
| `0x404F` | `0xA5` | Front Sensors (ADAS) | J1121 | EV_ZFASAU516 |
| `0x4067` | `0x75` | Telematics (TCU) | J949 | EV_ConBoxHighAU49X |
| `0x406F` | `0x47` | BOSE Audio | J525 | EV_AMPMst16C4Gen2BOSE |

### Sound and Aerodynamics

| DoIP Addr | VAG Code | Name | Workshop ID | ASAM ID |
|-----------|----------|------|-------------|---------|
| `0x401C` | `0xA9` | Structure-Borne Sound | — | EV_ActuaForIntNoise |
| `0x4064` | `0xC0` | E-Sound (exterior noise) | — | EV_ESoundMLBEvoS1NN |
| `0x4024` | `0x6B` | Aerodynamics Control | J223 | EV_MASGMarquPO622 |

### Other

| DoIP Addr | VAG Code | Name | Workshop ID | ASAM ID |
|-----------|----------|------|-------------|---------|
| `0x4010` | `0x19` | Gateway | J533 | EV_Gatew31xPO513 |
| `0x400B` | `0x65` | Tire Pressure (TPMS) | J502 | EV_RDKHUFPO68X |
| `0x4053` | — | Gear Selector | J587 | EV_GSMWaehlJOPPPO68X |
| `0x4086` | — | OTA Update (OTAFC) | J1222 | EV_OTAFCHarmaPO513 |

### VAG-to-DoIP Address Mapping

Every ECU stores its own address mapping in **DID 0xF1B6** (4 bytes):

```
[0x00] [VAG_system_code] [0x00] [DoIP_low_byte]
```

Example from BECM: `00 8C 00 7B` → VAG `0x8C` maps to DoIP `0x407B` (the `0x40` prefix is implicit).

Additionally, **DID 0x2A30** returns a 3-byte self-identification on most ECUs:

```
0x400B → 65 00 0B  (TPMS — first byte = VAG code 0x65)
0x4012 → 44 40 12  (EPS — first byte = VAG code 0x44)
0x4013 → 03 00 13  (ESP — first byte = VAG code 0x03)
0x404F → A5 00 4F  (ADAS — first byte = VAG code 0xA5)
```

The first byte is the VAG system code. The last two bytes are the DoIP address low bytes. This provides a programmatic way to map VAG codes to DoIP addresses without a static lookup table.

---

## 4. BECM Battery Data

The Battery Energy Control Module (BECM) at DoIP address `0x407B` provides the most valuable diagnostic data. 47 DIDs found responding in the default diagnostic session.

### Confirmed Battery DIDs

#### DID 0x0286 — State of Charge (SoC)

| Property | Value |
|----------|-------|
| Size | 1 byte |
| Encoding | Raw BMS value, remapped to display percentage |
| Formula | `displayed = (raw - 5) / 132 * 100`, clipped to 0–100% |
| Example | Raw `0x85` (133) → `(133 - 5) / 132 * 100 = 97.0%` |

The raw BMS SoC has a usable range of approximately 5 (0% displayed) to 137 (100% displayed). The car's dashboard applies this same remapping. Values above 137 are clipped to 100%.

**Confirmation:** Dashboard showed 97% while raw byte was 133. Formula `(133-5)/132*100 = 97.0%` — exact match.

This is a live value — changes in real-time during charging/driving.

#### DID 0x028C — State of Health (SoH)

| Property | Value |
|----------|-------|
| Size | 1 byte |
| Encoding | Direct percentage (raw = %) |
| Example | `0x5F` (95) = 95% |

Static value that doesn't change between consecutive reads. May fluctuate 1–2% between sessions as the BMS recalculates based on recent charge/discharge cycles, cell balancing state, and temperature. This is normal — SoH is not a fixed number.

Expected range for a 2020–2024 Taycan: 88–98% depending on age, mileage, and charging habits.

#### DID 0x02B2 — Charging Status

| Property | Value |
|----------|-------|
| Size | 1 byte |
| Encoding | Boolean: `1` = charging, `0` = not charging |

#### DID 0x02B3 — Status Flag

| Property | Value |
|----------|-------|
| Size | 1 byte |
| Observed | `0x00` during AC charging |
| Hypothesis | Charge type (0 = AC, 1 = DC), contactor state, or error flag |

### Pack Telemetry — DID 0x02BD (10 bytes)

This packed DID contains real-time electrical telemetry:

| Bytes | Size | Encoding | Description |
|-------|------|----------|-------------|
| 0–1 | uint16 BE signed | × 0.1 A | Pack current (positive = charging in) |
| 2–3 | uint16 BE | × 0.15 V | Pack voltage |
| 4 | uint8 | — | Sub-field (changes with voltage) |
| 5 | uint8 | × 0.5 °C (?) | Internal temperature |
| 6–8 | 3 bytes | — | Lifetime energy counter (static during session) |
| 9 | uint8 | — | Status/checksum byte |

**Decoded examples:**

| State | Current | Voltage | Power |
|-------|---------|---------|-------|
| AC taper charge at 97% SoC | 10.5 A | 867 V | 9.1 kW |
| AC taper charge at 98% SoC | 10.5 A | 868 V | 9.1 kW |

**To fully decode:** Read while driving (current negative/high, voltage drops under load) and while parked unplugged (current = 0, voltage settles to resting ~720V at 50% SoC).

```python
current_raw = int.from_bytes(data[0:2], "big", signed=True)
current_a = current_raw * 0.1

voltage_raw = int.from_bytes(data[2:4], "big")
voltage_v = voltage_raw * 0.15

power_kw = voltage_v * current_a / 1000
```

### Temperature — DID 0x02CB (2 bytes)

| Byte | Description |
|------|-------------|
| 0 | Battery temperature minimum (°C) |
| 1 | Battery temperature maximum (°C) |

Observed: `0x0F 0x0F` (15°C / 15°C) — thermal equilibrium. After a drive, the max should rise while the min may lag.

### Module Status Arrays

#### DID 0x0407 — Module Status (16 bytes = 8 × uint16 BE)

Observed: `[1, 3, 1, 3, 3, 3, 3, 3]`

Hypothesis: Per-module balancing status. Bit 0 = present, Bit 1 = actively balancing. At high SoC, most modules show `3` (balancing active). The two showing `1` are already balanced.

#### DID 0x040F — Module Data (16 bytes = 8 × uint16 BE)

Observed: `[1, 1000, 1000, 1000, 1000, 1000, 1000, 1000]`

`0x03E8` = 1000 repeated 7 times. Hypothesis: Per-module capacity in 0.1 Ah units (1000 = 100.0 Ah), or cell group voltage delta in 0.1 mV. First uint16 (`0x0001`) may be an index or offset.

### Intermittent DIDs

These DIDs responded on some reads but returned NRC `0x31` on others. They may require extended diagnostic session (`0x03`) for reliable access.

#### DID 0x02E1 — Energy Counter (4 bytes)

Value: `0x35443F18` (895,336,216). At 0.01 Wh scale: ~8,953 kWh lifetime — plausible for a regularly-driven EV.

#### DID 0x02FA — Cell Data (5 bytes)

Value: `0x81 85 A2 67 6D`. First byte `0x81` may be a flag/address byte. Remaining 4 bytes may pack cell group voltage or temperature data.

### Other BECM DIDs

| DID | Size | Value | Notes |
|-----|------|-------|-------|
| `0x02CA` | 2B | `0x0000` | Zero — inactive counter or flag |
| `0x02D1` | 1B | `0x00` | Status byte — thermal mode or contactor |
| `0x03DE` | 2B | `0x0000` | Zero |
| `0x0410` | 1B | `0x0F` (15) | Temperature or module count |
| `0x043F` | 2B | `0x0000` | Zero |
| `0x0440` | 7B | `02 01 02 06 04 12 00` | Configuration/calibration metadata |
| `0x04FC` | 3B | `0x000000` | Zero |
| `0x04FE` | 3B | `0x000000` | Zero |

### BECM Identity DIDs

| DID | Value | Description |
|-----|-------|-------------|
| `0xF186` | `0x01` | Active session (default) |
| `0xF187` | 9J1915234BL | Software part number |
| `0xF189` | 1652 | Software version |
| `0xF18B` | 3 bytes: YY MM DD | Manufacturing date |
| `0xF18C` | 20 chars | Serial number |
| `0xF191` | 9J1915234AJ | Hardware part number |
| `0xF192` | BCUe | Supplier HW ID (Battery Control Unit) |
| `0xF193` | 11.03 | Supplier HW version |
| `0xF194` | P2060_PAG_J1_BCU_BCU_APPL_ | Internal firmware identifier |
| `0xF195` | 12.43.02 | Internal SW version |
| `0xF197` | AA1652A | Calibration ID |
| `0xF19E` | EV_BECM1982091 | ASAM/ODX identifier |
| `0xF1A0` | 9J1909107A | Manufacturer data ID |
| `0xF1A3` | H14 | Hardware version |
| `0xF1AA` | AX2 | Workshop system ID |
| `0xF1B6` | `00 8C 00 7B` | VAG→DoIP address mapping |
| `0xF17C` | KT8-09604.11.2100290050 | FAZIT (factory acceptance test ID) |

---

## 5. DTC Status Byte Decoding

The DTC status byte is a bitmask defined by ISO 14229:

| Bit | Mask | Meaning |
|-----|------|---------|
| 0 | `0x01` | testFailed (currently failing) |
| 1 | `0x02` | testFailedThisMonitoringCycle |
| 2 | `0x04` | pendingDTC |
| 3 | `0x08` | confirmedDTC |
| 4 | `0x10` | testNotCompletedSinceLastClear |
| 5 | `0x20` | testFailedSinceLastClear |
| 6 | `0x40` | testNotCompletedThisMonitoringCycle |
| 7 | `0x80` | warningIndicatorRequested |

### Filtering for Real Faults

Only count DTCs where bits 0, 2, or 3 are set (testFailed, pending, or confirmed):

```python
is_fault = bool(status & 0x0D)  # bits 0, 2, 3
```

Status values of `0x10`, `0x40`, or `0x50` alone indicate incomplete self-tests, not actual faults. This distinction reduces the apparent DTC count from ~2800 (all entries including per-cell-module test status) to ~30 (real faults).

| Status | Meaning | Real Fault? |
|--------|---------|-------------|
| `0x08` | Pending only | Yes |
| `0x09` | Active + pending | Yes |
| `0x28` | Pending + confirmed | Yes |
| `0x2E` | Confirmed + pending + testFailed since clear | Yes |
| `0x2F` | Active + confirmed + pending | Yes (worst) |
| `0x10` | Test not completed since clear | No |
| `0x40` | Test not completed this cycle | No |
| `0x50` | Combined incomplete tests | No |

### BECM Cell Module DTC Entries

The BECM stores per-cell-module diagnostic entries (C01007 through C33109 — 33 modules x 3 parameters = 99 entries) all typically with status `0x50`. These are normal self-test status indicators, not faults.

---

## 6. Scan Protocol Analysis

Analysis of a captured pcap from a commercial scan tool reveals the optimal scan sequence.

### DID Read Order Per ECU

The scan tool reads these DIDs in order for each ECU:

1. `0xF19E` — ASAM/ODX identifier
2. `0xF1A2` — ASAM version
3. `0xF187` — Software part number
4. `0xF189` — Software version
5. `0xF191` — Hardware part number
6. `0xF1A3` — Hardware version
7. `0xF1AA` — Workshop system ID
8. `0xF17C` — FAZIT (factory acceptance test ID)
9. `0xF190` — VIN (not all ECUs store this)
10. `0x2A2F` — ECU type/class byte (single byte, not all ECUs support)
11. `0x2A30` — Self-identification (3 bytes)
12. Service `0x19` sub `0x02` mask `0xFF` — Read all DTCs

### Key Findings

**The scan tool does NOT read battery-specific DIDs.** It reads only identity data and DTCs from the BECM. The SoC, SoH, temperature, and telemetry DIDs were all discovered through independent DID enumeration.

**Parallel communication:** The gateway supports multiple outstanding requests. The scan tool fires requests to several ECUs before waiting for all responses. This is why a full 42-ECU scan completes in ~10 seconds rather than the ~25 seconds a serial approach takes.

**DID 0x2A30 is an address self-identification register.** The first byte is the VAG system code, the last two bytes are the DoIP address low bytes. This provides a programmatic way to discover the VAG-to-DoIP mapping without a static table.

**DID 0x2A2F is a single-byte ECU class/type identifier.** Only some ECUs respond. The BECM does not support it (NRC `0x31`).

---

## 7. Implementation Notes

### Use Raw Sockets

The Python `doipclient` and `udsoncan` libraries hang when connecting to this gateway. The issue is in routing activation handling or internal timeout management. Raw TCP sockets with manual DoIP header construction work perfectly and are simpler.

Similarly, the `udsoncan` library requires pre-registered DID definitions and has complex codec configuration. For DID enumeration and raw data reading, sending `0x22 [DID_high] [DID_low]` directly and parsing the `0x62` response is far more reliable.

### Interface Binding

On macOS with both Wi-Fi and Ethernet active, sockets must be explicitly bound to the link-local IP to ensure traffic routes through the ENET adapter:

```python
local_ip = "169.254.10.1"  # or auto-detect from ifconfig
sock.bind((local_ip, 0))
sock.connect(("169.254.x.x", 13400))
```

Without this, `sendto()` on UDP broadcasts and `connect()` on TCP may fail with `EHOSTDOWN` or `EADDRNOTAVAIL`.

### Timeout Recommendations

| Operation | Timeout | Notes |
|-----------|---------|-------|
| TCP connect | 5 seconds | Gateway responds instantly when awake |
| Routing activation | 3 seconds | Response within ~50ms |
| TesterPresent probe | 150–300ms | For address scanning |
| DID read | 1 second | Most respond within 200ms |
| DTC read | 2 seconds | Some ECUs return large responses |
| UDP discovery | 3 seconds | May need retry |

### SoC Display

The raw BMS SoC (DID `0x0286`) must be remapped to match the car's displayed percentage:

```python
displayed_soc = max(0, min(100, (raw - 5) / 132 * 100))
```

### DTC Counting

Filter by status bitmask. Only count DTCs where `(status & 0x0D) != 0`:

```python
is_real_fault = bool(status & 0x0D)  # bits 0 (active), 2 (pending), 3 (confirmed)
```

### Manufacturing Date Decoding

DID `0xF18B` returns 3 bytes: `[YY] [MM] [DD]` where year = 2000 + first byte.

```python
year = 2000 + raw[0]
month = raw[1]
day = raw[2]
```

### Gateway Sleep

The Taycan gateway goes to sleep after a period of inactivity, even with the ignition on. If the gateway stops responding:

1. Check physical link status (`ifconfig en7 | grep status`)
2. Cycle the ignition off, wait 5 seconds, then start again
3. Re-run UDP discovery — the gateway IP may change after restart

---

## 8. Open Questions

1. **DID 0x02BD sub-field boundaries** — need reads at different driving states (parked/driving/charging) to confirm voltage, current, and power byte positions and scaling factors.

2. **DID 0x02CB temperature** — strongly suspected to be battery min/max °C but needs a post-drive read where min != max to confirm.

3. **DID 0x0407 module status** — balancing hypothesis needs a mid-SoC read (e.g. 60%) to confirm that all values flip to `1` when balancing is not active.

4. **Extended session DIDs** — the intermittent DIDs (0x02E1 energy counter, 0x02FA cell data) may be reliably accessible in extended diagnostic session (service `0x10 0x03`). Not yet tested.

5. **Cell-level voltage data** — the BECM almost certainly has per-cell or per-module voltage data, but it may be behind security access (service `0x27`) or only available in extended/programming sessions.

6. **Inverter telemetry** — the front/rear inverters (`0x407C`, `0x40B8`) likely have non-standard DIDs with motor RPM, torque, and power data that haven't been enumerated.

7. **Parallel request optimisation** — implementing pipelined requests (sending multiple DIDs before collecting responses) would cut scan time from ~25s to ~10s.

8. **SoH scaling** — the 1:1 direct percentage appears correct (95–96% for a 2022 vehicle), but confirmation against an official Porsche dealer report would be definitive.

9. **DC charging telemetry** — all data captured so far was during AC charging. DC fast charging sessions may unlock different DID responses or higher-resolution data in the 0x02BD telemetry.

---

## UDS Service Reference

| Service | ID | Sub-function | Description |
|---------|-----|-------------|-------------|
| ReadDataByIdentifier | `0x22` | — | Read a DID value |
| ReadDTCInformation | `0x19` | `0x02` | Report DTCs by status mask |
| TesterPresent | `0x3E` | `0x00` | Keep-alive / ECU probe |
| DiagnosticSessionControl | `0x10` | `0x01`/`0x03` | Switch session (default/extended) |

### UDS Response Codes

| Byte | Meaning |
|------|---------|
| `0x62` | Positive response to ReadDataByIdentifier |
| `0x59` | Positive response to ReadDTCInformation |
| `0x7E` | Positive response to TesterPresent |
| `0x50` | Positive response to DiagnosticSessionControl |
| `0x7F` | Negative response (followed by service ID and NRC) |

### Common Negative Response Codes (NRC)

| NRC | Meaning |
|-----|---------|
| `0x11` | Service not supported |
| `0x12` | Sub-function not supported |
| `0x14` | Response too long |
| `0x31` | Request out of range (DID not supported) |
| `0x33` | Security access denied |
| `0x78` | Request correctly received, response pending |
