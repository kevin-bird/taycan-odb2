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

#### DID 0x028C — SoC Display (BMS-remapped percentage)

| Property | Value |
|----------|-------|
| Size | 1 byte |
| Encoding | Direct percentage, already remapped |
| Example | `0x39` (57) = 57% (car dashboard showed 56%) |

**IMPORTANT:** Initially assumed to be SoH, but confirmed as display-ready SoC:
- Car at ~97% → DID reads 96
- Car at 56% → DID reads 57

Tracks ~1% above the displayed SoC. This is the BMS's own pre-remapped value — use as a fallback when DID 0x0286 doesn't respond.

**The real SoH DID has not been conclusively identified yet.** See section 4.5 for SoH candidates under investigation.

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

### 4.5 Extended Session Findings (DID sweep 0x0500–0x1FFF)

A comprehensive sweep of the BECM in extended diagnostic session (0x10 0x03) revealed 134 additional DIDs not available in default session. These include per-module data, cell voltages, and SoH candidates.

#### SoH — DID 0x51E0 ✓ CONFIRMED

| Property | Value |
|----------|-------|
| DID | `0x51E0` |
| Size | 2 bytes (uint16 BE) |
| Session | Default (no extended session needed) |
| Formula | `raw * 0.127 - 1798.574` = percent |
| Sentinel | raw = 0x0000 → no data |
| Source | [OBDb/Porsche-Taycan](https://github.com/OBDb/Porsche-Taycan) signalset (signal `TAYCAN_HVBAT_SOH`) |

Community test data across model years:

| MY | Raw hex | Raw dec | SoH % |
|----|---------|---------|-------|
| 2020 | `0x3A00` | 14848 | 87.1% |
| 2021 | `0x39FC` | 14844 | 86.6% |
| 2022 | `0x3A02` | 14850 | 87.4% |
| 2023 | `0x3A31` | 14897 | 93.3% |
| 2024 | `0x3A28` | 14888 | 92.2% |

This DID was not found during initial investigation because it falls in the 0x5000–0xFFFF range which had not been swept.

#### DIDs 0x1E1C / 0x1E1E — BMS Current Limits (NOT SoH)

| DID | Size | Scan 1 | Scan 2 | Scan 3 |
|-----|------|--------|--------|--------|
| `0x1E1C` | 2 bytes | `0x035C` (860) | `0x0356` (854) | `0x02FA` (762) |
| `0x1E1E` | 2 bytes | `0x035C` (860) | `0x0356` (854) | `0x02FA` (762) |

**Not SoH — these are BMS discharge current limits (amps).** Per OBDb signalset:
- `0x1E1C` = Maximum dynamic discharge current limit (`TAYCAN_BMS_I_DCHG_LIM_DYN`)
- `0x1E1E` = Maximum predicted discharge current limit (`TAYCAN_BMS_I_DCHG_LIM_PRED`)

Values vary with temperature and SoC, which explains the 860→762 drop overnight as the battery cooled. Both DIDs always return identical values.

#### Cell voltage array — DID 0x0667 (396 bytes, 198 × uint16 BE)

The largest responding DID on the BECM. Offline analysis of the captured hex:

- **198 uint16 BE values** (396 bytes)
- High byte is always `0x01`, low byte varies from 19 to 150
- **Groups exactly into 33 modules × 6 values each**
- Within each module, **position 1 is always highest, position 5 is always lowest** — this is a sorted block, not raw cell voltages in physical order

**Structural interpretation:** Taycan Performance Plus has 12 cells per module wired as **6 parallel pairs**. This gives 6 unique voltage measurement points per module × 33 modules = **198 cell pair voltages across the whole pack**.

**Encoding hypothesis:** Raw value + 3400 mV offset
- Value range `0x0113` (275) → `0x0196` (406)
- Decoded range: **3675 mV to 3806 mV**
- At 57% SoC, this is plausible for NMC 811 cells
- Spread within a module: up to 131 mV (moderate-to-high imbalance)

**Verification required:** Read at very different SoC (e.g. 20%) and confirm:
1. Values track SoC (all shift down at low SoC)
2. Relative ordering between modules remains stable
3. Spread between highest and lowest cell grows under load

**Weakest module identified (captured at 57% SoC):**

| Rank | Module | Min raw | Min voltage | Spread |
|------|--------|---------|-------------|--------|
| 1 (worst) | 26 | 275 | 3.675 V | 91 mV |
| 2 | 23 | 281 | 3.681 V | 99 mV |
| 3 | 13 | 288 | 3.688 V | 92 mV |
| 3 | 16 | 288 | 3.688 V | 92 mV |
| 3 | 25 | 288 | 3.688 V | 92 mV |
| 6 | 2, 9, 10, 15 | 294 | 3.694 V | 92-99 mV |

Module 26 has the weakest cell pair in the pack — the first to degrade. Module 23 has the widest internal spread (99 mV), suggesting active imbalance.

**Position pattern across all 33 modules (mean values):**
- Position 1: 377 (highest, always)
- Position 2: 346
- Position 3: 327
- Position 4: 320
- Position 5: 313 (lowest, always)
- Position 6: 322

Positions 1 and 5 may be max/min cell in the module. Positions 2-4 may be intermediate cells or historical readings. Position 6 may be module average or the 6th physical cell pair.

#### Per-module status — DIDs 0x1821–0x1841 (33 × 3 bytes)

33 ECUs each returning a 3-byte ASCII-looking code:

```
0x1821: 4E 4D 53  "NMS"
0x1822: 4E 4F 54  "NOT"
0x1823: 4D 4D 52  "MMR"
0x1824: 4E 4E 53  "NNS"
0x1825: 4F 4F 55  "OOU"
...
```

33 entries = one per battery module. Letters cluster around `M/N/O` and `R/S/T/U` — likely state codes. Hypothesis:
- First letter: cell group A status (N=normal, M=marginal, O=??)
- Second letter: cell group B status
- Third letter: module flag (S=standard, T=trickle charging, U=unbalanced, R=resting)

**Needs:** Correlate with 0x0407 module status and read across multiple states to map the code meanings.

#### Per-module detailed data — DIDs 0x1850–0x1870 (33 × 43 bytes) ✓ DECODED

33 blocks of 43 bytes each. Fully decoded offline from the captured hex dump.

**Block structure:**
```
Byte  0:     Module ID (row, col hex nibbles)
Bytes 1-3:   Triplet 1: 0x91 [val] 0x39
Bytes 4-6:   Constant: 0x1E 0x02 0x66
Byte  7:     Constant: 0x82
Bytes 8-10:  Triplet 2: 0x91 [val] 0x39
Bytes 11-14: Padding: 0x00 0x00 0x00 0x00
Bytes 15-17: Triplet 3: 0x91 [val] 0x39
Byte  18:    Constant: 0x83
Bytes 19-21: Padding: 0x00 0x00 0x00
Bytes 22-24: Triplet 4: 0x91 [val] 0x39
Bytes 25-28: Constant: 0x00 0xD1 0x08 0x20
Bytes 29-31: Triplet 5: 0x91 [val] 0x39
Bytes 32-35: Constant: 0x09 0x00 0x20 0x80
Bytes 36-38: Triplet 6: 0x91 [val] 0x39
Bytes 39-42: Padding: 0x00 0x00 0x00 0x00
```

Each triplet follows the pattern `0x91 [value] 0x39`:
- `0x91` — constant flag
- `[value]` — the actual voltage (or metric)
- **`0x39` = 57 — the current SoC!** The BMS is timestamping each reading with the SoC at capture

**Pack topology revealed:**

The module ID byte encodes physical position as (row, col) hex nibbles. Mapping all 33 blocks:

```
Col→     1    2    3    4
Row 1:  0x11 0x12 0x13 0x14
Row 2:  0x21 0x22 0x23 0x24
Row 3:  0x31 0x32 0x33 0x34
Row 4:  0x41 0x42 0x43 0x44
Row 5:  0x51 0x52 0x53 0x54
Row 6:  0x61 0x62 0x63 0x64
Row 7:  0x71 0x72 0x73 0x74
Row 8:  0x81 0x82 0x83 0x84
Row 9:  0x91   —    —    —
```

**The Taycan Performance Plus pack is 8 rows × 4 columns + 1 extra module = 33 modules.** The 33rd module (position 9,1) is physically isolated from the main grid.

**Decoded voltage range (raw values 150-210, resolution 10 mV):**

With `raw + 3500 mV` offset hypothesis:
- Minimum: **3650 mV** (raw 150)
- Maximum: **3710 mV** (raw 210)
- Total spread: 60 mV across all 198 values
- Mean: 3679 mV

All values are multiples of 10, so the resolution is ~10 mV.

This is a **much tighter spread than DID 0x0667** (which showed 131 mV). Hypothesis:
- `0x0667` = historical min/max envelopes or statistical bounds (3675-3806 mV)
- `0x1850-0x1870` = current live cell pair voltages (3650-3710 mV)

**Weakest modules at time of capture (57% SoC):**

| DID | Physical Position | Min raw | Min voltage | Spread within module |
|-----|------|---------|-------------|----------------------|
| `0x1851` | **Row 2, Col 1** | 150 | 3650 mV | 30 mV |
| `0x185B` | **Row 2, Col 3** | 150 | 3650 mV | 20 mV |
| `0x1856` | Row 6, Col 3 | 160 | 3660 mV | 40 mV |
| `0x1859` | Row 1, Col 2 | 160 | 3660 mV | 20 mV |
| `0x185D` | Row 2, Col 2 | 160 | 3660 mV | 10 mV |

**Row 2 contains three of the four weakest modules (2,1 / 2,2 / 2,3).** These are physically adjacent — likely sharing a cooling plate. Possible causes:
1. **Thermal hotspot** — row 2 runs warmer than surrounding rows, accelerating wear
2. **Cooling deficiency** — coolant flow may be suboptimal in that zone
3. **Manufacturing batch** — all three modules from the same supplier batch
4. **Bus bar resistance** — electrical stress concentrated in that section

**Recommendation:** A thermal imaging check of the battery after a drive cycle would confirm whether row 2 runs hotter than the rest of the pack.

#### Other newly discovered DIDs

| DID | Size | Value | Hypothesis |
|-----|------|-------|------------|
| `0x02E0` | 4B | `b9 1b 6f ce` → `86 0f 6f a3` | Changed between reads — live counter, may be SoH tracker |
| `0x02F9` | 5B | `81 85 a2 67 6d` | Static — same as 0x02FA from default session |
| `0x0600` | 14B | all zeros | Unused field |
| `0x061E` | 11B | `T9J1010    ` | Internal part code |
| `0x061F` | 11B | `T9J1100    ` | Internal part code |
| `0x0620` | 11B | `TPNP020538 ` | Internal part/type code |
| `0x0621` | 11B | `TPNP020539 ` | Internal part/type code |
| `0x0622` | 11B | `T9J1011    ` | Internal part code |
| `0x0806` | 2B | `0x0525` (1317) | Unknown counter |
| `0x1801` | 2B | `0x1CD5` (7381) | Unknown — may be pack voltage in 0.1V |
| `0x1802` | 3B | `0x024929` | Large counter (149,801) |
| `0x1804` | 3B | `0x024AA6` | Large counter (150,182) — similar to 0x1802 |
| `0x1808` | 2B | `0xFFFF` | Unused/max value |
| `0x1809` | 2B | `0xFFFE` | Unused/max |
| `0x180A` | 2B | `0x1CCC` (7372) | Similar magnitude to 0x1801 |
| `0x180B` | 2B | `0x1CCF` (7373) | Similar magnitude |
| `0x180C`–`0x180F` | 1B each | `4D, 4F, 4D, 4F` = "MOMO" | Status letters |
| `0x1810` | 1B | `0x89` (137) | Hmm, matches full-charge SoC max |
| `0x1811` | 194B | structured block | Large config/status record |
| `0x1817` | 2B | `0x0101` | Flag pair |
| `0x1818` | 2B | `0x1CE1` (7393) | Voltage-related counter |
| `0x181B` | 2B | `0x1CDE` (7390) | Voltage-related counter |
| `0x181C` | 1B | `0x4B` = 'K' | Letter code |
| `0x181D` | 1B | `0x4C` = 'L' | Letter code |
| `0x1900` | 4B | `0x00015E3D` (89,661) | Large counter — cycle count? km driven? |
| `0x1901` | 4B | `0x000141B5` (82,357) | Large counter |
| `0x192A` | 1B | `0x07` | Status |
| `0x192B` | 1B | `0x38` (56) | Matches displayed SoC! |
| `0x1E17`–`0x1E1A` | 3B each | voltage triplets | Per-cell or per-module summary |
| `0x1E18` | 3B | `03 E8 04` | 1000 + flag byte — matches 0x040F pattern |
| `0x1E1B` | 2B | `0x0229` (553) | Paired with 0x1E1C |
| `0x1E1D` | 2B | `0x0229` (553) | Paired with 0x1E1E |
| `0x1E26`–`0x1E28` | 3B each | `01 02 E3` | Three identical — charge/discharge limits? |
| `0x1E2C` | 2B | `0x3930` ("90") | ASCII digits |
| `0x1E2D` | 2B | `0x394B` ("9K") | ASCII code |
| `0x1E33` | 3B | `91 D2 0D` | Same pattern as per-module data |
| `0x1E34` | 3B | `91 96 0B` | Same pattern as per-module data |
| `0x1E3B` | 2B | `0x1CD9` (7385) | Voltage-related counter |

The cluster of values around `0x1CCC`–`0x1CE1` (7372–7393) is suspicious. If these are pack voltages with ×0.1V scale, that's 737–739V. But the car is currently at ~867V per DID 0x02BD. So maybe they're stored voltages from a different time (resting voltage? pre-charge?), or they use a different scale.

---

## 4.6 Investigation sweep — other powertrain ECUs

A full investigation sweep across priority 1-4 ECUs was performed using `run_investigation.py`. Findings below.

### Front Inverter (0x407C) — 27 DIDs found

Range swept: `0x0100-0x1FFF`, extended session. Most responses were 0 because the car was stationary (motors not spinning).

**Identity:**
- `0x1FFF` (20 bytes) = `V8.17.10F` — **Inverter firmware version** (unique to 0x407C/0x40B8)

**Shared HV bus data** (same DIDs as BECM, same values):
- `0x02BD` (10 bytes) = same pack telemetry as BECM (voltage/current)
- `0x02CB` (2 bytes) = `0f 0f` (battery temp min/max in °C)
- `0x0410` (1 byte) = `0x0F` — same temp indicator as BECM

**Inverter-specific (differs between front/rear):**
- `0x028D` (2 bytes) = `0x067F` (1663) on front, `0x074C` (1868) on rear — **likely motor RPM or torque** (needs driving session to confirm)
- `0x02E0` (4 bytes) = unique counter per inverter
- `0x02FF` (19 bytes) = power electronics state block, differs between front/rear
- `0x02BD` byte 4 = inverter state byte

**At rest (all zero, will populate while driving):**
- `0x0407` (8 bytes) = module status
- `0x040F` (8 bytes) = motor control data
- `0x02EF` (6 bytes) = unused
- `0x13B0-0x13B5` (1 byte each) = motor event counters

### Rear Inverter (0x40B8) — 27 DIDs found

Identical DID layout to the front inverter. Firmware is also `V8.17.10F`. All the shared HV bus DIDs return identical values since both inverters see the same DC link.

### On-Board Charger (0x4044) — 145 DIDs found

Range swept: `0x0100-0x1FFF`, extended session. The OBC was active (AC charging at 10.5A), so many DIDs returned live data.

**Identity sub-components:**
- `0x0611` (28 bytes) = dual part numbers `9J1915737AB` / `9J1915737AC`
- `0x0612` (14 bytes) = `0090` / `0090`
- `0x0613` (12 bytes) = `H03` (hardware version)
- `0x0614` (28 bytes) = `9J1915737` / `9J1915737` (base part)
- `0x0615` (46 bytes) = manufacturing dates `19.07.21` etc.
- `0x0616` (52 bytes) = supplier version `8BS-8BS19.07.21100104 03`
- `0x0617` (32 bytes) = sub-component IDs `UX4 ETSA1` / `UX5 ETSA2`

The OBC has **two parallel charging paths** (UX4/UX5) each with its own part number and supplier ID. These are the two AC charging channels.

**ISO 15118 Plug & Charge certificate:**
- `0x104B` (2857 bytes) — **X.509 DER-encoded certificate** (starts with `30 82 02 53...`)
- Used for secure DC fast charging authentication
- This is the public identity certificate; the private key is not accessible

**Large configuration blocks:**
- `0x0C4B` (2407 bytes) — OBC firmware/config dump, starts with magic `01 23 45 67 00`
- `0x080C` (30 bytes) = `00000000020000000002A51600EU00` — region/part config code

**Live charging telemetry (captured at 10.5A AC):**
- `0x1501` (2 bytes) = `0x0360` (864) — incrementing counter
- `0x1507` (9 bytes) = voltage triplet pattern
- `0x1525` / `0x1529` (2 bytes each) = `12 07` (1810)
- `0x1553` (2 bytes) = `0x0800` (2048) — power limit
- `0x1554` (2 bytes) = `0x0B80` (2944)
- `0x1557` (2 bytes) = `0x05B4` (1460) — possibly charge current limit
- `0x1558` (2 bytes) = `0x0D32` (3378)
- `0x155A` (2 bytes) = `0x0FFC` (4092) — max power?
- `0x15E2` (1 byte) = `0x3C` (60) — temperature or percent
- `0x15EE` (4 bytes) = `00 02 06 B9` (132,793) — session counter
- `0x15EF` (4 bytes) = `00 02 14 FB` (136,443) — session counter
- `0x15F3` (4 bytes) = `01 02 3D 3D` (17,054,525) — **lifetime energy counter** (plausible Wh total)

**3-phase grid voltage (strong candidate):**
- `0x1DDA` (5 bytes) = `00 00 FF 02 EE`
- `0x1DDB` (9 bytes) = `00 00 FF 02 EE 02 EE 02 F9`
  - Three 16-bit values: `0x02EE` (750), `0x02EE` (750), `0x02F9` (761)
  - These look like **3-phase AC grid voltages**. At UK 230V supply, raw / 3.26 ≈ 230V
  - Or another scale may give exactly 230V mapping
  - Will need to vary (switch between Type 2 and wall socket, or DC fast charge) to confirm

**Internal OBC state (0x1DD0-0x1DFA):**
- `0x1DD0` (1 byte) = `0x6E` (110) — temperature candidate
- `0x1DD6` (2 bytes) = `0x0003` — state byte
- `0x1DE8` (4 bytes) = `00 4B 00 12` — two 16-bit values (75, 18)
- `0x1DE9` (4 bytes) = `00 2B 00 54` — two 16-bit values (43, 84)
- `0x1DF2` (1 byte) = `0x03` — OBC status

### DC-DC Converter (0x40B7) — 95 DIDs found

Range swept: `0x0100-0x1FFF`, extended session. The DC-DC was active (converting 800V HV bus down to 12V for accessories).

**Shared HV bus data:** Same `0x02BD`, `0x02CB`, `0x0410` values as all other powertrain ECUs.

**Live telemetry:**
- `0x1100` (2B) = `0x0216` (534) — candidate **LV (12V) bus voltage** at ~0.025V scale → ~13.35V (reasonable for 12V bus at rest)
- `0x1101` (2B) = `0x01FE` (510) — candidate **LV current**
- `0x1102` (2B) = `0x0B82` (2946) — possibly input current reference
- `0x1104` (2B) = `0x02D7` (727)
- `0x1105` (2B) = `0x0074` (116) — could be current in 0.1A = 11.6A
- `0x1540` (24B) = array with values `7D 04 94 03 F4 02 6A` — 4 × uint16 readings
- `0x1543` (10B) = ends with `0B EA` (3050) — HV bus voltage candidate × 0.265 ≈ 808V ✓
- `0x1550` (10B) = starts with `0B CD` (3021) — HV bus × 0.265 ≈ 800V ✓
- `0x1551` (10B) = starts with `0B F5` (3061) — HV bus × 0.265 ≈ 811V ✓
- `0x15E2` (1B) = `0x41` (65) — **DC-DC internal temperature** (65°C during conversion is reasonable)

**Measurement history arrays (0x1522-0x1529):** Eight 18-byte records each with the same layout: 5 zero bytes, then 4 × uint16 values. These look like rolling time-series snapshots of DC-DC operating points. Values are similar between records (within 10%).

### HV Booster (0x40C7) — 114 DIDs found

Range swept: `0x0100-0x1FFF`, extended session.

**Shared HV bus data:** Same pack telemetry as all other powertrain ECUs (`0x02BD`, `0x02CB`, etc.).

**Idle state:** The HV booster is the DC fast-charge voltage booster. At AC charging, most of its telemetry is zero (the booster is inactive). Only identity and shared HV bus data is populated.

**Interesting DIDs (mostly for future DC charging session):**
- `0x0912` (2B) = `0x0064` (100) — possibly 100% status
- `0x0914` (2B) = `0x01F9` (505) — voltage candidate × 0.1 = 50.5V
- `0x0917` (2B) = `0x01F4` (500) — 50.0V candidate
- `0x091C` / `0x091E` (2B) = `0x0208` (520) — 52.0V candidate
- `0x1101` (2B) = `0x0800` (2048) — matches OBC value
- `0x1102` (2B) = `0x0B80` (2944) — matches OBC value
- `0x1104` (2B) = `0x05B4` (1460) — matches OBC charge current limit
- `0x1107` (2B) = `0x05B4` (1460) — same
- `0x1109-0x110B` (4B each) = close voltage pairs (~2865-2903)
- `0x1112` (2B) = `0x05CE` (1486)
- `0x1113` (2B) = `0x0B82` (2946)
- `0x1500` (2B) = `0x0256` (598) — counter
- `0x1501` (2B) = `0x03D6` (982) — counter
- `0x1507`-`0x1509` (3B each) = `0x004DE4`, `0x004DCC`, `0x004E06` (19940, 19916, 19974) — **triple close values, likely 3-phase temperatures** at 0.001°C scale → 19.94°C, 19.92°C, 19.97°C (matches ambient)
- `0x15E2` (1B) = `0x3F` (63) — temperature
- `0x15E3` (1B) = `0x3C` (60) — temperature
- `0x1609` (2B) = `0x0DEF` (3567)

**Time-series arrays 0x1512, 0x1520-0x1570:** 20+ records of 18 bytes each, same format as DC-DC. Values vary between records but follow similar patterns. These are rolling snapshots of booster operating conditions.

### Standardized charging-ECU DID layout

The OBC, DC-DC, and HV Booster **all share the same DID address space layout**:
- `0x1100-0x111F` — live telemetry pairs
- `0x1500-0x15FF` — counters and status
- `0x1520-0x1570` — time-series measurement arrays (18 bytes each)
- `0x15E2/0x15E3` — temperature (consistent across all 3 ECUs)
- `0x1DD0-0x1DFA` — internal state

This is a standardized framework within the Porsche HV charging/conversion ECUs.

### What we still need

1. **Driving session** — to unlock inverter motor telemetry (RPM, torque, phase currents). Also fills in the inverter DIDs that are currently zero.
2. **Different charge rates** — to calibrate OBC grid voltage encoding and power counters
3. **DC fast charge session** — HV Booster is inactive during AC charging; DC fast charging will populate its telemetry
4. **0x02BD byte 4 variation** — the one byte in pack telemetry that changes with unknown encoding
5. **Priorities 3-4 sweeps** — Thermal Mgmt, ESP, Cluster, VCU, Air Susp, EPS still pending. These would reveal ambient temp, odometer, drive mode, etc.

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

## 8. Investigation Plan

### Current state
- **SoC:** fully decoded (DID 0x0286 with remap, fallback DID 0x028C as direct %)
- **Pack voltage/current/power:** decoded from DID 0x02BD
- **Temperature:** decoded from DID 0x02CB (min/max °C)
- **Module balancing:** partial (DID 0x0407)
- **SoH:** ✓ CONFIRMED — DID 0x51E0, default session, formula `raw * 0.127 - 1798.574`
- **Cell-level data:** decoded (0x0667 = 198 cell pair voltages, 0x1850–0x1870 = per-module grid)

### Priority 1: Find the SoH DID — ✓ DONE

**SoH confirmed as DID 0x51E0** on the BECM (default session, 2 bytes uint16 BE). Source: [OBDb/Porsche-Taycan](https://github.com/OBDb/Porsche-Taycan) community signalset. See section 4.5 for full details.

**Previous candidates ruled out:**
- 0x1E1C/0x1E1E: BMS discharge current limits (amps), not SoH. Vary with temperature/SoC.
- 0x028C: SoC display value, not SoH.
- BECM upper range 0x2000-0x4FFF: swept, only 1 hit (factory part code).

### Priority 2: Decode cell-level data

**DID 0x0667 (396 bytes)** — the most likely cell voltage array

Format: 198 × uint16 BE, all prefixed with `0x01XX`
- Decoded range: 0x0119–0x0196 (281–406)
- At `×10 mV` scale: 2810–4060 mV — matches Li-ion cell range
- Performance Plus has 396 cells in 33 modules — 198 values = half, or 6 per module

**To decode:**
1. Read at high SoC (>80%) and note the value distribution
2. Read at low SoC (<30%) and note the swing
3. Cells with smallest swing = weakest (highest internal resistance)
4. Write a cell voltage heatmap visualisation

**DIDs 0x1850–0x1870 (33 × 43 bytes)** — per-module detailed data

Each block starts with a module index byte, then structured cell data. The repeating `0x91 XX 39 XX 02 66 82` pattern suggests encoded cell voltages with status flags.

**To decode:**
1. Line up the 33 blocks and identify which bytes change between modules
2. Cross-reference byte positions with DID 0x0667 values
3. Map the `0x39` (SoC) and `0x91` (flag) byte positions

**DIDs 0x1821–0x1841 (33 × 3 bytes)** — per-module status codes

ASCII letter triplets like "NMS", "NOT", "MMR". Each module has one entry.

**To decode:**
1. Correlate with module numbers from 0x0407
2. Read when balancing is active vs inactive
3. Letters likely represent cell states (Normal/Marginal/??, Standard/Trickle/Unbalanced/Resting)

### Priority 3: Complete the DID sweep

Ranges swept on the BECM:
- `0x0100–0x1FFF` — 134 DIDs found (extended session)
- `0x2000–0x4FFF` — 1 DID found (factory part code at 0x484E)
- `0x5000–0xFFFF` — contains SoH (0x51E0), further sweep pending

Remaining unswept ranges on other ECUs:
- `0x5000–0xEFFF` — high manufacturer range on VCU, Gateway, Cluster

### Priority 4: Verify hypotheses at different states

Each of these DIDs has a static hypothesis that needs confirmation:

| DID | Hypothesis | Test condition |
|-----|-----------|----------------|
| `0x02BD` byte 4 | Sub-voltage or power | Read while driving (should swing) |
| `0x02BD` byte 5 | Temperature ×0.5°C | Read after drive (should rise) |
| `0x02CB` | Battery temp min/max | Read after drive (min ≠ max) |
| `0x0407` | Module balancing | Read at mid-SoC (should all be 1) |
| `0x0440` | Calibration data | Static — no test needed |

### Priority 5: Other ECUs

- **Front Inverter (0x407C):** enumerate manufacturer DID range for motor RPM, torque, temperature
- **Rear Inverter (0x40B8):** same
- **OBC (0x4044):** charge current limits, grid voltage, session duration
- **DC-DC (0x40B7):** 12V bus voltage, current, efficiency
- **HV Booster (0x40C7):** charge boost telemetry

---

## 9. Known unknowns

1. **SoH location** — ✓ FOUND. DID `0x51E0` on BECM, default session, `raw * 0.127 - 1798.574`. Source: OBDb/Porsche-Taycan. Previous candidates 0x1E1C/0x1E1E confirmed as BMS discharge current limits (amps).
2. **DID 0x02BD byte 4** — changes with voltage, but encoding unclear
3. **DID 0x02F9/0x02FA** — 5-byte cell data blocks, first byte `0x81` looks like a flag
4. **DIDs 0x1900/0x1901** — 4-byte counters (89,661 and 82,357) — km driven? charge cycles? Wh counters?
5. **Parallel request support** — would cut scan time from 25s to 10s
6. **Security access** — service `0x27` has not been attempted; some DIDs (including SoH) may unlock only after security challenge
7. **DC charging data** — all reads so far are AC charging only. DC fast charging would populate HV Booster telemetry and may reveal different OBC behaviour
8. **Inverter motor data** — 0x028D returns non-zero at rest (1663/1868) — meaning unknown. Motor RPM/torque/phase data likely zero until driving
9. **OBC grid voltage scale** — raw values 750/761 from 0x1DDB map to ~230V EU supply but exact scale factor unconfirmed
10. **BECM 0x5000-0xFFFF range** — contains SoH (0x51E0), full sweep of remaining DIDs pending

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
