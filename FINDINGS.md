# Taycan J1.1 DoIP Diagnostic Protocol — Complete Findings

**Vehicle:** Porsche Taycan 4S (MY2022)
**VIN:** WP0ZZZY1ZNSA62822
**Platform:** J1.1 (pre-facelift, 2020–early 2024)
**Battery:** Performance Battery Plus (93.4 kWh nominal)
**Date:** 2026-04-10
**Method:** Mac → BMW ENET cable → OBD-II port → raw TCP sockets

---

## 1. Network topology

### Physical layer
The Taycan's OBD-II port exposes Ethernet on pins 3 and 11 (standard DoIP pinout). A standard "BMW ENET cable" (~£8 on Amazon) connects this to a laptop's Ethernet port via RJ45. No special hardware, no ELM327, no CAN adapter required.

### IP configuration
| Node | IP address | MAC |
|------|-----------|-----|
| Gateway (Taycan) | 169.254.217.237 | 48:16:93:94:ed:d8 |
| Tester (Mac) | 169.254.10.1 (static) | — |
| Subnet mask | 255.255.0.0 | — |

The gateway uses a link-local address in the 169.254.x.x range. The Mac's Ethernet adapter must be configured with a static IP in the same subnet. Broadcast address for UDP discovery: 169.254.255.255.

### Protocol stack
```
Ethernet → IPv4 → TCP (port 13400) → DoIP (ISO 13400) → UDS (ISO 14229)
```

All diagnostic communication flows through a single TCP connection to the gateway. The gateway internally routes UDS requests to individual ECUs over FlexRay and CAN buses. This means one cable, one connection, access to all 42 ECUs.

---

## 2. DoIP protocol details

### Gateway discovery (UDP)
Send a Vehicle Identification Request (payload type 0x0001) via UDP broadcast to port 13400. The gateway responds with payload type 0x0004 containing:

| Offset | Length | Content |
|--------|--------|---------|
| 8–24 | 17 bytes | VIN (ASCII) |
| 25–26 | 2 bytes | Gateway logical address (uint16 BE) = 0x4010 |
| 27–32 | 6 bytes | MAC address |
| 33 | 1 byte | Further action required (0x10 = routing activation needed) |

The gateway emits 13 unsolicited Vehicle ID Responses during startup (observed in pcap). Any of these can be used for discovery without sending a request.

### Routing activation (TCP)
After establishing a TCP connection to 169.254.217.237:13400, send a Routing Activation Request before any diagnostic messages:

```
Header: 02 FD 00 05 00 00 00 07
Payload: [tester_addr: 0E 80] [activation_type: 00] [reserved: 00 00 00 00]
```

Response code 0x10 in byte 12 = routing activation accepted.

### DoIP header format (all messages)
```
[version: 0x02] [inverse: 0xFD] [payload_type: uint16 BE] [payload_length: uint32 BE]
```
Total header: 8 bytes, always big-endian.

### Diagnostic message wrapping
Every UDS request/response is wrapped in a DoIP diagnostic message (payload type 0x8001):
```
[DoIP header: 8 bytes]
[source_address: uint16 BE]  — 0x0E80 for tester, 0x40xx for ECU
[target_address: uint16 BE]  — target ECU or tester
[UDS payload: variable]
```

Response flow: the gateway first sends a Diagnostic Positive Ack (0x8002) confirming it accepted the message, then the actual diagnostic response (0x8001) arrives from the target ECU.

If the target address is unreachable, the gateway returns a Diagnostic Negative Ack (0x8003) instead.

### Functional addressing (broadcast)
Address 0xE400 is the DoIP functional addressing target. A TesterPresent (0x3E 0x00) sent to 0xE400 causes ALL connected ECUs to respond simultaneously. This is the fastest way to discover which ECUs are alive — one message instead of probing 42 addresses individually.

Observed in the pcap: the scan app sends TesterPresent to 0xE400, then immediately starts reading identity DIDs from all responding addresses in parallel.

### Key addresses
| Address | Role |
|---------|------|
| 0x0E80 | Tester (our diagnostic tool) |
| 0x4010 | DoIP Gateway |
| 0xE400 | Functional broadcast (all ECUs respond) |
| 0x40xx | Individual ECU addresses (see section 3) |

---

## 3. Complete ECU address map

42 ECUs confirmed responding. All live in the 0x40xx range. Discovered via brute-force TesterPresent sweep and confirmed against MapEV Diag scan report and Wireshark pcap capture.

### Powertrain and HV system

| DoIP addr | VAG code | Name | Workshop ID | ASAM ID | SW number |
|-----------|----------|------|-------------|---------|-----------|
| 0x4076 | 0x01 | Powertrain Control (VCU/ASG) | ESCP5 | EV_VCU00XXX0209J1909101XX | 9J0909101AQ |
| 0x407B | 0x8C | Battery Energy Control (BECM) | AX2 | EV_BECM1982091 | 9J1915234BL |
| 0x407C | 0x51 | Front Inverter (Bosch HIAMS) | J841 | EV_PWR1HIAMSPO513 | 9J1907121BG |
| 0x40B8 | 0xCE | Rear Inverter (Bosch HIAMS) | J944 | EV_PWR2HIAMSPO513 | 9J1907124AM |
| 0x4044 | 0xC6 | On-Board Charger (OBC) | J1050 | EV_OBC3Phase1KLOMLBev16B | 5QE915684DA |
| 0x40B7 | 0x81 | DC-DC Converter (800V→12V) | A48 | EV_DCDC400VBasisPREHPO513 | 9J1959663BE |
| 0x40C7 | 0xFF | HV Booster (charge boost) | J1178 | EV_HVChargBoostPREHPO513 | 9J1915539DC |

### Chassis

| DoIP addr | VAG code | Name | Workshop ID | ASAM ID |
|-----------|----------|------|-------------|---------|
| 0x4013 | 0x03 | Brakes / ESP | J104 | EV_ESP9BOSCHPO513 |
| 0x4012 | 0x44 | Power Steering (EPS) | J500 | EV_EPSBOPO68X |
| 0x4080 | 0x74 | Air Suspension | J775 | EV_ChassContrContiPO513 |
| 0x403B | — | Brake Boost | — | (discovered, not in MapEV config) |

### Body and comfort

| DoIP addr | VAG code | Name | Workshop ID | ASAM ID |
|-----------|----------|------|-------------|---------|
| 0x400E | 0x09 | Body Control Module (BCM) | J519 | EV_BCM1BOSCHAU651 |
| 0x408B | 0x46 | Comfort Module | J393 | EV_BCM2HellaAU736 |
| 0x4015 | 0x15 | Airbag | J234 | EV_AirbaVW31SMEAU65x |
| 0x404A | 0x42 | Door Electronics Driver | J386 | EV_DCU2DriveSideMAXHCONT |
| 0x404B | 0x52 | Door Electronics Passenger | J387 | EV_DCU2PasseSideMAXHCONT |
| 0x403E | 0xBB | Door Electronics Rear Driver | J388 | EV_DCU2RearDriveMAXHCONT |
| 0x403F | 0xBC | Door Electronics Rear Passenger | J389 | EV_DCU2RearPasseMAXHCONT |
| 0x4023 | 0x6D | Deck Lid | J605 | EV_DeckLidCONTIAU536 |
| 0x404C | 0x36 | Seat Adjustment Driver | J136 | EV_SCMDriveSideCONTIAU736 |
| 0x404D | 0x06 | Seat Adjustment Passenger | J521 | EV_SCMPasseSideCONTIAU736 |
| 0x400C | 0x16 | Steering Column Electronics | J527 | EV_SMLSKLOAU736 |
| 0x40A5 | 0xDE | Wireless Charger (Qi) | J1146 | EV_Charg1MobilDevicAU651 |

### Lighting

| DoIP addr | VAG code | Name | Workshop ID | ASAM ID |
|-----------|----------|------|-------------|---------|
| 0x4096 | 0xD6 | Light Control Left | A31 | EV_LLPGen3LKEBODPO68X |
| 0x4097 | 0xD7 | Light Control Right | A27 | EV_LLPGen3RKEBODPO68X |

### Climate and thermal

| DoIP addr | VAG code | Name | Workshop ID | ASAM ID |
|-----------|----------|------|-------------|---------|
| 0x4046 | 0x08 | Climate Control | J301 | EV_ACClimaBHTCPO513 |
| 0x4042 | 0xC5 | Thermal Management | J1024 | EV_ThermContrVISAU49X |

### Infotainment, ADAS, and comms

| DoIP addr | VAG code | Name | Workshop ID | ASAM ID |
|-----------|----------|------|-------------|---------|
| 0x4073 | 0x5F | Infotainment (PCM) | J794 | EV_MUTI |
| 0x4014 | 0x17 | Instrument Cluster | K | EV_DashBoardLGEPO513 |
| 0x4057 | 0x13 | Adaptive Cruise Control | J428 | EV_ACCBOSCHAU65X |
| 0x404F | 0xA5 | Front Sensors (ADAS) | J1121 | EV_ZFASAU516 |
| 0x4067 | 0x75 | Telematics (TCU) | J949 | EV_ConBoxHighAU49X |
| 0x406F | 0x47 | BOSE Audio | J525 | EV_AMPMst16C4Gen2BOSE |

### Sound and aerodynamics

| DoIP addr | VAG code | Name | Workshop ID | ASAM ID |
|-----------|----------|------|-------------|---------|
| 0x401C | 0xA9 | Structure-Borne Sound | — | EV_ActuaForIntNoise |
| 0x4064 | 0xC0 | E-Sound (exterior noise) | — | EV_ESoundMLBEvoS1NN |
| 0x4024 | 0x6B | Aerodynamics Control | J223 | EV_MASGMarquPO622 |

### Other

| DoIP addr | VAG code | Name | Workshop ID | ASAM ID |
|-----------|----------|------|-------------|---------|
| 0x4010 | 0x19 | Gateway | J533 | EV_Gatew31xPO513 |
| 0x400B | 0x65 | Tire Pressure (TPMS) | J502 | EV_RDKHUFPO68X |
| 0x4053 | — | Gear Selector | J587 | EV_GSMWaehlJOPPPO68X |
| 0x4086 | — | OTA Update (OTAFC) | J1222 | EV_OTAFCHarmaPO513 |

### VAG-to-DoIP address mapping

Every ECU stores its own address mapping in DID 0xF1B6 (4 bytes):
```
[0x00] [VAG_system_code] [0x00] [DoIP_low_byte]
```
Example from BECM: `00 8C 00 7B` → VAG 0x8C maps to DoIP 0x407B (the 0x40 prefix is implicit).

Additionally, DID 0x2A30 returns a 3-byte self-identification on most ECUs where the last 2 bytes are the ECU's own address identifier (e.g. 0x4012 returns `44 40 12`).

---

## 4. BECM battery data (0x407B)

### ECU identity

| Property | Value |
|----------|-------|
| ASAM/ODX ID | EV_BECM1982091 |
| Software part number | 9J1915234BL |
| Software version | 1652 |
| Hardware part number | 9J1915234AJ |
| Hardware version | H14 |
| Internal firmware | P2060_PAG_J1_BCU_BCU_APPL_ v12.43.02 |
| Calibration ID | AA1652A |
| Supplier HW ID | BCUe (Battery Control Unit) |
| Manufacturing date | 2021-11-04 |
| Serial number | 00000037210000675595 |
| Workshop ID | AX2 |
| FAZIT | KT8-09604.11.2100290050 |

### Confirmed battery DIDs

#### DID 0x028C — State of Charge (SoC) ✓ PRIMARY SOURCE
- **Size:** 1 byte
- **Scale:** direct percentage (BMS internal SoC, no scaling)
- **Example:** 0x39 (57) = 57% (car dashboard showed 56%)
- **Source:** OBDb signal `TAYCAN_BMS_SOC`
- **Behaviour:** BMS internal SoC. Closely tracks car display at mid-range but diverges at extremes: BMS 95% when car shows 97%, BMS 23% when car shows 17%. The car applies non-linear usable-range buffering.
- **CORRECTION:** Initially identified as SoH — confirmed as SoC.

#### DID 0x0286 — DO NOT USE ✗ UNRELIABLE
- **Size:** 1 byte
- **Status:** Intermittent — responded in only 4 of 11 scans, always returned ~134 regardless of actual charge level. At 17% actual SoC, still read 134 → false 97.7% reading. Likely a calibration or reference value, not live SoC.
- **Previously:** Used as primary SoC with formula `(raw - 5) / 132 * 100`. This appeared correct at high SoC by coincidence (stale 134 matched the actual 97%). Demoted to raw data only.

#### DID 0x51E0 — State of Health (SoH) ✓ CONFIRMED
- **Size:** 2 bytes (uint16 big-endian)
- **Scale:** `raw * 0.127 - 1798.574` = percentage
- **Session:** Default (no extended session required)
- **Example:** 0x39FC (14844) → `14844 * 0.127 - 1798.574 = 86.6%`
- **Source:** OBDb/Porsche-Taycan community signalset (455 commits, CC-BY-SA-4.0). Signal ID: `TAYCAN_HVBAT_SOH`. Confirmed across MY2020–2025 test data.
- **Sentinel:** raw = 0x0000 produces -1798.574 — treat as no-data.
- **Note:** DID 0x51E0 is in the 0x5000–0xFFFF range which was not swept during initial investigation — this is why it was not found earlier.

#### DIDs 0x1E1C / 0x1E1E — BMS Current Limits (NOT SoH) ✗ RULED OUT
- **Size:** 2 bytes each (uint16 big-endian)
- **0x1E1C:** Maximum dynamic discharge current limit (amps)
- **0x1E1E:** Maximum predicted discharge current limit (amps)
- **Session:** Extended (0x03) required
- **Behaviour:** Values dropped from 860 to 762 overnight — these are temperature/SoC-dependent current limits, not health metrics. Both DIDs always return identical values.
- **Source:** OBDb signal IDs `TAYCAN_BMS_I_DCHG_LIM_DYN` and `TAYCAN_BMS_I_DCHG_LIM_PRED`.

#### DID 0x02B2 — Charging status ✓ CONFIRMED
- **Size:** 1 byte
- **Type:** Boolean/enum
- **Values observed:** 1 = charging active (car was plugged in during all reads)
- **Needs:** Read while unplugged to confirm 0 = not charging.

#### DID 0x02B3 — Status flag
- **Size:** 1 byte
- **Values observed:** 0x00 (constant during AC charging)
- **Hypothesis:** Charge type (0 = AC, 1 = DC), contactor state, or error flag. Needs DC charging session to differentiate.

### Pack telemetry (partially decoded)

#### DID 0x02BD — Packed telemetry (10 bytes)
Three reads captured at increasing SoC:

| Read | SoC | Raw hex |
|------|-----|---------|
| 1 | 99.75% | `00 69 14 e0 63 28 00 e9 8b e8` |
| 2 | 100.0% | `00 69 14 e5 84 28 00 e9 8b 00` |
| 3 | 100.0% | `00 69 14 e9 18 28 00 e9 8b 00` |

**Sub-field analysis:**

| Bytes | Stable? | Values | Best hypothesis |
|-------|---------|--------|-----------------|
| 0–1 | Yes | 0x0069 (105) | Charge current. 105 × 0.1 = 10.5A — consistent with AC taper charge at high SoC. Should drop to 0 when unplugged, go negative (signed) during discharge. |
| 2–3 | Moving ↑ | 0x14E0 → 0x14E5 → 0x14E9 (5344 → 5349 → 5353) | Pack voltage. × 0.15 = 801.6V → 802.4V → 803.0V. Rising slowly as SoC tops up — matches expected ~800V at full charge on 800V architecture. |
| 4 | Moving | 0x63 → 0x84 → 0x18 | Sub-field of voltage (LSB), or power calculation byte. Needs more samples. |
| 5 | Yes | 0x28 (40) | Temperature (internal) or mode flag. 40 × 0.5 = 20°C is plausible for an internal component temp. |
| 6–8 | Yes | 0x00E98B (59,787) | Lifetime energy counter? 59,787 × some scale = cumulative kWh. Static during a single charge session as expected. |
| 9 | Changed once | 0xE8 → 0x00 → 0x00 | Fractional/sub-second counter, checksum, or status byte. |

**To fully decode:** Read while driving (current negative/high, voltage drops under load) and while parked unplugged (current = 0, voltage settles to resting ~720V at 50% SoC).

#### DID 0x02CB — Temperature pair
- **Size:** 2 bytes
- **Values observed:** 0x0F 0x0F (15, 15)
- **Hypothesis:** Battery temperature min/max in °C. Both at 15°C = thermal equilibrium. Consistent with a UK-garaged car in April. Confirm by reading after a spirited drive (max should rise, min may lag).

#### DID 0x0410 — Temperature or module count
- **Size:** 1 byte
- **Value:** 0x0F (15)
- **Note:** Same value as both bytes in 0x02CB. If temperature, this may be the average. If module count, the Taycan has module groupings that could number 15.

### Module status arrays

#### DID 0x0407 — Module status (16 bytes = 8 × uint16)
- **Values observed:** [1, 3, 1, 3, 3, 3, 3, 3]
- **Hypothesis:** Per-module balancing status. The Taycan Performance Battery Plus has physical module groups. Bit 0 = active, Bit 1 = balancing. So 1 (0b01) = present/not balancing, 3 (0b11) = present/balancing active. At 99–100% SoC, the BMS actively balances most modules — the two showing "1" are already balanced.
- **To confirm:** Read at mid-range SoC (60–70%) after the car has been off the charger. If all flip to 1, balancing hypothesis is confirmed.

#### DID 0x040F — Module data (16 bytes = 8 × uint16)
- **Values observed:** [1, 1000, 1000, 1000, 1000, 1000, 1000, 1000]
- **Note:** 0x03E8 = 1000 repeated 7 times with 0x0001 prefix.
- **Hypothesis:** Per-module capacity in 0.1 Ah units (1000 = 100.0 Ah), or cell group voltage delta in 0.1 mV (all at 100.0 mV = well balanced). The first uint16 (0x0001) may be an index or module count offset.

### Intermittent DIDs (responded on first read, NRC 0x31 on subsequent reads)

#### DID 0x02E1 — Energy counter (likely)
- **Size:** 4 bytes
- **Value:** 0x35443F18 (895,336,216)
- **Hypothesis:** Lifetime energy metric. In 0.01 Wh: ~8,953 kWh. In Wh: 895,336 kWh (too high). The 0.01 Wh scale gives a plausible lifetime figure for a 3-year-old EV driven regularly.
- **Note:** May require extended diagnostic session (0x03) for reliable access, or may be rate-limited by the BMS.

#### DID 0x02FA — Cell data (likely)
- **Size:** 5 bytes
- **Value:** 0x81 85 A2 67 6D
- **Note:** First byte 0x81 could be a flag/address byte (high bit set). Remaining 4 bytes may pack cell group voltage or temperature data. Also intermittent — likely session-dependent.

### Other BECM DIDs

| DID | Size | Value | Notes |
|-----|------|-------|-------|
| 0x02CA | 2B | 0x0000 | Zero — inactive counter or flag |
| 0x02D1 | 1B | 0x00 | Status byte — thermal mode or contactor |
| 0x03DE | 2B | 0x0000 | Zero |
| 0x0407 | 16B | See above | Module status array |
| 0x040F | 16B | See above | Module data array |
| 0x0410 | 1B | 0x0F | Temperature or count |
| 0x043F | 2B | 0x0000 | Zero |
| 0x0440 | 7B | 02 01 02 06 04 12 00 | Configuration/calibration metadata |
| 0x04FC | 3B | 0x000000 | Zero |
| 0x04FE | 3B | 0x000000 | Zero |

### BECM DTCs observed

| DTC code | Status | Description |
|----------|--------|-------------|
| P0AA600 | Confirmed, not active | HV Battery Voltage System Isolation Fault |
| 100014 | Pending | (appeared during diagnostic session — may be transient) |

The BECM also stores per-cell-module diagnostic entries (C01007 through C33109 — 33 modules × 3 parameters = 99 entries) all with status 0x50 (test not completed this monitoring cycle). These are not faults — they are normal self-test status indicators.

---

## 5. DTC status byte decoding

The DTC status byte is a bitmask defined by ISO 14229:

| Bit | Mask | Meaning |
|-----|------|---------|
| 0 | 0x01 | testFailed (currently failing) |
| 1 | 0x02 | testFailedThisMonitoringCycle |
| 2 | 0x04 | pendingDTC |
| 3 | 0x08 | confirmedDTC |
| 4 | 0x10 | testNotCompletedSinceLastClear |
| 5 | 0x20 | testFailedSinceLastClear |
| 6 | 0x40 | testNotCompletedThisMonitoringCycle |
| 7 | 0x80 | warningIndicatorRequested |

**Filtering for real faults:** Only count DTCs where bits 0, 2, or 3 are set (testFailed, pending, or confirmed). Status values of 0x10, 0x40, or 0x50 alone indicate incomplete self-tests, not actual faults. This distinction reduces the apparent DTC count from ~2800 (all entries) to 30 (real faults).

| Status value | Meaning | Count as fault? |
|-------------|---------|-----------------|
| 0x08 | Pending only | Yes |
| 0x09 | Active + pending | Yes |
| 0x28 | Pending + confirmed | Yes |
| 0x2E | Confirmed + pending + testFailed since clear | Yes |
| 0x2F | Active + confirmed + pending | Yes (worst) |
| 0x10 | Test not completed since clear | No |
| 0x40 | Test not completed this cycle | No |
| 0x50 | Combined incomplete tests | No |

---

## 6. Scan app protocol analysis (from pcap)

### Scan sequence per ECU

The captured scan app follows this exact DID read order for each ECU:

1. `0xF19E` — ASAM/ODX identifier
2. `0xF1A2` — ASAM version
3. `0xF187` — Software part number
4. `0xF189` — Software version
5. `0xF191` — Hardware part number
6. `0xF1A3` — Hardware version
7. `0xF1AA` — Workshop system ID
8. `0xF17C` — FAZIT (factory acceptance test ID)
9. `0xF190` — VIN (not all ECUs store this — BECM returns NRC 0x31)
10. `0x2A2F` — ECU type/class byte (single byte, not all ECUs support)
11. `0x2A30` — Self-identification (3 bytes, last 2 = address ID)
12. Service 0x19 sub 0x02 mask 0xFF — Read all DTCs

### Notable findings from pcap

**The scan app does NOT read any battery-specific DIDs.** It reads only identity data and DTCs from the BECM. The SoC (0x0286), SoH (0x028C), temperature (0x02CB), and telemetry (0x02BD) reads were all discovered through our own DID enumeration. Our dashboard reads more battery data than the captured scan tool.

**Parallel communication:** The gateway supports multiple outstanding requests. The pcap shows the scan app firing requests to several ECUs before waiting for all responses — this is why a full 42-ECU scan completes in ~10 seconds rather than the ~40 seconds our serial approach takes.

**DID 0x2A30 is an address self-identification register.** Response pattern across ECUs:
```
0x400B → 65 00 0B  (TPMS — low byte matches DoIP address)
0x4012 → 44 40 12  (EPS)
0x4013 → 03 00 13  (ESP — first byte = VAG system code 0x03)
0x4053 → 81 00 53  (Gear selector)
0x404F → A5 00 4F  (ADAS — first byte = VAG code 0xA5)
```
The first byte appears to be the VAG system code. The last two bytes are the DoIP address low bytes. This provides a programmatic way to map VAG codes to DoIP addresses without maintaining a static table.

**DID 0x2A2F is a single-byte ECU class/type identifier.** Only some ECUs respond. The BECM does not support it (NRC 0x31).

---

## 7. Fault code summary (2026-04-10)

30 real DTCs across 11 ECUs. All are pending or confirmed — none currently active except the Gear Selector (0x2F) and one OTA entry (0x09).

### OTA Update (0x4086) — 7 DTCs
| Code | Status | Notes |
|------|--------|-------|
| F0000F | Pending | |
| 00011E | Pending | |
| F00109 | Active + Pending | Currently active |
| EA6100 | Pending | |
| F1001D | Pending | |
| F10049 | Pending | |
| F10116 | Pending | |

Common after software updates. The active entry (F00109) may clear after a full drive cycle.

### Gear Selector (0x4053) — 1 DTC
| Code | Status | Notes |
|------|--------|-------|
| 00607A | Active + Confirmed + Pending (0x2F) | Only truly "active" fault on the car |

Worth monitoring — this is the only DTC in the worst state (active + confirmed + pending). If no shifting issues are noticed, likely a transient bus glitch.

### Gateway (0x4010) — 8 DTCs
All pending (0x08). Includes emergency call module communication errors, energy management, databus errors, and an IPv6 address conflict. The IPv6 conflict (FF0110) may have been caused by connecting diagnostic equipment.

### On-Board Charger (0x4044) — 4 DTCs
All pending/confirmed (0x28). Includes charge state and communication faults — likely transient from a low-SoC event or interrupted charge session.

### Battery BECM (0x407B) — 1 DTC
| Code | Status | Notes |
|------|--------|-------|
| 100014 | Pending (0x28) | Appeared during diagnostic session |

Additionally, the MapEV scan from earlier the same day showed P0AA600 (HV Battery Isolation Fault, confirmed but not active) which was not captured in the later scan. This fault indicates the BMS detected reduced isolation resistance between the HV system and chassis ground at some point.

### Other ECUs with faults
- **Brakes/ESP (0x4013):** 2 DTCs — cooling flap position + databus error
- **Front Sensors ADAS (0x404F):** 2 DTCs — pending communication faults
- **Instrument Cluster (0x4014):** 2 DTCs — pending
- **Power Steering (0x4012):** 1 DTC — pending
- **Adaptive Cruise (0x4057):** 1 DTC — pending
- **Light Right (0x4097):** 1 DTC — pending

---

## 8. Implementation notes

### Critical: use raw sockets, not doipclient

The Python `doipclient` and `udsoncan` libraries hang when connecting to this gateway. The issue appears to be in routing activation handling or internal timeout management. Raw TCP sockets with manual DoIP header construction work perfectly and are actually simpler.

### Timeout recommendations

| Operation | Timeout | Notes |
|-----------|---------|-------|
| TCP connect | 5 seconds | Gateway responds instantly |
| Routing activation | 3 seconds | Response within ~50ms |
| TesterPresent probe | 150ms | For address scanning |
| DID read | 1 second | Most respond within 200ms |
| DTC read | 2 seconds | Some ECUs return large responses |

### SoC display
The raw BMS SoC (DID 0x0286, scaled × 0.75) can exceed 100%. The dashboard should cap the displayed value at 100.0% to match the car's own display behaviour.

### DTC counting
Filter by status bitmask. Only count DTCs where `(status & 0x0D) != 0` (bits 0, 2, or 3 set = testFailed, pending, or confirmed). Status values of 0x10, 0x40, or 0x50 alone are incomplete self-tests, not faults.

### Scan file storage
Auto-save each scan to `scans/YYYY-MM-DD_HHMMSS.json`. The most valuable long-term data is SoH trending — one scan per month builds a degradation curve that no consumer Taycan tool currently provides.

---

## 9. What we don't know yet

1. **DID 0x02BD sub-field boundaries** — need reads at different driving states (parked/driving/charging) to confirm voltage, current, and power byte positions.
2. **DID 0x02CB** — strongly suspected to be temperature but needs a post-drive read where min ≠ max to confirm.
3. **DID 0x0407 module status** — balancing hypothesis needs mid-SoC read to confirm.
4. **Extended session (0x03) DIDs** — the intermittent DIDs (0x02E1 energy counter, 0x02FA cell data) may be reliably accessible in extended diagnostic session. Not yet tested.
5. **Cell-level voltage data** — the BECM almost certainly has per-cell or per-module voltage data, but it may be behind security access (service 0x27) or only available in extended/programming sessions.
6. **DC-DC converter and inverter telemetry** — the front/rear inverters (0x407C, 0x40B8) have ~45 non-standard DIDs each that haven't been enumerated.
7. **Parallel request optimisation** — the pcap shows the scan app sends multiple requests before collecting responses. Implementing this would cut scan time from ~40s to ~10s.
