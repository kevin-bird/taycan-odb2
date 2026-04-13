# OBDb Signal Reference — Porsche Taycan J1 Pre-Facelift (MY2020-2024)

Extracted from [OBDb/Porsche-Taycan](https://github.com/OBDb/Porsche-Taycan) community signalset.
CC-BY-SA-4.0 licensed, 455+ commits, validated across MY2020-2025.

**CAN-to-DoIP mapping:** The OBDb signals use 11-bit CAN IDs. On the Taycan's DoIP gateway, these map to 4-digit logical addresses (e.g., CAN 0x7E5 = DoIP 0x407B for the BECM). The DID numbers are the same regardless of transport — read DID 0x51E0 via DoIP and you get the same data as CAN.

---

## 1. ECU / CAN Header Map

| CAN Req | CAN Resp | ECU | DoIP Address | Description |
|---------|----------|-----|--------------|-------------|
| 0x710 | 0x77A | DC-DC / Power Mgmt | 0x40B7? | Range, consumption, DC-DC voltage/current |
| 0x713 | 0x77D | Wheel Speed Sensors | 0x4013? | Wheel speeds, steering angle |
| 0x714 | 0x77E | Trip / Odometer | — | Trip consumption |
| 0x71E | 0x788 | Differential / Transaxle | — | Motor/oil/clutch temps (MY2021+ only) |
| 0x742 | 0x7AC | PTC Heater | 0x4042? | Outside temp, pump RPM, heater current |
| 0x744 | 0x7AE | Charger (OBC) | 0x4044? | Charging rails, boost converter, efficiency |
| 0x746 | 0x7B0 | HVAC | 0x4046? | Fan speeds, cabin temp, humidity |
| 0x7E0 | 0x7E8 | VCU / Gateway | 0x4076? | Motor RPM/torque, displayed SoC, vehicle speed |
| 0x7E5 | 0x7ED | BECM (Battery) | 0x407B | SoH, BMS SoC, voltage, current, cell data, temps |

> DoIP addresses marked with `?` are best guesses based on function — verify by sweeping with `taycan_read.py`.

---

## 2. Battery Management — BECM (0x7E5 / DoIP 0x407B)

### 2.1 Core Battery Signals (default session)

| DID | Signal ID | Name | Bits | Formula | Unit | Notes |
|-----|-----------|------|------|---------|------|-------|
| 0x1801 | TAYCAN_HVBAT_VOLT | HV battery voltage | 16 | raw / 10 | V | Max 6553V |
| 0x51E0 | TAYCAN_HVBAT_SOH | HV battery health | 16 | raw * 0.127 - 1798.574 | % | raw=0 is no-data sentinel |
| 0x5200 | TAYCAN_LAUNCH | Launch control count | 32 | raw | count | Lifetime counter |

### 2.2 Core Battery Signals (extended session, din=03)

| DID | Signal ID | Name | Bits | Formula | Unit | Notes |
|-----|-----------|------|------|---------|------|-------|
| 0x028C | TAYCAN_BMS_SOC | BMS state of charge | 8 | raw | % | BMS internal, differs from display |
| 0x1802 | TAYCAN_BMS_I | HV battery current | 16 | raw * 2.56 - 1500 | A | Negative = discharging |
| 0xF45B | TAYCAN_BMS_SOC_HIRES | Hi-res SoC | 8 | raw * 100 / 255 | % | Higher precision |

### 2.3 BMS Temperature Sensors (extended session)

| DID | Signal ID | Name | Bits | Formula | Unit |
|-----|-----------|------|------|---------|------|
| 0x180C | TAYCAN_BMS_BMCE_T1 | BMC-E temperature 1 | 8 | raw - 50 | C |
| 0x180D | TAYCAN_BMS_BMCE_T2 | BMC-E temperature 2 | 8 | raw - 50 | C |
| 0x180E | TAYCAN_BMS_BMCE_T3 | BMC-E temperature 3 | 8 | raw - 50 | C |
| 0x180F | TAYCAN_BMS_SHUNT_T | Shunt temperature | 8 | raw - 50 | C |
| 0x1810 | TAYCAN_BMS_BMCE_T_CAN | BMC-E temperature 4 | 8 | raw / 2 - 40 | C |
| 0x181C | TAYCAN_BMS_COOL_IN_T | Cooling inlet temp | 8 | raw - 50 | C |
| 0x181D | TAYCAN_BMS_COOL_OUT_T | Cooling outlet temp | 8 | raw - 50 | C |
| 0x1E0E | TAYCAN_BMS_T_MAX | Battery temp max | 8 | raw - 100 | C |
| 0x1E0E | TAYCAN_BMS_T_MAX_CELL | ... cell number | 8 (bix 8) | raw | index |
| 0x1E0F | TAYCAN_BMS_T_MIN | Battery temp min | 8 | raw - 100 | C |
| 0x1E0F | TAYCAN_BMS_T_MIN_CELL | ... cell number | 8 (bix 8) | raw | index |
| 0x1E10 | TAYCAN_BMS_T_AVG | Battery temp average | 8 | raw - 100 | C |

### 2.4 Per-Module Temperatures (extended session, DIDs 0x1821-0x1841)

33 modules, each with 3 temperature sensors. All use the same formula: `raw - 50` (celsius).

| DID | Module | Signals |
|-----|--------|---------|
| 0x1821 | Module 1 | MOD1_T1, MOD1_T2, MOD1_T3 |
| 0x1822 | Module 2 | MOD2_T1, MOD2_T2, MOD2_T3 |
| ... | ... | ... |
| 0x1841 | Module 33 | MOD33_T1, MOD33_T2, MOD33_T3 |

Format: 3 bytes per DID, each byte = temperature sensor. Formula: `byte - 50 = celsius`.

### 2.5 Per-Module Cell Data (DIDs 0x1850-0x1870)

32 modules via default session (0x1850-0x186F), module 33 via extended session (0x1870).

Each module DID contains 6 cell pairs with voltage and SoC:

| Signal pattern | Bits | Formula | Unit | Description |
|----------------|------|---------|------|-------------|
| MODn_C1_V ... MODn_C6_V | 16 each | raw / 1000 | V | Cell pair voltage |
| MODn_C1_SOC ... MODn_C6_SOC | 8 each | raw | % | Cell pair SoC |

Signal groups defined for pattern matching:
- `TAYCAN_HVBAT_PACK_SOC` — matches `TAYCAN_HVBAT_(MODn)_(Cn)_SOC`
- `TAYCAN_HVBAT_PACK_V` — matches `TAYCAN_HVBAT_(MODn)_(Cn)_V`

### 2.6 BMS Current & Voltage Limits (extended session)

| DID | Signal ID | Name | Bits | Formula | Unit |
|-----|-----------|------|------|---------|------|
| 0x1E1B | TAYCAN_BMS_I_CHG_LIM_DYN | Max dynamic charge current | 16 | raw | A |
| 0x1E1C | TAYCAN_BMS_I_DCHG_LIM_DYN | Max dynamic discharge current | 16 | raw | A |
| 0x1E1D | TAYCAN_BMS_I_CHG_LIM_PRED | Max predicted charge current | 16 | raw | A |
| 0x1E1E | TAYCAN_BMS_I_DCHG_LIM_PRED | Max predicted discharge current | 16 | raw | A |
| 0x5170 | TAYCAN_BMS_V_CHG_PRED_MIN | Min predicted charge voltage | 16 | raw / 10 | V |
| 0x5171 | TAYCAN_BMS_V_CHG_DYN_MAX | Max dynamic charge voltage | 16 | raw / 10 | V |
| 0x5172 | TAYCAN_BMS_V_DCHG_PRED_MAX | Max predicted discharge voltage | 16 | raw / 10 | V |
| 0x5173 | TAYCAN_BMS_V_DCHG_PRED_MIN | Min predicted discharge voltage | 16 | raw / 10 | V |
| 0x5174 | TAYCAN_BMS_V_CHG_DYN_MIN | Min dynamic charge voltage | 16 | raw / 10 | V |
| 0x5175 | TAYCAN_BMS_V_DCHG_DYN_MIN | Min dynamic discharge voltage | 16 | raw / 10 | V |

### 2.7 Cell SoC Extremes (extended session)

| DID | Signal ID | Name | Bits | Formula | Unit |
|-----|-----------|------|------|---------|------|
| 0x1E2C | TAYCAN_BMS_CELL_SOC_MAX | Cell SoC max value | 8 | raw | % |
| 0x1E2C | TAYCAN_BMS_CELL_SOC_MAX_IDX | Cell SoC max index | 8 (bix 8) | raw | index |
| 0x1E2D | TAYCAN_BMS_CELL_SOC_MIN | Cell SoC min value | 8 | raw | % |
| 0x1E2D | TAYCAN_BMS_CELL_SOC_MIN_IDX | Cell SoC min index | 8 (bix 8) | raw | index |

### 2.8 Cell Voltage Extremes (extended session)

| DID | Signal ID | Name | Bits | Formula | Unit |
|-----|-----------|------|------|---------|------|
| 0x1E33 | TAYCAN_BMS_CELL_V_MAX | Cell voltage max | 16 | raw / 1000 | V |
| 0x1E33 | TAYCAN_BMS_CELL_V_MAX_IDX | Cell voltage max index | 8 (bix 16) | raw | index |
| 0x1E34 | TAYCAN_BMS_CELL_V_MIN | Cell voltage min | 16 | raw / 1000 | V |
| 0x1E34 | TAYCAN_BMS_CELL_V_MIN_IDX | Cell voltage min index | 8 (bix 16) | raw | index |

### 2.9 Power Reduction & Cooling (extended session)

| DID | Signal ID | Name | Bits | Formula | Unit |
|-----|-----------|------|------|---------|------|
| 0x1E0A | TAYCAN_BMS_PWR_REDUCE_ACT | Power reduction active | 8 | raw | flag |
| 0x1E3B | TAYCAN_BMS_CELL_DELTA_V | Cell voltage delta | 16 | raw / 1000 | V |
| 0x192B | TAYCAN_BMS_COOL_PUMP_PWR_SP | Cooling pump power setpoint | 8 | raw / 2 | % |
| 0x80EC | TAYCAN_BMS_COOL_PUMP_CTL | Coolant pump control value | 8 (bix 16) | raw | % |

---

## 3. VCU / Gateway (0x7E0 / DoIP 0x4076)

All default session unless noted.

### 3.1 Displayed SoC (the one that matches the car's dashboard!)

| DID | Signal ID | Name | Bits | Formula | Unit |
|-----|-----------|------|------|---------|------|
| 0x08D2 | TAYCAN_HVBAT_SOC_DISP | HV battery charge (displayed) | 16 | raw / 100 | % |

> This is the SoC the car's dashboard shows. Different from BMS SoC (0x028C) which is the internal BMS value.

### 3.2 Motor & Drivetrain

| DID | Signal ID | Name | Bits | Formula | Unit |
|-----|-----------|------|------|---------|------|
| 0x1151 | TAYCAN_EM_RPM_1 | Electric motor 1 RPM | 16 | raw / 2 (signed) | RPM |
| 0x1152 | TAYCAN_EM_RPM_2 | Electric motor 2 RPM | 16 | raw / 2 (signed) | RPM |
| 0x1153 | TAYCAN_EM_TORQ_1 | Motor 1 torque | 16 | raw / 32 (signed) | Nm |
| 0x1154 | TAYCAN_EM_TORQ_2 | Motor 2 torque | 16 | raw / 32 (signed) | Nm |
| 0x1155 | TAYCAN_EM_TORQ_3 | Motor 3 torque | 16 | raw / 32 (signed) | Nm |
| 0x3DF8 | TAYCAN_ENG_MOTOR_RPM | Electric motor RPM | 16 | raw / 2 (signed) | RPM |
| 0x29D4 | TAYCAN_ENG_TRQ_REQ_1 | Driver torque requested 1 | 16 | raw / 10 | Nm |
| 0x4380 | TAYCAN_ENG_TRQ_REQ_2 | Driver torque requested 2 | 16 | raw / 10 | Nm |

### 3.3 Battery (via VCU)

| DID | Signal ID | Name | Bits | Formula | Unit |
|-----|-----------|------|------|---------|------|
| 0x1156 | TAYCAN_HVBAT_SOC | HV battery charge | 8 | raw / 2 | % |
| 0x1158 | TAYCAN_MAX_DCHA_CUR_2 | Max discharge current | 16 | raw / 10 (signed) | A |
| 0x1159 | TAYCAN_MAX_CHA_CUR_2 | Max charge current | 16 | raw / 10 (signed) | A |

### 3.4 Vehicle Dynamics

| DID | Signal ID | Name | Bits | Formula | Unit |
|-----|-----------|------|------|---------|------|
| 0xF40D | TAYCAN_VSS | Vehicle speed | 8 | raw | km/h |
| 0x115B | TAYCAN_VSS_DIR | Vehicle speed (directional) | 16 | raw / 64 (signed) | km/h |
| 0x2005 | TAYCAN_BRAKE_BST_P | Brake booster pressure | 16 | raw / 1000 | bar |
| 0x2061 | TAYCAN_APP_POS1 | Accelerator pedal pos 1 | 16 | raw / 1000 | V |
| 0x2062 | TAYCAN_APP_POS2 | Accelerator pedal pos 2 | 16 | raw / 1000 | V |
| 0x395E | TAYCAN_ENG_BRAKE_PUMP | Brake vacuum pump | 1 (bix 7) | raw | on/off |

### 3.5 Climate & System

| DID | Signal ID | Name | Bits | Formula | Unit |
|-----|-----------|------|------|---------|------|
| 0x1004 | TAYCAN_AAT | Ambient temperature | 16 | raw / 128 (signed) | C |
| 0x028D | TAYCAN_ECU_TEMP | ECU temperature | 16 | raw / 10 (signed) | C |
| 0xF442 | TAYCAN_VPWR | Control module voltage | 16 | raw / 1000 | V |
| 0xF41F | TAYCAN_RUNTM | Time since start | 16 | raw | sec |

### 3.6 DTC Info

| DID | Signal ID | Name | Bits | Formula | Unit |
|-----|-----------|------|------|---------|------|
| 0xF421 | TAYCAN_MIL_DIST | Distance while MIL active | 16 | raw | km |
| 0xF430 | TAYCAN_WARM_UPS | Warm-ups since DTCs cleared | 8 | raw | count |
| 0xF431 | TAYCAN_CLR_DIST | Distance since DTCs cleared | 16 | raw | km |

---

## 4. DC-DC Converter (0x710)

Requires `fcm1` (function code mode 1).

| DID | Signal ID | Name | Bits | Formula | Unit |
|-----|-----------|------|------|---------|------|
| 0x2A53 | TAYCAN_DCDC_V_LOW | DC-DC low voltage | 8 | raw / 10 | V |
| 0x2A53 | TAYCAN_DCDC_I | DC-DC current | 16 (bix 8) | raw - 511 | A |
| 0x2A53 | TAYCAN_DCDC_I_RSV | DC-DC reserved current | 16 (bix 24) | raw - 511 | A |
| 0x2AB2 | TAYCAN_HVBAT_E_MAX | HV battery max energy | 16 | raw * 50 | W |
| 0x2AB4 | TAYCAN_RANGE_EST_INT | Estimated range (internal) | 16 (bix 16) | raw | km |
| 0x2AB4 | TAYCAN_HVBAT_CSMP_AVG_INT | Avg battery consumption | 8 (bix 72) | raw | A |
| 0x2AB5 | TAYCAN_RANGE_EST_CAN | Estimated range (CAN) | 16 (bix 32) | raw | km |
| 0x2AB6 | TAYCAN_RANGE | Range remaining | 16 | raw | miles |
| 0x2AB7 | TAYCAN_AVG_CSMP_CAT0-6 | Avg consumption (7 cats) | 16 each | raw / 10 | kWh |

---

## 5. Charger / OBC (0x744)

Requires `fcm1` + extended session (`din=03`) for most commands.

| DID | Signal ID | Name | Bits | Formula | Unit |
|-----|-----------|------|------|---------|------|
| 0x1507 | TAYCAN_CHRGR_RAIL1_E | Rail 1 energy | 24 | raw / 10 | kWh |
| 0x1507 | TAYCAN_CHRGR_RAIL2_E | Rail 2 energy | 24 (bix 24) | raw / 10 | kWh |
| 0x1507 | TAYCAN_CHRGR_RAIL3_E | Rail 3 energy | 24 (bix 48) | raw / 10 | kWh |
| 0x1529 | TAYCAN_CHRGR_PRX_V_CONN_B | PRX connector B voltage | 16 | raw | mV |
| 0x1553 | TAYCAN_CHRGR_BOOST_HI_I | Boost HV highside current | 16 | raw / 4 - 512 | A |
| 0x1554 | TAYCAN_CHRGR_BOOST_HI_V | Boost HV highside voltage | 16 | raw / 4 | V |
| 0x1557 | TAYCAN_CHRGR_BOOST_LO_I | Boost HV lowside current | 16 | raw / 4 - 512 | A |
| 0x1558 | TAYCAN_CHRGR_BOOST_LO_V | Boost HV lowside voltage | 16 | raw / 4 | V |
| 0x1559 | TAYCAN_CHRGR_BOOST_CMD_V | Boost commanded voltage | 16 | raw / 4 | V |
| 0x155A | TAYCAN_CHRGR_BOOST_CMD_I | Boost commanded current | 16 | raw / 4 - 512 | A |
| 0x15D5 | TAYCAN_CHRGR_PWR_MAX | Max charging power | 16 | raw | A |
| 0x15D6 | TAYCAN_CHRGR_EFFICIENCY | Power efficiency | 8 | raw / 10 + 75 | % |
| 0x15E1 | TAYCAN_CHRGR_PWR_LOSS | Charger power loss | 8 | raw * 20 | W |
| 0x15E2 | TAYCAN_CHRGR_COOLANT_T | Charger coolant temp | 8 | raw - 40 | C |
| 0x15EE | TAYCAN_CHRGR_DUR_TOTAL | Total charge duration | 32 | raw | min |
| 0x15EF | TAYCAN_CHRGR_E_TOTAL | Total energy turnover | 32 | raw | kWh |
| 0x15F7 | TAYCAN_CHRGR_3V_SUPPLY | 3V supply voltage | 8 | raw / 100 + 3.1 | V |
| 0x1DA7 | TAYCAN_CHRGR_V_OUT | Charger output voltage | 8 | raw | V |
| 0x1DD0 | TAYCAN_CHRGR_SOC_DISP | SoC display (charger) | 8 | raw / 2 | % |
| 0x1DD3 | TAYCAN_CHRGR_CHG_PWR_MAX | Max charge power | 16 | raw | — |
| 0x4965 | TAYCAN_HVBAT_KWH | HV battery energy (stored) | 16 | raw / 20 | kWh |

> DID 0x4965 (TAYCAN_HVBAT_KWH) is the only charger DID that does NOT require extended session.

---

## 6. Wheel Speeds & Steering (0x713)

Default session, no special requirements.

| DID | Signal ID | Name | Bits | Formula | Unit |
|-----|-----------|------|------|---------|------|
| 0x2B1B | TAYCAN_TIRE_FL_SPD | Front left wheel speed | 16 | raw * 9 / 160 | km/h |
| 0x2B1C | TAYCAN_TIRE_FR_SPD | Front right wheel speed | 16 | raw * 9 / 160 | km/h |
| 0x2B1D | TAYCAN_TIRE_RL_SPD | Rear left wheel speed | 16 | raw * 9 / 160 | km/h |
| 0x2B1E | TAYCAN_TIRE_RR_SPD | Rear right wheel speed | 16 | raw * 9 / 160 | km/h |
| 0x2B29 | TAYCAN_STEER_ANGLE | Steering wheel angle | 16 | raw / 1000 (signed) | rad |

---

## 7. HVAC / Climate (0x746)

Requires `fcm1`.

| DID | Signal ID | Name | Bits | Formula | Unit |
|-----|-----------|------|------|---------|------|
| 0x2604 | TAYCAN_HVAC_AC_LOAD | A/C compressor load | 16 | raw / 10 | Nm |
| 0x2606 | TAYCAN_HVAC_FAN1_ACT | Radiator fan 1 actual | 16 | raw / 10 | % |
| 0x2606 | TAYCAN_HVAC_FAN2_ACT | Radiator fan 2 actual | 16 (bix 16) | raw / 10 | % |
| 0x2607 | TAYCAN_HVAC_FAN_CMD | Radiator fan commanded | 16 | raw / 10 | % |
| 0x2609 | TAYCAN_HVAC_OUTSIDE_T | Outside temperature | 16 | raw / 10 (signed) | C |
| 0x2612 | TAYCAN_HVAC_EVAP_T | Evaporator output temp | 16 | raw / 10 (signed) | C |
| 0x2613 | TAYCAN_HVAC_INTERIOR_T | Interior temperature | 16 | raw / 10 (signed) | C |
| 0x27C3 | TAYCAN_HVAC_OUTSIDE_HUM | Outside humidity | 8 (bix 56) | raw / 2 | % |
| 0x27C4 | TAYCAN_HVAC_INSIDE_HUM | Inside humidity | 8 (bix 32) | raw / 2 | % |

---

## 8. PTC Heater (0x742)

Requires `fcm1`.

| DID | Signal ID | Name | Bits | Formula | Unit |
|-----|-----------|------|------|---------|------|
| 0x2609 | TAYCAN_PTC_OUTSIDE_T | Outside temperature | 8 | raw / 2 - 50 | C |
| 0x27D6 | TAYCAN_PTC_PUMP_RPM | Water pump RPM | 8 | raw * 300 | RPM |
| 0x27D6 | TAYCAN_PTC_PUMP_PWR | Water pump power | 8 (bix 16) | raw * 40 | W |
| 0x475F | TAYCAN_PTC_HTR_I | Heater current | 8 | raw / 4 | A |
| 0x475F | TAYCAN_PTC_HTR_FLUID_T1 | Heater fluid temp 1 | 8 (bix 64) | raw - 50 | C |
| 0x475F | TAYCAN_PTC_HTR_FLUID_T2 | Heater fluid temp 2 | 8 (bix 72) | raw - 50 | C |

---

## 9. Differential / Motor Temps (0x71E)

Requires `fcm1` + extended session. **MY2021+ only** (not available on MY2020).

| DID | Signal ID | Name | Bits | Formula | Unit |
|-----|-----------|------|------|---------|------|
| 0xF105 | TAYCAN_DIFF_MOTOR_T | Motor temperature | 8 | raw * 2 - 50 | C |
| 0xF105 | TAYCAN_DIFF_OIL_T | Oil temperature | 8 (bix 8) | raw * 2 - 50 | C |
| 0xF105 | TAYCAN_DIFF_CLUTCH_T | Clutch temperature | 8 (bix 16) | raw * 2 - 50 | C |

---

## 10. Trip Data (0x714)

Requires `fcm1`.

| DID | Signal ID | Name | Bits | Formula | Unit |
|-----|-----------|------|------|---------|------|
| 0x0530 | TAYCAN_TRIP_USE_SHORT | Trip consumption (short) | 18 (bix 238) | raw / 1000 (signed) | kWh/100mi |

---

## 11. Test Data Examples (MY2022)

Representative decoded values from community test cases:

### Battery
| Signal | Raw hex | Decoded |
|--------|---------|---------|
| TAYCAN_HVBAT_VOLT (0x1801) | `1C39` | 722.5 V |
| TAYCAN_BMS_SOC (0x028C) | `50` | 80% |
| TAYCAN_BMS_I (0x1802) | `01A6EA` | -419.68 A |
| TAYCAN_HVBAT_SOH (0x51E0) | `39FC` | 86.6% |
| TAYCAN_HVBAT_SOH (0x51E0) | `3A02` | 87.4% |

### Motor
| Signal | Raw hex | Decoded |
|--------|---------|---------|
| TAYCAN_EM_RPM_1 (0x1151) | `6A2` | 849 RPM |
| TAYCAN_HVBAT_SOC_DISP (0x08D2) | `1F40` | 80.0% (displayed) |

### Charger
| Signal | Raw hex | Decoded |
|--------|---------|---------|
| TAYCAN_CHRGR_BOOST_HI_V (0x1554) | `0C24` | 777.0 V |
| TAYCAN_CHRGR_COOLANT_T (0x15E2) | `45` | 29 C |
| TAYCAN_HVBAT_KWH (0x4965) | `0730` | 92.0 kWh |

---

## 12. Model Year Availability

Commands confirmed working per model year (from command_support.yaml):

| ECU | MY2020 | MY2021 | MY2022 | MY2023 | MY2024 |
|-----|--------|--------|--------|--------|--------|
| BECM cell data (0x1850-0x186F) | Yes | Yes | Yes | Yes | Yes |
| BECM SoH (0x51E0) | Yes | Yes | Yes | Yes | Yes |
| BECM voltage (0x1801) | Yes | Yes | Yes | Yes | Yes |
| BECM temps (0x1821-0x1841) | Yes | Yes | Yes | Yes | Yes |
| VCU motor RPM (0x1151-0x1152) | Yes | Yes | Yes | Yes | Yes |
| VCU displayed SoC (0x08D2) | Yes | Yes | Yes | Yes | Yes |
| Wheel speeds (0x2B1B-0x2B1E) | Yes | Yes | Yes | Yes | Yes |
| Range (0x2AB6) | Yes | Yes | Yes | — | — |
| Charger rail energy (0x1507) | Yes | Yes | Yes | — | — |
| HVAC climate (0x2604+) | Yes | Yes | Yes | — | — |
| Differential temps (0xF105) | — | Yes | — | — | — |

> Dashes indicate not tested/not in command_support.yaml for that year, not necessarily unsupported.

---

## 13. Key Differences: OBDb vs Our DoIP Implementation

| Aspect | OBDb (CAN/OBD2) | Our Dashboard (DoIP) |
|--------|-----------------|----------------------|
| Transport | 11-bit CAN via BLE dongle | DoIP over Ethernet TCP |
| BECM address | 0x7E5 (CAN) | 0x407B (DoIP logical) |
| VCU address | 0x7E0 (CAN) | 0x4076 (DoIP logical) |
| DIDs | Same numbers work on both | Same numbers work on both |
| Session control | `din=03` = extended | `0x10 0x03` = extended |
| Multi-frame | ISO-TP (CAN segmentation) | DoIP handles segmentation |
| Displayed SoC | VCU DID 0x08D2 (not yet tested via DoIP) | Currently using BECM 0x028C |

### Priority DIDs to add to our dashboard

1. **0x08D2 on VCU (0x4076)** — displayed SoC matching car dashboard
2. **0x1801 on BECM** — independent voltage reading (raw / 10)
3. **0x1802 on BECM** — independent current reading (raw * 2.56 - 1500)
4. **0x4965 on OBC** — stored energy in kWh (raw / 20)
5. **0x1E0E/0x1E0F on BECM** — temp max/min with cell index
6. **0x1E2C/0x1E2D on BECM** — cell SoC max/min with index
7. **0x1E33/0x1E34 on BECM** — cell voltage max/min with index
8. **0x1E3B on BECM** — cell voltage delta
