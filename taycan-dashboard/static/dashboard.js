// Taycan Diagnostic Dashboard — Frontend Logic

let currentScan = null;
let trendChart = null;
let pollTimer = null;

// ─── Init ────────────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", () => {
  loadLatestScan();
  loadHistory();
  loadTrends();
  checkConnection();

  // Close modal on overlay click
  document.getElementById("ecu-modal").addEventListener("click", (e) => {
    if (e.target.classList.contains("modal-overlay")) closeModal();
  });

  // Close modal on Escape
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeModal();
  });
});

// ─── API Helpers ─────────────────────────────────────────────────────────

async function api(path) {
  const resp = await fetch(path);
  return resp.json();
}

async function apiPost(path) {
  const resp = await fetch(path, { method: "POST" });
  return resp.json();
}

// ─── Connection Status ──────────────────────────────────────────────────

async function checkConnection() {
  try {
    const status = await api("/api/status");
    const dot = document.getElementById("conn-dot");
    dot.classList.toggle("connected", status.gateway_reachable);
    dot.title = status.gateway_reachable
      ? `Connected to ${status.gateway_ip}`
      : "Gateway not reachable";

    document.getElementById("hdr-vin").textContent = status.vin || "---";
    document.getElementById("hdr-model").textContent =
      `${status.year} ${status.model}` || "---";
    document.getElementById("hdr-platform").textContent = status.platform || "---";
  } catch {
    document.getElementById("conn-dot").classList.remove("connected");
  }
}

// ─── Scan ────────────────────────────────────────────────────────────────

async function startScan() {
  const btn = document.getElementById("scan-btn");
  btn.disabled = true;
  btn.textContent = "Scanning...";

  try {
    await apiPost("/api/scan");
    pollProgress();
  } catch (e) {
    btn.disabled = false;
    btn.textContent = "Scan Now";
    document.getElementById("scan-progress").textContent = `Error: ${e}`;
  }
}

function pollProgress() {
  if (pollTimer) clearInterval(pollTimer);

  pollTimer = setInterval(async () => {
    try {
      const prog = await api("/api/scan/progress");
      const el = document.getElementById("scan-progress");

      if (prog.running) {
        const pct = prog.total > 0
          ? Math.round((prog.progress / prog.total) * 100) : 0;
        el.textContent = `${prog.progress}/${prog.total} (${pct}%) — ${prog.message}`;
      } else {
        clearInterval(pollTimer);
        pollTimer = null;
        el.textContent = "";

        const btn = document.getElementById("scan-btn");
        btn.disabled = false;
        btn.textContent = "Scan Now";

        // Reload everything
        loadLatestScan();
        loadHistory();
        loadTrends();
        checkConnection();
      }
    } catch {
      clearInterval(pollTimer);
      pollTimer = null;
    }
  }, 500);
}

// ─── Load Scan Data ──────────────────────────────────────────────────────

async function loadLatestScan() {
  try {
    const data = await api("/api/scan/latest");
    if (!data.error) {
      currentScan = data;
      renderScan(data);
    }
  } catch {}
}

async function loadScan(filename) {
  try {
    const data = await api(`/api/scans/${filename}`);
    if (!data.error) {
      currentScan = data;
      renderScan(data);

      // Highlight active row
      document.querySelectorAll(".history-table tr").forEach((r) =>
        r.classList.remove("active")
      );
      const row = document.querySelector(`[data-filename="${filename}"]`);
      if (row) row.classList.add("active");
    }
  } catch {}
}

// ─── Render Scan ─────────────────────────────────────────────────────────

function renderScan(scan) {
  // Timestamp
  document.getElementById("scan-time").textContent = scan.timestamp
    ? `Last scan: ${scan.timestamp}`
    : "";

  // Battery
  const bat = scan.battery || {};
  renderSoH(bat.soh_percent);
  renderSoC(bat.soc_percent);
  renderCharging(bat.charging);
  renderVoltage(bat.pack_voltage_v);
  renderPower(bat.pack_current_a, bat.pack_power_kw);
  renderTemp(bat.temperature_min_c, bat.temperature_max_c);
  renderModuleStatus(bat.module_status, bat.module_data);

  // ECUs
  renderEcuGrid(scan.ecus || []);

  // Cell / Module grid
  renderCellGrid(bat.module_grid, bat.cell_stats);

  // DTCs
  renderDtcSummary(scan.ecus || []);

  // Summary — count only real faults (is_fault=true) for display
  const s = scan.summary || {};
  const faultCount = (scan.ecus || []).reduce((sum, e) =>
    sum + (e.dtcs || []).filter((d) => d.is_fault).length, 0);
  const ecusWithFaults = (scan.ecus || []).filter((e) =>
    (e.dtcs || []).some((d) => d.is_fault)).length;
  document.getElementById("ecu-summary").textContent =
    `${s.ecus_reachable || 0} reachable / ${s.ecus_scanned || 0} total — ${faultCount} faults across ${ecusWithFaults} ECUs`;
}

// ─── Battery Rendering ──────────────────────────────────────────────────

function renderSoH(pct) {
  const el = document.getElementById("soh-value");
  const gauge = document.getElementById("soh-gauge");
  const circumference = 2 * Math.PI * 65; // ~408.4

  if (pct != null) {
    el.textContent = pct;
    const offset = circumference * (1 - pct / 100);
    gauge.style.strokeDashoffset = offset;

    // Color based on health
    if (pct >= 90) gauge.style.stroke = "var(--green)";
    else if (pct >= 80) gauge.style.stroke = "var(--accent)";
    else if (pct >= 70) gauge.style.stroke = "var(--amber)";
    else gauge.style.stroke = "var(--red)";
  } else {
    el.textContent = "--";
    gauge.style.strokeDashoffset = circumference;
  }
}

function renderSoC(pct) {
  const el = document.getElementById("soc-value");
  const bar = document.getElementById("soc-bar");

  if (pct != null) {
    const display = Math.min(100, pct);
    el.textContent = `${display.toFixed(1)}%`;
    bar.style.width = `${display}%`;
  } else {
    el.textContent = "--%";
    bar.style.width = "0%";
  }
}

function renderCharging(charging) {
  const el = document.getElementById("charging-status");
  if (charging === true) {
    el.innerHTML = '<span class="charging-badge yes">Charging</span>';
  } else if (charging === false) {
    el.innerHTML = '<span class="charging-badge no">Not Charging</span>';
  } else {
    el.innerHTML = '<span class="charging-badge no">Unknown</span>';
  }
}

function renderTemp(min, max) {
  const el = document.getElementById("temp-value");
  if (min != null && max != null) {
    el.textContent = `${min}\u00B0C / ${max}\u00B0C`;
  } else {
    el.textContent = "-- / --";
  }
}

function renderVoltage(v) {
  const el = document.getElementById("voltage-value");
  el.textContent = v != null ? `${v.toFixed(1)} V` : "-- V";
}

function renderPower(current, power) {
  const el = document.getElementById("power-value");
  if (current != null && power != null) {
    el.textContent = `${current.toFixed(1)} A / ${power.toFixed(1)} kW`;
  } else {
    el.textContent = "-- A / -- kW";
  }
}

function renderModuleStatus(status, data) {
  const el = document.getElementById("module-status");
  if (status) {
    el.textContent = status.join(", ");
  } else {
    el.textContent = "--";
  }
}

// ─── Cell / Module Grid ──────────────────────────────────────────────────

function renderCellGrid(modules, stats) {
  const section = document.getElementById("cell-section");
  const gridEl = document.getElementById("module-grid");
  const statsEl = document.getElementById("cell-stats-bar");
  const legendEl = document.getElementById("cell-legend");

  if (!modules || modules.length === 0) {
    section.style.display = "none";
    return;
  }

  section.style.display = "block";

  // Pack stats bar
  const packMin = stats?.pack_min_mv ?? 0;
  const packMax = stats?.pack_max_mv ?? 0;
  const packAvg = stats?.pack_avg_mv ?? 0;
  const packSpread = stats?.pack_spread_mv ?? 0;
  const spreadClass = packSpread > 100 ? "critical" : packSpread > 50 ? "warning" : "";

  statsEl.innerHTML = `
    <div class="cell-stat">
      <div class="cell-stat-label">Modules</div>
      <div class="cell-stat-value">${stats?.module_count || 0}<span class="cell-stat-unit">/ 33</span></div>
    </div>
    <div class="cell-stat">
      <div class="cell-stat-label">Cell Pair Min</div>
      <div class="cell-stat-value">${(packMin / 1000).toFixed(3)}<span class="cell-stat-unit">V</span></div>
    </div>
    <div class="cell-stat">
      <div class="cell-stat-label">Cell Pair Max</div>
      <div class="cell-stat-value">${(packMax / 1000).toFixed(3)}<span class="cell-stat-unit">V</span></div>
    </div>
    <div class="cell-stat">
      <div class="cell-stat-label">Pack Average</div>
      <div class="cell-stat-value">${(packAvg / 1000).toFixed(3)}<span class="cell-stat-unit">V</span></div>
    </div>
    <div class="cell-stat">
      <div class="cell-stat-label">Spread (Δ)</div>
      <div class="cell-stat-value ${spreadClass}">${packSpread}<span class="cell-stat-unit">mV</span></div>
    </div>
  `;

  // Build 9-row grid (rows 1-9). Row 9 has only col 1 (the extra module).
  // Modules keyed by row/col for quick lookup
  const byPos = {};
  modules.forEach((m) => {
    byPos[`${m.row},${m.col}`] = m;
  });

  // Determine thresholds for color coding
  // Weakest = within 5 mV of packMin → red
  // Warning = within 15 mV of packMin → amber
  // Best = within 5 mV of packMax → blue
  // Rest = green
  const healthClass = (minMv) => {
    if (minMv <= packMin + 5) return "weak";
    if (minMv <= packMin + 15) return "warning";
    if (minMv >= packMax - 5) return "best";
    return "healthy";
  };

  let html = "";
  for (let row = 1; row <= 9; row++) {
    for (let col = 1; col <= 4; col++) {
      const m = byPos[`${row},${col}`];
      if (m) {
        const cls = healthClass(m.min_mv);
        const volts = (m.min_mv / 1000).toFixed(3);
        const tooltip = [
          `Module ${m.module_id} (Row ${m.row}, Col ${m.col})`,
          `DID: ${m.did}`,
          `Voltages: ${m.voltages_mv.map((v) => (v / 1000).toFixed(3)).join(", ")} V`,
          `Min: ${m.min_mv} mV`,
          `Max: ${m.max_mv} mV`,
          `Avg: ${m.avg_mv} mV`,
          `Spread: ${m.spread_mv} mV`,
        ].join("\n");
        html += `
          <div class="module-tile ${cls}" title="${tooltip}">
            <div class="pos">R${m.row}C${m.col}</div>
            <div class="voltage">${volts}<span class="voltage-unit"> V</span></div>
            <div class="spread">Δ ${m.spread_mv}mV</div>
          </div>
        `;
      } else if (row === 9) {
        // Row 9 only has col 1
        if (col === 1) {
          html += `<div class="module-tile empty"></div>`;
        }
      } else {
        html += `<div class="module-tile empty"></div>`;
      }
    }
  }

  gridEl.innerHTML = html;

  // Legend + callout
  const weakest = stats?.weakest_module;
  const imbalanced = stats?.most_imbalanced_module;
  legendEl.innerHTML = `
    <h4>Legend</h4>
    <div class="legend-row"><div class="legend-swatch best"></div>Highest voltage</div>
    <div class="legend-row"><div class="legend-swatch healthy"></div>Healthy</div>
    <div class="legend-row"><div class="legend-swatch warning"></div>Below average</div>
    <div class="legend-row"><div class="legend-swatch weak"></div>Weakest cell</div>
    ${weakest ? `
      <div class="callout">
        <strong>Weakest:</strong> ${weakest.position}<br>
        Min voltage: ${(weakest.min_mv / 1000).toFixed(3)} V
      </div>
    ` : ""}
    ${imbalanced && imbalanced.spread_mv > 20 ? `
      <div class="callout">
        <strong>Most imbalanced:</strong> ${imbalanced.position}<br>
        Spread: ${imbalanced.spread_mv} mV
      </div>
    ` : ""}
  `;
}

// ─── ECU Grid ────────────────────────────────────────────────────────────

// System importance tiers (lower = more important)
const ECU_PRIORITY = {
  "Battery (BECM)": 0,
  "Powertrain (VCU)": 0,
  "Front Inverter": 0,
  "Rear Inverter": 0,
  "On-Board Charger": 1,
  "DC-DC Converter": 1,
  "HV Booster": 1,
  "Thermal Management": 1,
  "Gateway": 2,
  "Brakes (ESP)": 2,
  "Brake Boost": 2,
  "Power Steering (EPS)": 2,
  "Airbag": 2,
  "Air Suspension": 3,
  "Adaptive Cruise": 3,
  "Front Sensors (ADAS)": 3,
  "Instrument Cluster": 4,
  "Body Control (BCM)": 4,
  "Comfort Module": 4,
  "Climate Control": 5,
  "Infotainment (PCM)": 5,
  "Telematics (TCU)": 5,
  "OTA Update": 5,
};

function ecuSortKey(ecu) {
  const faults = (ecu.dtcs || []).filter((d) => d.is_fault);
  const activeFaults = faults.filter((d) => d.active).length;
  const faultCount = faults.length;

  // Sort order: active faults → stored faults → healthy → unreachable
  // Within each group: by system priority, then by name
  let tier;
  if (!ecu.reachable) tier = 3;
  else if (activeFaults > 0) tier = 0;
  else if (faultCount > 0) tier = 1;
  else tier = 2;

  const priority = ECU_PRIORITY[ecu.name] ?? 6;
  return tier * 10000 - faultCount * 100 + priority;
}

function renderEcuGrid(ecus) {
  const grid = document.getElementById("ecu-grid");
  grid.innerHTML = "";

  const sorted = [...ecus].sort((a, b) => ecuSortKey(a) - ecuSortKey(b));

  sorted.forEach((ecu, idx) => {
    const tile = document.createElement("div");
    tile.className = "ecu-tile";

    const faults = (ecu.dtcs || []).filter((d) => d.is_fault);
    const faultCount = faults.length;
    const hasActive = faults.some((d) => d.active);

    if (!ecu.reachable) {
      tile.classList.add("unreachable");
    } else if (hasActive) {
      tile.classList.add("active-dtc");
    } else if (faultCount > 0) {
      tile.classList.add("stored-dtc");
    } else {
      tile.classList.add("healthy");
    }

    let dtcBadge = "";
    if (faultCount > 0) {
      const cls = hasActive ? "active" : "has-dtc";
      dtcBadge = `<span class="ecu-dtc-count ${cls}">${faultCount}</span>`;
    }

    tile.innerHTML = `
      <div class="ecu-name">${dtcBadge}${ecu.name}</div>
      <div class="ecu-addr">${ecu.doip_address}</div>
    `;

    tile.onclick = () => showEcuDetail(ecu);
    grid.appendChild(tile);
  });
}

// ─── ECU Detail Modal ────────────────────────────────────────────────────

function showEcuDetail(ecu) {
  document.getElementById("modal-name").textContent = ecu.name;
  document.getElementById("modal-addr").textContent =
    `${ecu.doip_address} — ${ecu.asam_id || ""}`;

  const info = document.getElementById("modal-info");
  const rows = [
    ["SW Part Number", ecu.sw_number],
    ["SW Version", ecu.sw_version],
    ["HW Part Number", ecu.hw_number],
    ["HW Version", ecu.hw_version],
    ["Serial Number", ecu.serial],
    ["VIN", ecu.vin],
    ["System Name", ecu.system_name],
    ["Workshop ID", ecu.workshop_id],
    ["FAZIT", ecu.fazit],
    ["Mfg Date", ecu.mfg_date],
  ].filter(([, v]) => v);

  info.innerHTML = rows
    .map(([k, v]) => `<tr><td>${k}</td><td>${v}</td></tr>`)
    .join("");

  const dtcs = document.getElementById("modal-dtcs");
  const faults = (ecu.dtcs || []).filter((d) => d.is_fault);
  const nonFaults = (ecu.dtcs || []).length - faults.length;
  if (faults.length > 0) {
    dtcs.innerHTML =
      `<div class="card-title" style="margin-top:8px">Fault Codes (${faults.length})${nonFaults > 0 ? ` <span style="color:var(--text-dim);text-transform:none;letter-spacing:0">+ ${nonFaults} inactive entries</span>` : ""}</div>` +
      faults
        .map((d) => {
          const flags = [];
          if (d.active) flags.push('<span class="active">ACTIVE</span>');
          if (d.confirmed) flags.push('<span class="confirmed">CONFIRMED</span>');
          if (d.pending) flags.push("PENDING");
          const desc = d.description ? `<div style="color:var(--text);font-size:14px;margin-top:3px">${d.description}</div>` : "";
          const notes = d.notes ? `<div style="color:var(--text-dim);font-size:13px;margin-top:2px">${d.notes}</div>` : "";
          const sev = d.severity ? `<span class="flag ${d.severity === 'critical' ? 'active' : d.severity === 'high' ? 'confirmed' : 'pending'}" style="margin-left:6px">${d.severity.toUpperCase()}</span>` : "";
          return `<div class="dtc-item" style="padding:6px 0">
            <span class="dtc-code">${d.code}</span>${sev}
            <span class="dtc-flags">${flags.join(" ")}</span>
            <span style="float:right;color:var(--text-dim);font-size:13px">${d.status_hex}</span>
            ${desc}${notes}
          </div>`;
        })
        .join("");
  } else if (ecu.reachable) {
    const totalEntries = (ecu.dtcs || []).length;
    const suffix = totalEntries > 0
      ? ` <span style="color:var(--text-dim)">(${totalEntries} inactive entries)</span>` : "";
    dtcs.innerHTML = `<div style="color:var(--green);font-size:13px;margin-top:12px">No active faults${suffix}</div>`;
  } else {
    dtcs.innerHTML = '<div style="color:var(--text-dim);font-size:13px;margin-top:12px">ECU not reachable</div>';
  }

  document.getElementById("ecu-modal").classList.add("active");
}

function closeModal() {
  document.getElementById("ecu-modal").classList.remove("active");
}

// ─── DTC Summary ─────────────────────────────────────────────────────────

function renderDtcSummary(ecus) {
  const el = document.getElementById("dtc-list");
  const ecusWithFaults = ecus
    .filter((e) => (e.dtcs || []).some((d) => d.is_fault))
    .sort((a, b) => ecuSortKey(a) - ecuSortKey(b));

  if (ecusWithFaults.length === 0) {
    el.innerHTML = '<div class="no-faults">No fault codes found</div>';
    return;
  }

  el.innerHTML = ecusWithFaults
    .map((ecu) => {
      const entries = ecu.dtcs.filter((d) => d.is_fault)
        .map((d) => {
          const flags = [];
          if (d.active) flags.push('<span class="flag active">ACTIVE</span>');
          if (d.confirmed) flags.push('<span class="flag confirmed">CONFIRMED</span>');
          if (d.pending) flags.push('<span class="flag pending">PENDING</span>');
          const desc = d.description ? ` — ${d.description}` : "";
          return `<div class="dtc-entry" style="flex-direction:column;gap:2px">
            <div>
              <span class="code">${d.code}</span><span style="color:var(--text-dim);font-size:13px">${desc}</span>
              <span class="flags" style="float:right">${flags.join("")} <span style="color:var(--text-dim)">${d.status_hex}</span></span>
            </div>
          </div>`;
        })
        .join("");

      return `<div class="dtc-group">
        <div class="dtc-group-header">${ecu.name} <span style="color:var(--text-dim)">${ecu.doip_address}</span></div>
        ${entries}
      </div>`;
    })
    .join("");
}

// ─── Scan History ────────────────────────────────────────────────────────

async function loadHistory() {
  try {
    const scans = await api("/api/scans");
    const tbody = document.getElementById("history-body");
    tbody.innerHTML = scans
      .map(
        (s) => `<tr data-filename="${s.filename}" onclick="loadScan('${s.filename}')">
        <td>${s.timestamp}</td>
        <td>${s.soh_percent != null ? s.soh_percent + "%" : "--"}</td>
        <td>${s.soc_percent != null ? s.soc_percent.toFixed(1) + "%" : "--"}</td>
        <td>${s.total_dtcs}</td>
        <td>${(s.scan_duration_ms / 1000).toFixed(1)}s</td>
      </tr>`
      )
      .join("");
  } catch {}
}

// ─── Trend Chart ─────────────────────────────────────────────────────────

async function loadTrends() {
  try {
    const data = await api("/api/trends");
    renderTrendChart(data);
  } catch {}
}

function renderTrendChart(data) {
  const ctx = document.getElementById("trend-chart");
  if (!ctx) return;

  if (trendChart) trendChart.destroy();

  // Filter to only scans that have actual data (non-null SoH)
  const filtered = {
    timestamps: [],
    soh: [],
    soc: [],
  };

  for (let i = 0; i < data.timestamps.length; i++) {
    if (data.soh[i] != null) {
      filtered.timestamps.push(data.timestamps[i]);
      filtered.soh.push(data.soh[i]);
      filtered.soc.push(data.soc[i] != null ? Math.min(100, data.soc[i]) : null);
    }
  }

  if (filtered.timestamps.length === 0) {
    // No data yet — show placeholder
    ctx.parentElement.querySelector(".card-title").textContent =
      "SoH Trend — no scan data yet";
    return;
  }

  const labels = filtered.timestamps.map((t) => {
    const d = new Date(t);
    return `${d.getMonth() + 1}/${d.getDate()} ${d.getHours()}:${String(d.getMinutes()).padStart(2, "0")}`;
  });

  trendChart = new Chart(ctx, {
    type: "line",
    data: {
      labels,
      datasets: [
        {
          label: "SoH %",
          data: filtered.soh,
          borderColor: "#00d4aa",
          backgroundColor: "#00d4aa22",
          fill: true,
          tension: 0.3,
          pointRadius: 4,
          pointBackgroundColor: "#00d4aa",
          yAxisID: "y",
        },
        {
          label: "SoC %",
          data: filtered.soc,
          borderColor: "#4488ff",
          backgroundColor: "#4488ff22",
          fill: false,
          tension: 0.3,
          pointRadius: 3,
          yAxisID: "y1",
          borderDash: [4, 4],
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: "index", intersect: false },
      plugins: {
        legend: {
          labels: { color: "#7a7b88", font: { size: 11 } },
        },
      },
      scales: {
        x: {
          ticks: { color: "#7a7b88", font: { size: 10 }, maxTicksLimit: 8 },
          grid: { color: "#1a1b25" },
        },
        y: {
          position: "left",
          min: 80,
          max: 100,
          title: { display: true, text: "SoH %", color: "#00d4aa" },
          ticks: { color: "#7a7b88", font: { size: 10 } },
          grid: { color: "#1a1b25" },
        },
        y1: {
          position: "right",
          min: 0,
          max: 100,
          title: { display: true, text: "SoC %", color: "#4488ff" },
          ticks: { color: "#7a7b88", font: { size: 10 } },
          grid: { display: false },
        },
      },
    },
  });
}
