// GUARDIAN Dashboard Client Engine
// Connects to WebSocket stream and manages interactive attack triggers & XAI explainability modals

let currentModalDeviceId = null;
let ws = null;
let activeDevices = [];

// Initialize dashboard on DOM ready
document.addEventListener("DOMContentLoaded", () => {
  initWebSocket();
  refreshData();
  // Poll fallback every 4 seconds in case WS drops
  setInterval(refreshData, 4000);
});

// WebSocket Connection Manager
function initWebSocket() {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${protocol}//${window.location.host}/ws`;

  try {
    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      const badge = document.getElementById("ws-badge");
      if (badge) {
        badge.innerHTML = `<span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse mr-1.5"></span> Live Gateway`;
        badge.className = "flex items-center text-xs px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20";
      }
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === "TELEMETRY_UPDATE") {
          updateSystemKPIs(data.system);
          renderDevices(data.devices);
          renderAlerts(data.recent_alerts);
        }
      } catch (e) {
        console.error("WS Parse error", e);
      }
    };

    ws.onclose = () => {
      const badge = document.getElementById("ws-badge");
      if (badge) {
        badge.innerHTML = `<span class="w-1.5 h-1.5 rounded-full bg-amber-400 mr-1.5"></span> Polling Mode`;
        badge.className = "flex items-center text-xs px-2 py-0.5 rounded-full bg-amber-500/10 text-amber-400 border border-amber-500/20";
      }
      setTimeout(initWebSocket, 3000);
    };

    ws.onerror = () => {
      ws.close();
    };
  } catch (err) {
    console.warn("WebSocket not supported, relying on REST polling");
  }
}

// REST Data Refresh
async function refreshData() {
  try {
    const [devRes, alertRes, intelRes, metricRes] = await Promise.all([
      fetch("/api/devices").then(r => r.json()),
      fetch("/api/alerts").then(r => r.json()),
      fetch("/api/intelligence").then(r => r.json()),
      fetch("/api/metrics").then(r => r.json())
    ]);

    activeDevices = devRes;
    renderDevices(devRes);
    renderAlerts(alertRes);
    renderIntelligence(intelRes);

    if (metricRes && metricRes.length > 0) {
      const latest = metricRes[metricRes.length - 1];
      updateSystemKPIs({
        cpu_pct: latest.cpu_usage_pct,
        ram_mb: latest.ram_usage_mb,
        avg_detection_latency_ms: latest.detection_latency_ms,
        enforcement_latency_ms: latest.enforcement_latency_ms
      });
    }
  } catch (e) {
    console.error("Error refreshing dashboard data:", e);
  }
}

function updateSystemKPIs(sys) {
  if (!sys) return;
  const detEl = document.getElementById("kpi-det-latency");
  const enfEl = document.getElementById("kpi-enf-latency");
  const cpuEl = document.getElementById("kpi-cpu");
  const ramEl = document.getElementById("kpi-ram");

  if (detEl && sys.avg_detection_latency_ms !== undefined) {
    detEl.textContent = `${(sys.avg_detection_latency_ms / 1000).toFixed(2)} s`;
  }
  if (enfEl && sys.enforcement_latency_ms !== undefined) {
    enfEl.textContent = `${(sys.enforcement_latency_ms / 1000).toFixed(3)} s`;
  }
  if (cpuEl && sys.cpu_pct !== undefined) {
    cpuEl.textContent = `${sys.cpu_pct.toFixed(1)} %`;
  }
  if (ramEl && sys.ram_mb !== undefined) {
    ramEl.textContent = `${Math.round(sys.ram_mb)} MB`;
  }
}

// Render Devices Grid
function renderDevices(devices) {
  const grid = document.getElementById("device-grid");
  if (!grid || !devices) return;

  grid.innerHTML = devices.map(dev => {
    const score = dev.current_threat_score || 0;
    const level = dev.threat_level || "MONITOR";
    
    let levelClass = "threat-monitor";
    let badgeColor = "bg-emerald-500/20 text-emerald-400 border-emerald-500/30";
    let barColor = "#10b981";

    if (level === "BLOCK" || score >= 86) {
      levelClass = "threat-block";
      badgeColor = "bg-rose-500/20 text-rose-400 border-rose-500/30";
      barColor = "#ef4444";
    } else if (level === "QUARANTINE" || score >= 61) {
      levelClass = "threat-quarantine";
      badgeColor = "bg-orange-500/20 text-orange-400 border-orange-500/30";
      barColor = "#f97316";
    } else if (level === "RESTRICT" || score >= 31) {
      levelClass = "threat-restrict";
      badgeColor = "bg-amber-500/20 text-amber-400 border-amber-500/30";
      barColor = "#f59e0b";
    }

    return `
      <div class="device-card ${levelClass}">
        <div>
          <div class="flex items-start justify-between gap-2 mb-2">
            <div>
              <span class="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">${dev.hardware}</span>
              <h4 class="font-bold text-white text-sm mt-1">${dev.name}</h4>
              <p class="text-[11px] font-mono text-slate-400">${dev.ip_address} &bull; ${dev.mac_address}</p>
            </div>
            <span class="text-xs font-mono font-bold px-2 py-1 rounded border ${badgeColor}">
              ${level}
            </span>
          </div>

          <div class="mt-3">
            <div class="flex justify-between items-center text-xs font-mono">
              <span class="text-slate-400">Threat Score:</span>
              <span class="font-bold text-white">${score}/100</span>
            </div>
            <div class="threat-bar-container">
              <div class="threat-bar-fill" style="width: ${Math.max(4, score)}%; background: ${barColor}"></div>
            </div>
          </div>
        </div>

        <div class="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs font-mono">
          <span class="text-[11px] text-slate-400">${dev.confidence_level || 'High (90-100%)'}</span>
          <div class="flex gap-2">
            ${level !== 'MONITOR' ? `
              <button onclick="overrideDevice('${dev.id}', 'MONITOR')" class="text-emerald-400 hover:text-emerald-300 text-xs font-bold">
                🔓 Unblock
              </button>
            ` : `
              <span class="text-emerald-400 text-xs">✓ Normal</span>
            `}
          </div>
        </div>
      </div>
    `;
  }).join("");
}

// Render Alerts Feed
function renderAlerts(alerts) {
  const container = document.getElementById("alerts-list");
  const countEl = document.getElementById("alerts-count");
  if (!container || !alerts) return;

  if (countEl) countEl.textContent = `${alerts.length} incidents`;

  if (alerts.length === 0) {
    container.innerHTML = `<div class="p-6 text-center text-slate-500 text-xs font-mono">No active threats detected. Fleet operating normally.</div>`;
    return;
  }

  container.innerHTML = alerts.map(a => `
    <div onclick="openAlertModal(${JSON.stringify(a).replace(/"/g, '&quot;')})" class="p-3 bg-slate-950/80 hover:bg-slate-950 rounded-xl border border-slate-800/80 hover:border-slate-700 cursor-pointer transition flex items-center justify-between">
      <div class="flex items-center space-x-3">
        <span class="text-xs px-2 py-0.5 rounded font-mono font-bold ${a.threat_level === 'BLOCK' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'}">
          ${a.threat_level}
        </span>
        <div>
          <div class="text-xs font-bold text-white">${a.device_name} &bull; <span class="text-rose-400">${a.likely_attack}</span></div>
          <div class="text-[11px] font-mono text-slate-400">${new Date(a.timestamp).toLocaleTimeString()} &bull; Score: ${a.threat_score}/100</div>
        </div>
      </div>
      <span class="text-xs text-cyan-400 font-mono hover:underline">Explain ➔</span>
    </div>
  `).join("");
}

// Render Threat Intelligence IOCs
function renderIntelligence(intel) {
  const ipList = document.getElementById("intel-ip-list");
  if (!ipList || !intel) return;

  if (intel.blacklisted_ips && intel.blacklisted_ips.length > 0) {
    ipList.innerHTML = intel.blacklisted_ips.map(ip => `
      <div class="flex items-center justify-between bg-rose-950/30 px-2 py-1 rounded border border-rose-900/40">
        <span>${ip}</span>
        <span class="text-[9px] text-rose-400 uppercase">Blocked</span>
      </div>
    `).join("");
  } else {
    ipList.innerHTML = `<span class="text-slate-500">No malicious remote endpoints active</span>`;
  }
}

// Trigger Live Attack Simulation
async function triggerAttack(attackType) {
  const select = document.getElementById("attack-target-select");
  const deviceId = select ? select.value : "dev_08_camera";

  try {
    const res = await fetch("/api/simulate-attack", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ device_id: deviceId, attack_type: attackType })
    });
    const data = await res.json();
    if (data.alert) {
      showExplainableModal(data.alert);
    }
    refreshData();
  } catch (err) {
    alert("Error triggering attack: " + err);
  }
}

// Manual User Override
async function overrideDevice(deviceId, targetLevel) {
  try {
    await fetch("/api/override", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ device_id: deviceId, requested_level: targetLevel })
    });
    refreshData();
  } catch (err) {
    alert("Error executing override: " + err);
  }
}

function oneClickUnblockCurrent() {
  if (currentModalDeviceId) {
    overrideDevice(currentModalDeviceId, "MONITOR");
    closeModal();
  }
}

// Open Explainable Modal Dialog (Section 3.3.2)
function showExplainableModal(alertObj) {
  currentModalDeviceId = alertObj.device_id;
  const modal = document.getElementById("xai-modal");
  
  document.getElementById("modal-device-title").textContent = `${alertObj.device_name.toUpperCase()} ${alertObj.threat_level}`;
  document.getElementById("modal-badge-level").textContent = alertObj.threat_level;
  document.getElementById("modal-time").textContent = alertObj.timestamp || new Date().toLocaleTimeString();
  document.getElementById("modal-score").textContent = `${alertObj.threat_score}/100`;
  document.getElementById("modal-attack-type").textContent = alertObj.likely_attack;
  document.getElementById("modal-confidence").textContent = alertObj.confidence_level;

  const bulletsContainer = document.getElementById("modal-bullets");
  bulletsContainer.innerHTML = (alertObj.why_blocked_bullet_points || []).map(b => `
    <div class="bg-slate-950 p-3 rounded-xl border border-slate-800 space-y-1">
      <div class="flex items-center justify-between">
        <span class="font-bold text-white text-xs">${b.number}. ${b.title}</span>
        <span class="text-[10px] font-bold px-1.5 py-0.5 rounded font-mono ${b.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40' : 'bg-amber-500/20 text-amber-400 border border-amber-500/40'}">
          ${b.severity}
        </span>
      </div>
      <div class="grid grid-cols-2 text-xs font-mono text-slate-400">
        <div>Normal: <span class="text-slate-200">${b.normal}</span></div>
        <div>Detected: <span class="text-rose-400 font-bold">${b.observed}</span></div>
      </div>
      <div class="text-[11px] text-slate-300 font-sans mt-1">${b.detail}</div>
    </div>
  `).join("");

  const actionsContainer = document.getElementById("modal-actions");
  actionsContainer.innerHTML = (alertObj.recommended_actions || []).map(a => `
    <li>${a}</li>
  `).join("");

  modal.classList.remove("hidden");
  modal.classList.add("flex");
}

function openAlertModal(alert) {
  let bullets = [];
  try {
    bullets = JSON.parse(alert.details_json);
  } catch (e) {}

  showExplainableModal({
    device_id: alert.device_id,
    device_name: alert.device_name,
    threat_level: alert.threat_level,
    threat_score: alert.threat_score,
    timestamp: new Date(alert.timestamp).toLocaleTimeString(),
    likely_attack: alert.likely_attack,
    confidence_level: alert.confidence_level,
    why_blocked_bullet_points: bullets,
    recommended_actions: [
      "Keep device isolated from external WAN",
      "Factory reset recommended to purge persistence",
      "Check manufacturer portal for firmware security patches"
    ]
  });
}

function closeModal() {
  const modal = document.getElementById("xai-modal");
  modal.classList.add("hidden");
  modal.classList.remove("flex");
  currentModalDeviceId = null;
}
