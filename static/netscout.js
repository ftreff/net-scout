// netscout.js - client logic for Net-Scout UI (patched)
// Added guards to ensure map and markersLayer exist and call map.invalidateSize()
// after rendering alerts or when layout changes so the Leaflet map doesn't disappear.

const API_BASE = "/api";
let map, markersLayer;
let lightLayer, darkLayer;
const DARK_TILE = "https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png";
const LIGHT_TILE = "https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png";
const ATTRIB = '&copy; <a href="https://carto.com/">CartoDB</a> &copy; OpenStreetMap contributors';

let ALERTS_POLL_INTERVAL = 60000; // 60s
let STATUS_POLL_INTERVAL = 10000; // 10s
let alertsPollTimer = null;
let statusPollTimer = null;

function getSavedTheme() {
  return localStorage.getItem("netscout_theme") || "dark";
}
function setSavedTheme(t) { localStorage.setItem("netscout_theme", t); }

function applyTopbarTheme(theme) {
  const topbar = document.getElementById("topbar");
  if (!topbar) return;
  if (theme === "dark") {
    topbar.style.background = "#0b3d91";
    topbar.style.color = "#fff";
    document.documentElement.setAttribute("data-theme", "dark");
  } else {
    topbar.style.background = "#f8f9fa";
    topbar.style.color = "#111";
    document.documentElement.setAttribute("data-theme", "light");
  }
}

function ensureMap() {
  if (!map) initMap();
  if (!markersLayer && map) markersLayer = L.layerGroup().addTo(map);
}

function initMap() {
  const theme = getSavedTheme();
  map = L.map("map", { zoomControl: true }).setView([20, 0], 2);

  lightLayer = L.tileLayer(LIGHT_TILE, { attribution: ATTRIB, maxZoom: 19 });
  darkLayer = L.tileLayer(DARK_TILE, { attribution: ATTRIB, maxZoom: 19 });

  if (theme === "light") lightLayer.addTo(map);
  else darkLayer.addTo(map);

  markersLayer = L.layerGroup().addTo(map);

  document.getElementById("themeDarkBtn").addEventListener("click", () => switchToTheme("dark"));
  document.getElementById("themeLightBtn").addEventListener("click", () => switchToTheme("light"));
  applyTopbarTheme(theme);

  // Ensure map redraw after initial layout
  map.whenReady(() => {
    setTimeout(() => {
      try { map.invalidateSize(); } catch (e) { /* ignore */ }
    }, 150);
  });

  // Recalculate on window resize
  window.addEventListener("resize", () => {
    try { if (map && typeof map.invalidateSize === "function") map.invalidateSize(); } catch (e) {}
  });
}

function switchToTheme(theme) {
  setSavedTheme(theme);
  if (!map) return;
  if (theme === "light") {
    if (map.hasLayer(darkLayer)) map.removeLayer(darkLayer);
    lightLayer.addTo(map);
  } else {
    if (map.hasLayer(lightLayer)) map.removeLayer(lightLayer);
    darkLayer.addTo(map);
  }
  applyTopbarTheme(theme);
}

function buildPopupHtml(a) {
  const evidence = a.evidence || {};
  const enrich = a.enrichment || {};
  let html = `<div style="min-width:260px;">`;
  html += `<b>Alert ID:</b> ${a.id}<br>`;
  html += `<b>Type:</b> ${a.alert_type}<br>`;
  html += `<b>Score:</b> ${a.score}<br>`;
  html += `<b>Src:</b> ${a.src_ip || "N/A"}<br>`;
  html += `<b>Dst:</b> ${a.dst_ip || "N/A"}<br>`;
  html += `<b>When:</b> ${a.created_at || "N/A"}<br>`;
  html += `<b>Status:</b> ${a.status || "N/A"}<br>`;
  html += `<hr>`;
  html += `<b>Evidence:</b><pre style="white-space:pre-wrap;max-height:120px;overflow:auto;">${JSON.stringify(evidence, null, 2)}</pre>`;
  if (Object.keys(enrich).length) {
    html += `<hr><b>Enrichment:</b><pre style="white-space:pre-wrap;max-height:160px;overflow:auto;">${JSON.stringify(enrich, null, 2)}</pre>`;
  } else {
    html += `<div style="opacity:0.8; margin-top:6px;">No enrichment yet</div>`;
  }
  html += `</div>`;
  return html;
}

async function loadAlerts() {
  ensureMap();

  const since = document.getElementById("sinceSelect").value;
  const type = document.getElementById("filterType").value;
  const src = document.getElementById("filterSrc").value.trim();
  const dst = document.getElementById("filterDst").value.trim();
  const minScore = document.getElementById("minScore").value || 0;
  const limit = 500;

  const params = new URLSearchParams();
  if (since) params.set("since", since);
  if (type) params.set("type", type);
  if (src) params.set("src", src);
  if (dst) params.set("dst", dst);
  if (minScore) params.set("min_score", minScore);
  params.set("limit", limit);

  const url = `${API_BASE}/alerts?${params.toString()}`;
  try {
    const res = await fetch(url);
    const data = await res.json();
    const alerts = data.alerts || [];
    renderAlerts(alerts);
  } catch (err) {
    console.error("Failed to load alerts", err);
  }
}

function renderAlerts(alerts) {
  ensureMap();

  markersLayer.clearLayers();
  const tbody = document.querySelector("#alertsTable tbody");
  tbody.innerHTML = "";

  alerts.forEach(a => {
    const score = Number(a.score || 0);

    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td style="padding:6px">${a.id}</td>
      <td>${a.alert_type}</td>
      <td>${a.src_ip || ""}</td>
      <td>${a.dst_ip || ""}</td>
      <td>${score}</td>
      <td>${a.created_at || ""}</td>
      <td>${a.status || "new"}</td>
      <td>
        <button class="small" data-id="${a.id}" data-action="enrich">Enrich</button>
        <button class="small" data-id="${a.id}" data-action="snooze">Snooze</button>
        <button class="small" data-id="${a.id}" data-action="fp">Mark FP</button>
      </td>
    `;
    tbody.appendChild(tr);

    tr.querySelector("button[data-action='enrich']").addEventListener("click", () => enrichAlert(a.id));
    tr.querySelector("button[data-action='snooze']").addEventListener("click", () => snoozeAlert(a.id));
    tr.querySelector("button[data-action='fp']").addEventListener("click", () => markFalsePositive(a.id));

    if (a.latitude && a.longitude) {
      const color = score >= 80 ? "red" : score >= 50 ? "orange" : "blue";
      const marker = L.circleMarker([a.latitude, a.longitude], {
        radius: 8,
        fillColor: color,
        color: "#000",
        weight: 1,
        opacity: 1,
        fillOpacity: 0.8
      });
      marker.bindPopup(buildPopupHtml(a));
      markersLayer.addLayer(marker);
    }
  });

  // Force Leaflet to recalculate size after DOM updates so the map remains visible
  setTimeout(() => {
    try {
      if (map && typeof map.invalidateSize === "function") {
        map.invalidateSize();
      }
    } catch (e) {
      console.warn("map.invalidateSize() failed", e);
    }
  }, 200);
}

async function runScan(enrich = false, dry_run = false) {
  const since = document.getElementById("sinceSelect").value;
  const body = { since, enrich, dry_run };
  try {
    const res = await fetch(`${API_BASE}/run_scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    const data = await res.json();
    alert("Scan started. Log: " + (data.log || "n/a"));
  } catch (err) {
    console.error("Failed to start scan", err);
    alert("Failed to start scan");
  }
}

async function enrichAlert(alert_id) {
  try {
    const res = await fetch(`${API_BASE}/enrich_alert`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ alert_id })
    });
    const data = await res.json();
    alert("Enrichment started. Log: " + (data.log || "n/a"));
  } catch (err) {
    console.error("Failed to start enrichment", err);
    alert("Failed to start enrichment");
  }
}

async function bulkEnrichNewest(n) {
  try {
    const res = await fetch(`${API_BASE}/enrich_bulk`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ limit: n })
    });
    const data = await res.json();
    alert("Bulk enrichment started. Log: " + (data.log || (data.logs || []).join(", ")));
  } catch (err) {
    console.error("Failed to start bulk enrich", err);
    alert("Failed to start bulk enrich");
  }
}

async function snoozeAlert(alert_id) {
  const duration = prompt("Snooze duration in minutes (default 60):", "60");
  if (duration === null) return;
  try {
    const res = await fetch(`${API_BASE}/snooze_alert`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ alert_id, action: "snooze", duration_minutes: Number(duration || 60) })
    });
    const data = await res.json();
    if (data.status === "ok") {
      alert("Alert snoozed");
      loadAlerts();
    } else {
      alert("Failed to snooze: " + JSON.stringify(data));
    }
  } catch (err) {
    console.error("Snooze failed", err);
    alert("Snooze failed");
  }
}

async function markFalsePositive(alert_id) {
  if (!confirm("Mark alert " + alert_id + " as false positive?")) return;
  try {
    const res = await fetch(`${API_BASE}/snooze_alert`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ alert_id, action: "false_positive" })
    });
    const data = await res.json();
    if (data.status === "ok") {
      alert("Marked false positive");
      loadAlerts();
    } else {
      alert("Failed: " + JSON.stringify(data));
    }
  } catch (err) {
    console.error("Mark FP failed", err);
    alert("Mark FP failed");
  }
}

async function pollStatus() {
  try {
    const res = await fetch(`${API_BASE}/status`);
    const data = await res.json();
    updateStatusUI(data);
  } catch (err) {
    console.error("Status poll failed", err);
  }
}

function formatSeconds(s) {
  if (s == null) return "n/a";
  s = Number(s);
  if (isNaN(s)) return "n/a";
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const sec = Math.floor(s % 60);
  if (m < 60) return `${m}m ${sec}s`;
  const h = Math.floor(m / 60);
  const mm = m % 60;
  return `${h}h ${mm}m`;
}

function updateStatusUI(data) {
  const scan = data.scan_progress || {};
  const enrich = data.enrich_progress || {};
  const tasks = data.tasks || {};

  const scanFill = document.getElementById("scanStatusFill");
  const scanLabel = document.getElementById("scanStatusLabel");
  const lastScan = document.getElementById("lastScanTime");
  const enrichFill = document.getElementById("enrichStatusFill");
  const enrichLabel = document.getElementById("enrichStatusLabel");
  const lastEnrich = document.getElementById("lastEnrichTime");

  // Use numeric percent if available; otherwise fallback to heuristics
  const scanPercent = Number(scan.percent || 0);
  try { if (scanFill) scanFill.style.width = `${scanPercent}%`; } catch (e) {}
  if (tasks.scan_running) {
    scanLabel.textContent = `Running (${scan.processed || 0}/${scan.total_candidates || "?"})`;
  } else if (scan.finished) {
    scanLabel.textContent = "Complete";
  } else {
    scanLabel.textContent = `${scanPercent}%`;
  }
  if (lastScan) lastScan.textContent = data.last_scan_log || "never";

  const enrichPercent = Number(enrich.percent || 0);
  try { if (enrichFill) enrichFill.style.width = `${enrichPercent}%`; } catch (e) {}
  if (tasks.enrich_running) {
    enrichLabel.textContent = `Running (${enrich.total_processed || 0}/${enrich.total_started || "?"})`;
  } else {
    enrichLabel.textContent = `${enrichPercent}%`;
  }
  if (lastEnrich) lastEnrich.textContent = data.last_enrich_log || "never";
}

function wireUi() {
  document.getElementById("runScanBtn").addEventListener("click", () => runScan(false, false));
  document.getElementById("runScanEnrichBtn").addEventListener("click", () => runScan(true, false));
  document.getElementById("refreshBtn").addEventListener("click", () => loadAlerts());
  document.getElementById("sinceSelect").addEventListener("change", () => loadAlerts());
  document.getElementById("applyFiltersBtn").addEventListener("click", () => loadAlerts());
  document.getElementById("clearFiltersBtn").addEventListener("click", () => {
    document.getElementById("filterType").value = "";
    document.getElementById("filterSrc").value = "";
    document.getElementById("filterDst").value = "";
    document.getElementById("minScore").value = 0;
    loadAlerts();
  });
  document.getElementById("bulkEnrichBtn").addEventListener("click", () => {
    const n = Number(document.getElementById("bulkEnrichCount").value || 10);
    if (n <= 0) return alert("Enter a positive number");
    bulkEnrichNewest(n);
  });

  document.getElementById("themeDarkBtn").addEventListener("click", () => switchToTheme("dark"));
  document.getElementById("themeLightBtn").addEventListener("click", () => switchToTheme("light"));
}

function startPolling() {
  if (alertsPollTimer) clearInterval(alertsPollTimer);
  if (statusPollTimer) clearInterval(statusPollTimer);
  loadAlerts();
  pollStatus();
  alertsPollTimer = setInterval(loadAlerts, ALERTS_POLL_INTERVAL);
  statusPollTimer = setInterval(pollStatus, STATUS_POLL_INTERVAL);
}

window.addEventListener("load", () => {
  initMap();
  wireUi();
  startPolling();
});
