// netscout.js - patched: fixes auto-zoom, popup styling, rdns display, Trace Route button

const API_BASE = "/api";
let map, markersLayer;
let lightLayer, darkLayer;
const DARK_TILE = "https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png";
const LIGHT_TILE = "https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png";
const ATTRIB = '&copy; <a href="https://carto.com/">CartoDB</a> &copy; OpenStreetMap contributors';

let ALERTS_POLL_INTERVAL = 60000;
let STATUS_POLL_INTERVAL = 10000;
let alertsPollTimer = null;
let statusPollTimer = null;
let invalidateTimer = null;

function getSavedTheme() { return localStorage.getItem("netscout_theme") || "dark"; }
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

  // Add auto-zoom control (top-left)
  const AutoZoomControl = L.Control.extend({
    options: { position: 'topleft' },
    onAdd: function () {
      const container = L.DomUtil.create('div', 'leaflet-bar');
      const btn = L.DomUtil.create('a', 'autozoom', container);
      btn.href = '#';
      btn.title = 'Auto-zoom to fit markers';
      btn.innerHTML = '&#128269;';
      btn.style.padding = '6px';
      btn.style.display = 'flex';
      btn.style.alignItems = 'center';
      btn.style.justifyContent = 'center';
      L.DomEvent.on(btn, 'click', L.DomEvent.stop).on(btn, 'click', (e) => {
        fitToMarkers();
      });
      return container;
    }
  });
  map.addControl(new AutoZoomControl());

  document.getElementById("themeDarkBtn").addEventListener("click", () => switchToTheme("dark"));
  document.getElementById("themeLightBtn").addEventListener("click", () => switchToTheme("light"));
  applyTopbarTheme(theme);

  map.whenReady(() => { setTimeout(() => safeInvalidate(), 150); });
  window.addEventListener("resize", () => safeInvalidate());
}

function safeInvalidate() {
  if (invalidateTimer) clearTimeout(invalidateTimer);
  invalidateTimer = setTimeout(() => {
    try { if (map && typeof map.invalidateSize === "function") map.invalidateSize(); } catch (e) { console.warn(e); }
  }, 150);
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
  safeInvalidate();
}

function buildPopupHtml(a) {
  // Show rdns fields if present in enrichment; otherwise show "n/a"
  const evidence = a.evidence || {};
  const enrich = a.enrichment || {};
  const src_rdns = enrich.src_rdns || enrich.src_rdns_name || enrich.src_rdns_name || enrich.src_rdns || (enrich.src_rdns === 0 ? "0" : null);
  const dst_rdns = enrich.dst_rdns || enrich.dst_rdns_name || enrich.dst_rdns || null;

  const src_rdns_display = src_rdns ? String(src_rdns) : "n/a";
  const dst_rdns_display = dst_rdns ? String(dst_rdns) : "n/a";

  // Build HTML with readable colors (popup CSS will style background and pre)
  let html = `<div class="ns-popup">`;
  html += `<div style="font-weight:700;margin-bottom:6px;">Alert ID: ${a.id}</div>`;
  html += `<div><b>Type:</b> ${a.alert_type || "N/A"}</div>`;
  html += `<div><b>Score:</b> ${a.score || 0}</div>`;
  html += `<div><b>Src:</b> ${a.src_ip || "N/A"}</div>`;
  html += `<div style="margin-left:6px;color:var(--muted);"><b>Src DNS:</b> ${escapeHtml(src_rdns_display)}</div>`;
  html += `<div><b>Dst:</b> ${a.dst_ip || "N/A"}</div>`;
  html += `<div style="margin-left:6px;color:var(--muted);"><b>Dst DNS:</b> ${escapeHtml(dst_rdns_display)}</div>`;
  html += `<div><b>When:</b> ${a.created_at || "N/A"}</div>`;
  html += `<div><b>Status:</b> ${a.status || "N/A"}</div>`;
  html += `<hr style="margin:8px 0;">`;
  html += `<div style="font-weight:600;color:var(--panel-text);">Evidence:</div>`;
  html += `<pre class="ns-pre">${escapeHtml(JSON.stringify(evidence, null, 2))}</pre>`;
  html += `<div style="font-weight:600;color:var(--panel-text); margin-top:6px;">Enrichment:</div>`;
  html += `<pre class="ns-pre">${escapeHtml(JSON.stringify(enrich, null, 2))}</pre>`;
  html += `<div style="display:flex; gap:8px; margin-top:8px;">`;
  // Trace Route button opens new page with alert_id param
  html += `<button class="ns-btn" onclick="window.open('/trace_route?alert_id=${encodeURIComponent(a.id)}','_blank')">Trace Route</button>`;
  html += `<button class="ns-btn secondary" onclick="window.open('/enrichment_cache','_blank')">Enrichment Cache</button>`;
  html += `</div>`;
  html += `</div>`;
  return html;
}

function escapeHtml(s) {
  if (s === null || s === undefined) return "";
  return String(s).replace(/[&<>"']/g, function(m){ return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[m]; });
}

function fitToMarkers() {
  try {
    if (!markersLayer) return;
    // Build bounds from all marker layers
    const layers = markersLayer.getLayers ? markersLayer.getLayers() : [];
    if (!layers.length) return;
    const group = L.featureGroup(layers);
    const bounds = group.getBounds();
    if (bounds && bounds.isValid()) {
      map.fitBounds(bounds.pad(0.15));
    }
  } catch (e) {
    console.warn("fitToMarkers failed", e);
  }
}

async function loadAlerts() {
  ensureMap();

  const since = document.getElementById("sinceSelect").value;
  const type = document.getElementById("filterType").value;
  const src = document.getElementById("filterSrc").value.trim();
  const dst = document.getElementById("filterDst").value.trim();
  const minScore = document.getElementById("minScore").value || 0;
  const limit = 500;
  const excludePrivate = document.getElementById("excludePrivate") && document.getElementById("excludePrivate").checked;

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
    let alerts = data.alerts || [];

    if (excludePrivate) {
      alerts = alerts.filter(a => {
        const s = (a.src_ip || "").trim();
        return !(s.startsWith("192.168."));
      });
    }

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
      // Use a sanitized popup and ensure popup content uses CSS classes defined in netscout.css
      marker.bindPopup(buildPopupHtml(a), { maxWidth: 420 });
      markersLayer.addLayer(marker);
    }
  });

  // After markers added, ensure map redraw and keep map visible
  safeInvalidate();
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
    document.getElementById("excludePrivate").checked = false;
    loadAlerts();
  });
  document.getElementById("bulkEnrichBtn").addEventListener("click", () => {
    const n = Number(document.getElementById("bulkEnrichCount").value || 10);
    if (n <= 0) return alert("Enter a positive number");
    bulkEnrichNewest(n);
  });

  document.getElementById("themeDarkBtn").addEventListener("click", () => switchToTheme("dark"));
  document.getElementById("themeLightBtn").addEventListener("click", () => switchToTheme("light"));

  // Auto-refresh controls
  const autoEnabled = document.getElementById("autoRefreshEnabled");
  const refreshSelect = document.getElementById("refreshInterval");
  const autoStatus = document.getElementById("autoRefreshStatus");

  function applyRefreshSettings() {
    const enabled = autoEnabled.checked;
    const interval = Number(refreshSelect.value || 60) * 1000;
    ALERTS_POLL_INTERVAL = interval;
    autoStatus.textContent = enabled ? `on (${interval/1000}s)` : 'off';
    if (alertsPollTimer) clearInterval(alertsPollTimer);
    if (enabled) alertsPollTimer = setInterval(loadAlerts, ALERTS_POLL_INTERVAL);
  }

  autoEnabled.addEventListener("change", applyRefreshSettings);
  refreshSelect.addEventListener("change", applyRefreshSettings);

  // When log dropdown changes, ensure map redraw
  const logSelect = document.getElementById("logSelect");
  if (logSelect) logSelect.addEventListener("change", () => safeInvalidate());
}

function startPolling() {
  if (alertsPollTimer) clearInterval(alertsPollTimer);
  if (statusPollTimer) clearInterval(statusPollTimer);
  loadAlerts();
  pollStatus();
  statusPollTimer = setInterval(pollStatus, STATUS_POLL_INTERVAL);
  const enabled = document.getElementById("autoRefreshEnabled") ? document.getElementById("autoRefreshEnabled").checked : true;
  const interval = Number(document.getElementById("refreshInterval") ? document.getElementById("refreshInterval").value : 60) * 1000;
  ALERTS_POLL_INTERVAL = interval;
  if (alertsPollTimer) clearInterval(alertsPollTimer);
  if (enabled) alertsPollTimer = setInterval(loadAlerts, ALERTS_POLL_INTERVAL);
  const autoStatus = document.getElementById("autoRefreshStatus");
  if (autoStatus) autoStatus.textContent = enabled ? `on (${interval/1000}s)` : 'off';
}

window.addEventListener("load", () => {
  initMap();
  wireUi();
  startPolling();
});
