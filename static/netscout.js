// netscout.js
// Map + UI logic for Net-Scout (light/dark theme support, dark default)

const API_BASE = "/api";
let map, markersLayer;
let lightLayer, darkLayer;
const DARK_TILE = "https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png";
const LIGHT_TILE = "https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png";
const ATTRIB = '&copy; <a href="https://carto.com/">CartoDB</a> &copy; OpenStreetMap contributors';

function getSavedTheme() {
  const t = localStorage.getItem("netscout_theme");
  return t ? t : "dark";
}

function setSavedTheme(theme) {
  localStorage.setItem("netscout_theme", theme);
}

function applyTopbarTheme(theme) {
  const topbar = document.getElementById("topbar");
  if (!topbar) return;
  if (theme === "dark") {
    topbar.style.background = "#0b3d91";
    topbar.style.color = "#fff";
  } else {
    topbar.style.background = "#f8f9fa";
    topbar.style.color = "#111";
  }
  topbar.setAttribute("data-theme", theme);
}

function initMap() {
  const theme = getSavedTheme();

  map = L.map("map", { zoomControl: true }).setView([20, 0], 2);

  lightLayer = L.tileLayer(LIGHT_TILE, { attribution: ATTRIB, maxZoom: 19 });
  darkLayer = L.tileLayer(DARK_TILE, { attribution: ATTRIB, maxZoom: 19 });

  // Default: dark
  if (theme === "light") {
    lightLayer.addTo(map);
  } else {
    darkLayer.addTo(map);
  }

  markersLayer = L.layerGroup().addTo(map);

  // Theme buttons
  document.getElementById("themeDarkBtn").addEventListener("click", () => {
    switchToTheme("dark");
  });
  document.getElementById("themeLightBtn").addEventListener("click", () => {
    switchToTheme("light");
  });

  applyTopbarTheme(theme);
}

function switchToTheme(theme) {
  setSavedTheme(theme);
  if (!map) return;
  if (theme === "light") {
    map.removeLayer(darkLayer);
    lightLayer.addTo(map);
  } else {
    map.removeLayer(lightLayer);
    darkLayer.addTo(map);
  }
  applyTopbarTheme(theme);
}

// Fetch alerts and render markers + table
async function loadAlerts() {
  const since = document.getElementById("sinceSelect").value;
  const minScore = Number(document.getElementById("minScore").value || 0);
  // Convert simple relative windows to ISO by letting server handle; we pass raw string
  const url = `${API_BASE}/alerts?since=${encodeURIComponent(since)}&limit=500`;
  const res = await fetch(url);
  const data = await res.json();
  const alerts = data.alerts || [];

  // Clear markers and table
  markersLayer.clearLayers();
  const tbody = document.querySelector("#alertsTable tbody");
  tbody.innerHTML = "";

  alerts.forEach(a => {
    const score = Number(a.score || 0);
    if (score < minScore) return;

    // Add table row
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td style="padding:6px">${a.id}</td>
      <td>${a.alert_type}</td>
      <td>${a.src_ip || ""}</td>
      <td>${a.dst_ip || ""}</td>
      <td>${score}</td>
      <td>${a.created_at || ""}</td>
      <td>
        <button class="small" data-id="${a.id}" data-action="enrich">Enrich</button>
      </td>
    `;
    tbody.appendChild(tr);

    // Wire enrich button
    tr.querySelector("button[data-action='enrich']").addEventListener("click", () => {
      enrichAlert(a.id);
    });

    // Add marker if coordinates exist
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

      const popupHtml = buildPopupHtml(a);
      marker.bindPopup(popupHtml);
      markersLayer.addLayer(marker);
    }
  });
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

async function runScan(enrich=false, dry_run=false) {
  const since = document.getElementById("sinceSelect").value;
  const body = { since, enrich, dry_run };
  const res = await fetch(`${API_BASE}/run_scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  const data = await res.json();
  alert("Scan started. Check log: " + (data.log || "n/a"));
}

async function enrichAlert(alert_id) {
  const res = await fetch(`${API_BASE}/enrich_alert`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ alert_id })
  });
  const data = await res.json();
  alert("Enrichment started. Check log: " + (data.log || "n/a"));
}

function wireUi() {
  document.getElementById("runScanBtn").addEventListener("click", () => runScan(false, false));
  document.getElementById("runScanEnrichBtn").addEventListener("click", () => runScan(true, false));
  document.getElementById("refreshBtn").addEventListener("click", () => loadAlerts());
  document.getElementById("sinceSelect").addEventListener("change", () => loadAlerts());
  document.getElementById("minScore").addEventListener("change", () => loadAlerts());
}

window.addEventListener("load", () => {
  initMap();
  wireUi();
  loadAlerts();
});
