const hostEl = document.getElementById("host");
const clientIpEl = document.getElementById("clientIp");
const statusEl = document.getElementById("status");
const detailsEl = document.getElementById("details");
const previewEl = document.getElementById("preview");
const downloadClientEl = document.getElementById("downloadClient");
const downloadServerEl = document.getElementById("downloadServer");
const startServerBtn = document.getElementById("startServerBtn");
const reloadPeerBtn = document.getElementById("reloadPeerBtn");
const startPairingBtn = document.getElementById("startPairingBtn");
const pairingStatusEl = document.getElementById("pairingStatus");
const pairingStatusTextEl = document.getElementById("pairingStatusText");
const downloadPairingEl = document.getElementById("downloadPairing");
const debugSectionEl = document.getElementById("debugSection");
const debugLogsEl = document.getElementById("debugLogs");

function setStatus(text, connected = false) {
  statusEl.textContent = text;
  statusEl.className = connected ? "ok" : "warn";
}

async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options
  });
  const text = await res.text();
  let data;
  try { data = text ? JSON.parse(text) : {}; } catch { data = { raw: text }; }
  if (!res.ok) throw new Error(data.error || data.raw || `HTTP ${res.status}`);
  return data;
}

function pageHost() {
  return window.location.hostname || "localhost";
}

function renderStatus(data) {
  hostEl.textContent = data.host || pageHost();
  clientIpEl.textContent = data.clientAddress || "-";
  setStatus(data.connected ? "Connection received!" : "Waiting for VPN connection...", !!data.connected);

  const handshakeText = data.handshakeUnix ? new Date(data.handshakeUnix * 1000).toLocaleString() : "none";
  detailsEl.textContent = `Tunnel: ${data.tunnelRunning ? "running" : "stopped"} | Handshake: ${handshakeText} | Age: ${data.handshakeAgeSeconds ?? "n/a"}s`;

  downloadClientEl.href = data.clientConfigUrl;
  downloadServerEl.href = data.serverConfigUrl;

  previewEl.value =
`Client config: ${data.clientConfigUrl}
Server config: ${data.serverConfigUrl}`;
}

let currentPairingId = null;

async function startPairing() {
  try {
    const result = await api("/api/start-pairing", { method: "POST", body: "{}" });
    currentPairingId = result.pairingId;
    pairingStatusEl.style.display = "block";
    pairingStatusTextEl.textContent = "Connecting to iOS device via VPN...";
    downloadPairingEl.style.display = "none";
    
    pollPairingStatus();
  } catch (err) {
    alert(err.message);
  }
}

async function pollPairingStatus() {
  if (!currentPairingId) return;
  
  try {
    const status = await api(`/api/pairing/${currentPairingId}/status`);
    
    // Display debug logs
    if (status.debugLogs && status.debugLogs.length > 0) {
      debugSectionEl.style.display = "block";
      const logText = status.debugLogs.map(log => {
        const time = new Date(log.timestamp).toLocaleTimeString();
        const dataStr = log.data ? ` | Data: ${JSON.stringify(log.data)}` : '';
        return `[${time}] [${log.step}] ${log.message}${dataStr}`;
      }).join('\n');
      debugLogsEl.textContent = logText;
      debugLogsEl.scrollTop = debugLogsEl.scrollHeight;
    }
    
    switch (status.status) {
      case "extracting":
        pairingStatusTextEl.textContent = "Extracting public key from iOS device...";
        break;
      case "success":
        pairingStatusTextEl.textContent = "Public key extraction successful!";
        downloadPairingEl.href = `/api/pairing/${currentPairingId}/download`;
        downloadPairingEl.style.display = "inline-block";
        return;
      case "failed":
        pairingStatusTextEl.textContent = "Extraction failed: " + (status.error || "Unknown error");
        return;
      default:
        pairingStatusTextEl.textContent = "Status: " + status.status;
    }
    
    setTimeout(pollPairingStatus, 2000);
  } catch (err) {
    pairingStatusTextEl.textContent = "Error checking status: " + err.message;
  }
}

async function refresh() {
  const data = await api("/api/status");
  renderStatus(data);
}

async function loadInitial() {
  const data = await api("/api/status");
  renderStatus(data);
}

startServerBtn.addEventListener("click", async () => {
  try {
    await api("/api/start-server", { method: "POST", body: "{}" });
    const data = await api("/api/status");
    renderStatus(data);
  } catch (err) {
    alert(err.message);
  }
});

reloadPeerBtn.addEventListener("click", async () => {
  try {
    await api("/api/reload-peer", { method: "POST", body: "{}" });
    const data = await api("/api/status");
    renderStatus(data);
  } catch (err) {
    alert(err.message);
  }
});

startPairingBtn.addEventListener("click", async () => {
  startPairing();
});


loadInitial().catch(err => {
  setStatus(err.message);
});

setInterval(() => {
  api("/api/status")
    .then(renderStatus)
    .catch(() => {});
}, 2000);