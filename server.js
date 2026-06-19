const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { spawnSync } = require("child_process");
const SimpleLockdownClient = require("./lockdown-simple");
const plist = require("plist");

const app = express();
const PORT = Number.parseInt(process.env.PORT || "3000", 10);

const WG_TUNNEL_NAME = process.env.WG_TUNNEL_NAME || "WebTrust";
const WG_PORT = process.env.WG_PORT || "51820";
const WG_SERVER_ADDRESS = process.env.WG_SERVER_ADDRESS || "10.66.66.1/24";
const WG_CLIENT_ADDRESS_PREFIX = process.env.WG_CLIENT_ADDRESS_PREFIX || "10.66.66.";
const WG_ALLOWED_IPS = process.env.WG_ALLOWED_IPS || "0.0.0.0/0, ::/0";
const WG_DNS = process.env.WG_DNS || "1.1.1.1";
const WG_KEEPALIVE = process.env.WG_KEEPALIVE || "25";
const AUTO_START =
  String(process.env.AUTO_START_WG || "").toLowerCase() === "1" ||
  String(process.env.AUTO_START_WG || "").toLowerCase() === "true";

const DATA_DIR = path.join(__dirname, "data");
const CONF_DIR = path.join(DATA_DIR, "conf");
const LOG_FILE = path.join(DATA_DIR, "webtrust.log");

fs.mkdirSync(CONF_DIR, { recursive: true });

const logs = [];
const pairingSessions = new Map();

// Static configuration
const STATIC_CLIENT_ADDRESS = process.env.STATIC_CLIENT_ADDRESS || "10.66.66.2/32";
const STATIC_CLIENT_PRIVATE_KEY_PATH = path.join(CONF_DIR, "client-private.key");
const STATIC_CLIENT_PUBLIC_KEY_PATH = path.join(CONF_DIR, "client-public.key");

function log(level, msg, extra) {
  const entry = {
    time: new Date().toISOString(),
    level,
    msg,
    extra: extra === undefined ? null : extra
  };

  logs.push(entry);
  if (logs.length > 500) logs.shift();

  const line =
    `[${entry.time}] [${level}] ${msg}` +
    (extra === undefined ? "" : ` ${typeof extra === "string" ? extra : JSON.stringify(extra)}`);

  fs.appendFileSync(LOG_FILE, line + "\n", "utf8");
  console.log(line);
}

const info = (msg, extra) => log("INFO", msg, extra);
const warn = (msg, extra) => log("WARN", msg, extra);
const err = (msg, extra) => log("ERROR", msg, extra);

function randomId(bytes = 8) {
  return crypto.randomBytes(bytes).toString("hex");
}

function normalizeHost(host) {
  return String(host || "")
    .trim()
    .replace(/^https?:\/\//i, "")
    .split(",")[0]
    .split("/")[0]
    .trim()
    .replace(/:\d+$/, "");
}

function getPageHost(req) {
  const forwarded = req.get("x-forwarded-host");
  const host = forwarded || req.get("host") || "";
  return normalizeHost(host);
}

function where(name) {
  const r = spawnSync("where", [name], { encoding: "utf8", windowsHide: true });
  if (r.status === 0) {
    const first = r.stdout.split(/\r?\n/).map(s => s.trim()).find(Boolean);
    if (first) return first;
  }
  return null;
}

function findBinary(envName, candidates) {
  const envValue = process.env[envName];
  if (envValue && fs.existsSync(envValue)) return envValue;

  for (const candidate of candidates) {
    if (candidate.includes(path.sep) && fs.existsSync(candidate)) return candidate;
    const resolved = where(candidate);
    if (resolved) return resolved;
  }

  return null;
}

const WG_EXE = findBinary("WG_BIN", [
  "wg.exe",
  path.join(process.env["ProgramFiles"] || "C:\\Program Files", "WireGuard", "wg.exe"),
  path.join(process.env["ProgramFiles(x86)"] || "C:\\Program Files (x86)", "WireGuard", "wg.exe")
]);

const WIREGUARD_EXE = findBinary("WIREGUARD_BIN", [
  "wireguard.exe",
  path.join(process.env["ProgramFiles"] || "C:\\Program Files", "WireGuard", "wireguard.exe"),
  path.join(process.env["ProgramFiles(x86)"] || "C:\\Program Files (x86)", "WireGuard", "wireguard.exe")
]);

function run(file, args, input = null) {
  info(`exec ${path.basename(file)} ${args.join(" ")}`);
  const r = spawnSync(file, args, {
    input: input ?? undefined,
    encoding: "utf8",
    windowsHide: true
  });

  if (r.error) {
    err(`exec failed ${file}`, r.error.message);
    throw r.error;
  }

  if (r.stdout) info(`stdout ${path.basename(file)}`, r.stdout.trim());
  if (r.stderr) warn(`stderr ${path.basename(file)}`, r.stderr.trim());
  if (r.status !== 0) warn(`nonzero exit ${path.basename(file)}`, { status: r.status });

  return {
    status: r.status,
    stdout: r.stdout || "",
    stderr: r.stderr || ""
  };
}

function serviceName() {
  return `WireGuardTunnel$${WG_TUNNEL_NAME}`;
}

function tunnelConfPath() {
  return path.join(CONF_DIR, `${WG_TUNNEL_NAME}.conf`);
}

function serverPrivatePath() {
  return path.join(CONF_DIR, "server-private.key");
}

function serverPublicPath() {
  return path.join(CONF_DIR, "server-public.key");
}

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

function wgGenKey() {
  if (!WG_EXE) throw new Error("wg.exe not found. Install WireGuard for Windows first.");
  const r = run(WG_EXE, ["genkey"]);
  const key = r.stdout.trim();
  if (!key) throw new Error("wg genkey returned empty output");
  return key;
}

function wgPubKey(privateKey) {
  if (!WG_EXE) throw new Error("wg.exe not found. Install WireGuard for Windows first.");
  const r = run(WG_EXE, ["pubkey"], privateKey + "\n");
  const key = r.stdout.trim();
  if (!key) throw new Error("wg pubkey returned empty output");
  return key;
}

function ensureServerKeys() {
  ensureDir(CONF_DIR);

  let privateKey = null;
  let publicKey = null;

  if (fs.existsSync(serverPrivatePath()) && fs.existsSync(serverPublicPath())) {
    privateKey = fs.readFileSync(serverPrivatePath(), "utf8").trim();
    publicKey = fs.readFileSync(serverPublicPath(), "utf8").trim();
  }

  if (!privateKey || !publicKey) {
    info("generating persistent server keypair");
    privateKey = wgGenKey();
    publicKey = wgPubKey(privateKey);
    fs.writeFileSync(serverPrivatePath(), privateKey, "utf8");
    fs.writeFileSync(serverPublicPath(), publicKey, "utf8");
  }

  return { privateKey, publicKey };
}

function ensureClientKeys() {
  ensureDir(CONF_DIR);

  let privateKey = null;
  let publicKey = null;

  if (fs.existsSync(STATIC_CLIENT_PRIVATE_KEY_PATH) && fs.existsSync(STATIC_CLIENT_PUBLIC_KEY_PATH)) {
    privateKey = fs.readFileSync(STATIC_CLIENT_PRIVATE_KEY_PATH, "utf8").trim();
    publicKey = fs.readFileSync(STATIC_CLIENT_PUBLIC_KEY_PATH, "utf8").trim();
  }

  if (!privateKey || !publicKey) {
    info("generating persistent client keypair");
    privateKey = wgGenKey();
    publicKey = wgPubKey(privateKey);
    fs.writeFileSync(STATIC_CLIENT_PRIVATE_KEY_PATH, privateKey, "utf8");
    fs.writeFileSync(STATIC_CLIENT_PUBLIC_KEY_PATH, publicKey, "utf8");
  }

  return { privateKey, publicKey };
}

function serverPublicKey() {
  return ensureServerKeys().publicKey;
}

function clientPublicKey() {
  return ensureClientKeys().publicKey;
}

function buildServerConf() {
  const { privateKey } = ensureServerKeys();
  return [
    "[Interface]",
    `PrivateKey = ${privateKey}`,
    `Address = ${WG_SERVER_ADDRESS}`,
    `ListenPort = ${WG_PORT}`,
    ""
  ].join("\n");
}

function buildClientConf(host) {
  const { privateKey: clientPrivate } = ensureClientKeys();
  const endpointHost = normalizeHost(host) || "your-public-host.example";
  return [
    "[Interface]",
    `PrivateKey = ${clientPrivate}`,
    `Address = ${STATIC_CLIENT_ADDRESS}`,
    `DNS = ${WG_DNS}`,
    "",
    "[Peer]",
    `PublicKey = ${serverPublicKey()}`,
    `Endpoint = ${endpointHost}:${WG_PORT}`,
    `AllowedIPs = ${WG_ALLOWED_IPS}`,
    `PersistentKeepalive = ${WG_KEEPALIVE}`,
    ""
  ].join("\n");
}

function writeConfigs(host) {
  fs.writeFileSync(tunnelConfPath(), buildServerConf(), "utf8");
  const clientConfPath = path.join(CONF_DIR, "client.conf");
  fs.writeFileSync(clientConfPath, buildClientConf(host), "utf8");
  info("configs written", {
    tunnelConf: tunnelConfPath(),
    clientConf: clientConfPath
  });
}

function tunnelRunning() {
  const q = run("sc", ["query", serviceName()]);
  return /STATE\s*:\s*\d+\s+RUNNING/i.test(q.stdout);
}

function tunnelInstalled() {
  const q = run("sc", ["query", serviceName()]);
  return q.status === 0 && !/The specified service does not exist/i.test((q.stdout || "") + (q.stderr || ""));
}

function uninstallTunnel() {
  if (!tunnelInstalled()) return;

  try {
    run(WIREGUARD_EXE, ["/uninstalltunnelservice", tunnelConfPath()]);
  } catch (e) {
    warn("uninstallTunnel failed", e.message);
  }

  try {
    run("sc", ["stop", serviceName()]);
  } catch (e) {
    warn("sc stop failed", e.message);
  }
}

function installTunnelFromCurrentConf() {
  if (!WIREGUARD_EXE) throw new Error("wireguard.exe not found. Install WireGuard for Windows first.");

  const conf = tunnelConfPath();
  if (!fs.existsSync(conf)) {
    fs.writeFileSync(conf, buildServerConf(), "utf8");
  }

  if (tunnelInstalled()) {
    uninstallTunnel();
  }

  const install = run(WIREGUARD_EXE, ["/installtunnelservice", conf]);
  if (install.status !== 0) {
    throw new Error((install.stderr || install.stdout || "installtunnelservice failed").trim());
  }

  const start = run("sc", ["start", serviceName()]);
  if (
    start.status !== 0 &&
    !/START_PENDING|RUNNING/i.test((start.stdout || "") + "\n" + (start.stderr || ""))
  ) {
    throw new Error((start.stderr || start.stdout || "sc start failed").trim());
  }

  info("tunnel installed and started", { service: serviceName(), conf });
}

function ensureTunnelReady() {
  ensureServerKeys();
  fs.writeFileSync(tunnelConfPath(), buildServerConf(), "utf8");

  if (!tunnelInstalled() || !tunnelRunning()) {
    installTunnelFromCurrentConf();
  } else {
    info("tunnel already running");
  }
}

function addPeer() {
  if (!WG_EXE) throw new Error("wg.exe not found. Install WireGuard for Windows first.");

  const clientPublic = clientPublicKey();
  const r = run(WG_EXE, [
    "set",
    WG_TUNNEL_NAME,
    "peer",
    clientPublic,
    "allowed-ips",
    STATIC_CLIENT_ADDRESS
  ]);

  if (r.status !== 0) {
    throw new Error((r.stderr || r.stdout || "wg set failed").trim());
  }

  info("peer added", { clientPublic, allowedIps: STATIC_CLIENT_ADDRESS });
}

function parseHandshakeOutput(text) {
  const map = new Map();
  const lines = String(text || "").trim().split(/\r?\n/).map(s => s.trim()).filter(Boolean);

  for (const line of lines) {
    const parts = line.split(/\s+/);
    if (parts.length >= 2) {
      map.set(parts[0], Number.parseInt(parts[1], 10) || 0);
    }
  }

  return map;
}

function refreshHandshake() {
  if (!WG_EXE) return 0;

  const r = run(WG_EXE, ["show", WG_TUNNEL_NAME, "latest-handshakes"]);
  const raw = r.stdout.trim();
  info("handshake check", raw ? raw : "(empty)");

  const map = parseHandshakeOutput(raw);
  const clientPublic = clientPublicKey();
  const hs = map.get(clientPublic) || 0;

  return hs;
}

function getStatus(host) {
  const handshakeUnix = refreshHandshake();
  const age = handshakeUnix
    ? Math.max(0, Math.floor(Date.now() / 1000) - handshakeUnix)
    : null;

  const connected = handshakeUnix > 0 && age !== null && age < 180;

  return {
    ok: true,
    host: normalizeHost(host),
    clientAddress: STATIC_CLIENT_ADDRESS,
    tunnelName: WG_TUNNEL_NAME,
    tunnelInstalled: tunnelInstalled(),
    tunnelRunning: tunnelRunning(),
    connected,
    handshakeUnix: handshakeUnix || null,
    handshakeAgeSeconds: age,
    serverPublicKey: serverPublicKey(),
    clientConfigUrl: "/api/client.conf",
    serverConfigUrl: "/api/server.conf"
  };
}

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

app.get("/api/boot", (req, res) => {
  res.json({
    ok: true,
    windows: process.platform === "win32",
    wgExeFound: Boolean(WG_EXE),
    wireguardExeFound: Boolean(WIREGUARD_EXE),
    autoStart: AUTO_START,
    serviceName: serviceName(),
    serverPublicKey: serverPublicKey()
  });
});

app.get("/api/status", (req, res) => {
  try {
    const host = getPageHost(req);
    res.json(getStatus(host));
  } catch (e) {
    err("status failed", e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.get("/api/client.conf", (req, res) => {
  const host = getPageHost(req);
  writeConfigs(host);
  const file = path.join(CONF_DIR, "client.conf");

  info("download client conf", { file });
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename="webtrust-client.conf"`);
  res.send(fs.readFileSync(file, "utf8"));
});

app.get("/api/server.conf", (req, res) => {
  const file = tunnelConfPath();
  fs.writeFileSync(file, buildServerConf(), "utf8");

  info("download server conf", { file });
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename="${WG_TUNNEL_NAME}.conf"`);
  res.send(fs.readFileSync(file, "utf8"));
});

app.post("/api/start-server", (req, res) => {
  try {
    ensureTunnelReady();
    addPeer();
    res.json({ ok: true, message: "Server started and peer added." });
  } catch (e) {
    err("start server failed", e.message);
    res.status(500).json({
      ok: false,
      error: e.message,
      hint: "Run as Administrator and forward UDP port 51820 to this machine."
    });
  }
});

app.post("/api/reload-peer", (req, res) => {
  try {
    addPeer();
    res.json({ ok: true, message: "Peer added to live tunnel." });
  } catch (e) {
    err("reload peer failed", e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.post("/api/start-pairing", async (req, res) => {
  try {
    const deviceIp = STATIC_CLIENT_ADDRESS.split('/')[0];
    info("Starting iOS public key extraction", { deviceIp });
    
    // Start extraction in background - create pairing session first
    const pairingId = randomId();
    pairingSessions.set(pairingId, {
      id: pairingId,
      status: "extracting",
      lockdown: null,
      startTime: Date.now(),
      debugLogs: []
    });
    
    // Check if device is reachable via VPN
    const lockdown = new SimpleLockdownClient(deviceIp, 62078, (logEntry) => {
      const pairingSession = pairingSessions.get(pairingId);
      if (pairingSession) {
        if (!pairingSession.debugLogs) pairingSession.debugLogs = [];
        pairingSession.debugLogs.push(logEntry);
      }
    });
    
    // Update pairing session with lockdown client
    const pairingSession = pairingSessions.get(pairingId);
    if (pairingSession) {
      pairingSession.lockdown = lockdown;
    }
    
    // Attempt to extract public key via TLS
    lockdown.getSessionAndExtractPublicKey()
      .then(result => {
        const pairingSession = pairingSessions.get(pairingId);
        if (pairingSession) {
          pairingSession.status = "success";
          pairingSession.result = result;
          info("Public key extraction successful", { pairingId });
        }
      })
      .catch(error => {
        const pairingSession = pairingSessions.get(pairingId);
        if (pairingSession) {
          pairingSession.status = "failed";
          pairingSession.error = error.message;
          err("Public key extraction failed", error.message);
        }
      });
    
    res.json({ 
      ok: true, 
      pairingId,
      message: "Public key extraction initiated. Connecting to iOS device via VPN..."
    });
  } catch (e) {
    err("start extraction failed", e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.get("/api/pairing/:id/status", (req, res) => {
  const pairing = pairingSessions.get(req.params.id);
  if (!pairing) return res.status(404).json({ ok: false, error: "Pairing session not found" });

  res.json({
    ok: true,
    pairingId: pairing.id,
    status: pairing.status,
    error: pairing.error || null,
    hasResult: !!pairing.result,
    result: pairing.result || null,
    debugLogs: pairing.debugLogs || []
  });
});

app.get("/api/pairing/:id/download", (req, res) => {
  const pairing = pairingSessions.get(req.params.id);
  if (!pairing) return res.status(404).json({ ok: false, error: "Pairing session not found" });
  if (!pairing.result) return res.status(400).json({ ok: false, error: "No public key result available" });

  const resultJson = JSON.stringify(pairing.result, null, 2);
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename="ios-public-key-${pairing.id}.json"`);
  res.send(resultJson);
});

app.get("/api/logs", (req, res) => {
  res.json({ ok: true, logs: logs.slice(-200) });
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

setInterval(() => {
  try {
    refreshHandshake();
  } catch (e) {
    warn("poll failed", e.message);
  }
}, 2000);

process.on("SIGINT", () => {
  info("shutting down");
  process.exit(0);
});

info("server starting", {
  port: PORT,
  wgExe: WG_EXE,
  wireguardExe: WIREGUARD_EXE,
  autoStart: AUTO_START,
  serverPublicKey: serverPublicKey()
});

app.listen(PORT, '0.0.0.0', () => {
  info(`listening on http://0.0.0.0:${PORT}`);
});