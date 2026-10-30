const express = require('express');
const http = require('http');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const multer = require('multer');
const { Server } = require('socket.io');

const { parseLine, parseLog } = require('./src/parser');
const { Detector } = require('./src/detector');
const { exportBlocklist, isValidIp } = require('./src/blocklist');
const { generate } = require('./src/sampleLog');
const db = require('./src/db');
const auth = require('./src/auth');

const PORT = process.env.PORT || 5000;
const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } });

app.use(cors());
app.use(express.json());

// Password protection for public deployments: set DASHBOARD_PASSWORD (and optionally DASHBOARD_USER)
const AUTH_USER = process.env.DASHBOARD_USER || 'admin';
const AUTH_PASS = process.env.DASHBOARD_PASSWORD;
if (AUTH_PASS) {
  app.use(auth.httpGuard(AUTH_USER, AUTH_PASS));
  io.use(auth.socketGuard(AUTH_USER, AUTH_PASS));
  console.log(`[auth] password protection ON (user: ${AUTH_USER})`);
} else {
  console.log('[auth] DASHBOARD_PASSWORD not set - dashboard is open. Fine locally, NOT for a public deployment.');
}

app.use(express.static(path.join(__dirname, 'public')));

// ---------- Session state (the dataset the dashboard is showing) ----------
let config = {};
let session;
function newSession(source) {
  session = {
    source,
    detector: new Detector(config),
    alerts: [],
    timeline: new Map(),   // minute ISO -> { requests, alerts }
    simulating: false
  };
}
newSession('(empty)');

const minuteKey = d => new Date(d).toISOString().slice(0, 16);
function bucket(key) {
  let b = session.timeline.get(key);
  if (!b) { b = { requests: 0, alerts: 0 }; session.timeline.set(key, b); }
  return b;
}

// Core ingest used by uploads, live API, file tail and simulator
function ingestEntry(entry, { live = false } = {}) {
  const newAlerts = session.detector.process(entry);
  bucket(minuteKey(entry.time)).requests++;
  for (const a of newAlerts) {
    bucket(minuteKey(a.time)).alerts++;
    session.alerts.push(a);
    if (session.alerts.length > 5000) session.alerts.shift();
    if (live) io.emit('alert', a);
  }
  return newAlerts;
}

async function buildState() {
  const decisions = await db.getDecisions();
  const decided = new Map(decisions.map(d => [d.ip, d.decision]));
  const byType = {}, bySeverity = {};
  for (const a of session.alerts) {
    byType[a.type] = (byType[a.type] || 0) + 1;
    bySeverity[a.severity] = (bySeverity[a.severity] || 0) + 1;
  }
  const ipRisk = session.detector.getIpRisk().map(r => ({ ...r, decision: decided.get(r.ip) || null }));
  const timeline = [...session.timeline.entries()].sort().map(([minute, v]) => ({ minute, ...v }));
  return {
    source: session.source,
    simulating: session.simulating,
    totals: { requests: session.detector.stats.total, alerts: session.alerts.length },
    statusClasses: session.detector.stats.byClass,
    byType, bySeverity, timeline,
    ipRisk: ipRisk.slice(0, 25),
    recentAlerts: session.alerts.slice(-100).reverse(),
    config: session.detector.config
  };
}

let broadcastTimer = null;
function scheduleBroadcast() {
  if (broadcastTimer) return;
  broadcastTimer = setTimeout(async () => {
    broadcastTimer = null;
    io.emit('state', await buildState());
  }, 500);
}

// ---------- API ----------
app.get('/api/state', async (req, res) => res.json(await buildState()));

app.post('/api/upload', upload.single('logfile'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded (field name: logfile)' });
  const { entries, skipped } = parseLog(req.file.buffer.toString('utf8'));
  if (!entries.length) return res.status(422).json({ error: 'No valid log lines found. Expected Apache/Nginx combined format.' });

  newSession(req.file.originalname);
  for (const e of entries) ingestEntry(e);
  try { await db.saveAnalysis(req.file.originalname, entries.length, session.alerts); }
  catch (err) { console.error('[db] save failed:', err.message); }

  const state = await buildState();
  io.emit('state', state);
  res.json({ parsed: entries.length, skipped, alerts: session.alerts.length });
});

// Live ingestion: POST {"lines": ["...", "..."]} or {"line": "..."}
app.post('/api/ingest', (req, res) => {
  const lines = req.body.lines || (req.body.line ? [req.body.line] : []);
  let n = 0;
  for (const l of lines) {
    const e = parseLine(String(l));
    if (e) { ingestEntry(e, { live: true }); n++; }
  }
  scheduleBroadcast();
  res.json({ ingested: n });
});

// Demo: stream simulated attack traffic through the live pipeline
app.post('/api/simulate', (req, res) => {
  if (session.simulating) return res.status(409).json({ error: 'Simulation already running' });
  newSession('Live simulation');
  session.simulating = true;
  // Shift generated timestamps so the whole scenario ends "now"
  const lines = generate(new Date(Date.now() - 10 * 60000));
  let i = 0;
  const timer = setInterval(() => {
    for (let k = 0; k < 5 && i < lines.length; k++, i++) {
      const e = parseLine(lines[i]);
      if (e) ingestEntry(e, { live: true });
    }
    scheduleBroadcast();
    if (i >= lines.length) {
      clearInterval(timer);
      session.simulating = false;
      db.saveAnalysis('Live simulation', session.detector.stats.total, session.alerts).catch(() => {});
      scheduleBroadcast();
    }
  }, 100);
  res.json({ started: true, lines: lines.length });
});

app.post('/api/reset', async (req, res) => {
  newSession('(empty)');
  io.emit('state', await buildState());
  res.json({ ok: true });
});

app.get('/api/config', (req, res) => res.json(session.detector.config));
app.put('/api/config', (req, res) => {
  const b = req.body || {};
  const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, Number(v) || lo));
  const patch = {};
  if (b.bruteForce) patch.bruteForce = { threshold: clamp(b.bruteForce.threshold, 2, 1000), windowSec: clamp(b.bruteForce.windowSec, 5, 3600) };
  if (b.recon404) patch.recon404 = { threshold: clamp(b.recon404.threshold, 2, 1000), windowSec: clamp(b.recon404.windowSec, 5, 3600) };
  if (b.riskBlockThreshold !== undefined) patch.riskBlockThreshold = clamp(b.riskBlockThreshold, 1, 100);
  session.detector.updateConfig(patch);
  config = JSON.parse(JSON.stringify(session.detector.config));
  res.json(session.detector.config);
});

app.post('/api/blocklist/:ip', async (req, res) => {
  const { ip } = req.params;
  const { decision } = req.body;
  if (!isValidIp(ip)) return res.status(400).json({ error: 'Invalid IP' });
  if (!['approved', 'rejected', 'clear'].includes(decision)) return res.status(400).json({ error: 'decision must be approved, rejected or clear' });
  if (decision === 'clear') {
    await db.clearDecision(ip);
  } else {
    const risk = session.detector.getIpRisk().find(r => r.ip === ip);
    await db.setDecision(ip, decision, risk ? risk.score : 0);
  }
  io.emit('state', await buildState());
  res.json({ ip, decision });
});

app.get('/api/blocklist/export', async (req, res) => {
  const format = ['nginx', 'htaccess', 'iptables', 'txt'].includes(req.query.format) ? req.query.format : 'txt';
  const approved = (await db.getDecisions()).filter(d => d.decision === 'approved').map(d => d.ip);
  res.type('text/plain').attachment(`blocklist-${format}.txt`).send(exportBlocklist(approved, format));
});

app.get('/api/alerts/export', (req, res) => {
  const esc = v => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const rows = ['time,ip,type,severity,detail,path,status'];
  for (const a of session.alerts) {
    rows.push([new Date(a.time).toISOString(), a.ip, a.type, a.severity, a.detail, a.path, a.status].map(esc).join(','));
  }
  res.type('text/csv').attachment('alerts.csv').send(rows.join('\n'));
});

app.get('/api/history', async (req, res) => {
  try { res.json(await db.getHistory(10)); }
  catch { res.status(500).json({ error: 'Database error' }); }
});

// ---------- Optional: tail a real log file (LOG_FILE=/var/log/nginx/access.log) ----------
function tailFile(file) {
  let pos = fs.statSync(file).size;
  let leftover = '';
  console.log(`[tail] watching ${file}`);
  fs.watchFile(file, { interval: 1000 }, (cur) => {
    if (cur.size < pos) pos = 0; // rotated
    if (cur.size === pos) return;
    const stream = fs.createReadStream(file, { start: pos, end: cur.size - 1, encoding: 'utf8' });
    pos = cur.size;
    let buf = leftover;
    stream.on('data', c => (buf += c));
    stream.on('end', () => {
      const parts = buf.split(/\r?\n/);
      leftover = parts.pop();
      for (const l of parts) { const e = parseLine(l); if (e) ingestEntry(e, { live: true }); }
      scheduleBroadcast();
    });
  });
}

io.on('connection', async (socket) => socket.emit('state', await buildState()));

(async () => {
  await db.init();
  if (process.env.LOG_FILE && fs.existsSync(process.env.LOG_FILE)) {
    newSession(process.env.LOG_FILE);
    tailFile(process.env.LOG_FILE);
  }
  server.listen(PORT, () => console.log(`Log Analyzer v2 running on http://localhost:${PORT}`));
})();

module.exports = { app, server };
