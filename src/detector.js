// Stateful detection engine. Same instance can process a batch (uploaded file)
// or a live stream (one entry at a time) - the logic is identical.

const DEFAULT_CONFIG = {
  bruteForce: { enabled: true, threshold: 10, windowSec: 60 },   // failed auth responses per IP
  recon404: { enabled: true, threshold: 15, windowSec: 60 },     // many 404s = directory scanning
  sqli: { enabled: true },
  xss: { enabled: true },
  pathTraversal: { enabled: true },
  scannerUA: { enabled: true },
  riskBlockThreshold: 50                                          // score at which an IP is suggested for blocking
};

const SEVERITY_WEIGHT = { low: 5, medium: 15, high: 30, critical: 50 };

const SQLI_PATTERNS = [
  /union(\s|\/\*.*?\*\/)+(all(\s)+)?select/i,
  /(\'|\")\s*(or|and)\s+[\w'"]+\s*=\s*[\w'"]+/i,
  /(\'|\")\s*or\s+1\s*=\s*1/i,
  /;\s*(drop|alter|truncate|delete)\s+(table|database)/i,
  /\b(sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(/i,
  /information_schema/i,
  /(\'|\")\s*(--|#)/,
  /\bselect\b.+\bfrom\b/i,
  /load_file\s*\(|into\s+outfile/i
];

const XSS_PATTERNS = [
  /<\s*script/i,
  /on(error|load|click|mouseover)\s*=/i,
  /javascript\s*:/i,
  /<\s*(img|svg|iframe)[^>]*(src|onload|onerror)/i,
  /document\.(cookie|location)/i
];

const TRAVERSAL_PATTERNS = [
  /\.\.[\/\\]/,
  /(\/|\\)etc(\/|\\)(passwd|shadow)/i,
  /boot\.ini|win\.ini/i,
  /\/proc\/self\//i
];

const SCANNER_UA = /(sqlmap|nikto|nmap|masscan|acunetix|nessus|wpscan|dirbuster|gobuster|havij|burp|zgrab|hydra)/i;
const LOGIN_PATH = /(login|signin|sign-in|auth|admin|wp-login|session)/i;

class Detector {
  constructor(config = {}) {
    this.config = JSON.parse(JSON.stringify(DEFAULT_CONFIG));
    this.updateConfig(config);
    this.reset();
  }

  updateConfig(cfg) {
    for (const k of Object.keys(cfg || {})) {
      if (typeof this.config[k] === 'object' && typeof cfg[k] === 'object') {
        Object.assign(this.config[k], cfg[k]);
      } else if (k in this.config) {
        this.config[k] = cfg[k];
      }
    }
  }

  reset() {
    this.windows = new Map();   // key "ip|rule" -> array of epoch ms
    this.lastFired = new Map(); // key "ip|rule" -> epoch ms
    this.ipStats = new Map();   // ip -> { requests, alerts, score, types:Set, firstSeen, lastSeen }
    this.stats = { total: 0, byStatus: {}, byClass: {} };
  }

  _ip(ip, time) {
    let s = this.ipStats.get(ip);
    if (!s) {
      s = { ip, requests: 0, alerts: 0, score: 0, types: new Set(), firstSeen: time, lastSeen: time };
      this.ipStats.set(ip, s);
    }
    s.lastSeen = time;
    return s;
  }

  _slide(ip, rule, t, windowSec) {
    const key = `${ip}|${rule}`;
    let arr = this.windows.get(key);
    if (!arr) { arr = []; this.windows.set(key, arr); }
    arr.push(t);
    const cutoff = t - windowSec * 1000;
    while (arr.length && arr[0] < cutoff) arr.shift();
    return arr.length;
  }

  _canFire(ip, rule, t, windowSec) {
    const key = `${ip}|${rule}`;
    const last = this.lastFired.get(key);
    if (last && t - last < windowSec * 1000) return false;
    this.lastFired.set(key, t);
    return true;
  }

  _alert(entry, type, severity, detail) {
    const s = this._ip(entry.ip, entry.time);
    s.alerts++;
    s.types.add(type);
    s.score += SEVERITY_WEIGHT[severity];
    return {
      time: entry.time,
      ip: entry.ip,
      type,
      severity,
      detail,
      path: entry.decodedPath.slice(0, 300),
      status: entry.status,
      userAgent: entry.userAgent.slice(0, 200)
    };
  }

  // Process one parsed entry. Returns array of alerts triggered by it.
  process(entry) {
    const alerts = [];
    const c = this.config;
    const t = entry.time.getTime();
    const ipStat = this._ip(entry.ip, entry.time);
    ipStat.requests++;

    this.stats.total++;
    this.stats.byStatus[entry.status] = (this.stats.byStatus[entry.status] || 0) + 1;
    const cls = `${Math.floor(entry.status / 100)}xx`;
    this.stats.byClass[cls] = (this.stats.byClass[cls] || 0) + 1;

    const target = entry.decodedPath;

    // --- Payload based rules: one alert per matching request ---
    if (c.sqli.enabled && SQLI_PATTERNS.some(p => p.test(target))) {
      alerts.push(this._alert(entry, 'SQL Injection', 'critical', 'SQL syntax pattern in request'));
    }
    if (c.xss.enabled && XSS_PATTERNS.some(p => p.test(target))) {
      alerts.push(this._alert(entry, 'XSS', 'high', 'Script/HTML injection pattern in request'));
    }
    if (c.pathTraversal.enabled && TRAVERSAL_PATTERNS.some(p => p.test(target))) {
      alerts.push(this._alert(entry, 'Path Traversal', 'high', 'Directory traversal / sensitive file access attempt'));
    }
    if (c.scannerUA.enabled && SCANNER_UA.test(entry.userAgent)) {
      if (this._canFire(entry.ip, 'scannerUA', t, 300)) {
        const m = entry.userAgent.match(SCANNER_UA)[1].toLowerCase();
        alerts.push(this._alert(entry, 'Scanner Tool', 'medium', `Known attack tool user-agent: ${m}`));
      }
    }

    // --- Rate based rules: sliding window per IP ---
    const failedAuth =
      (entry.status === 401 || entry.status === 403) ||
      (entry.method === 'POST' && LOGIN_PATH.test(entry.path) && entry.status >= 400 && entry.status < 500);
    if (c.bruteForce.enabled && failedAuth) {
      const n = this._slide(entry.ip, 'bruteForce', t, c.bruteForce.windowSec);
      if (n >= c.bruteForce.threshold && this._canFire(entry.ip, 'bruteForce', t, c.bruteForce.windowSec)) {
        alerts.push(this._alert(entry, 'Brute Force', 'high',
          `${n} failed auth responses within ${c.bruteForce.windowSec}s`));
      } else if (n > c.bruteForce.threshold) {
        ipStat.score += 1; // sustained attack keeps raising the risk score
      }
    }
    if (c.recon404.enabled && entry.status === 404) {
      const n = this._slide(entry.ip, 'recon404', t, c.recon404.windowSec);
      if (n >= c.recon404.threshold && this._canFire(entry.ip, 'recon404', t, c.recon404.windowSec)) {
        alerts.push(this._alert(entry, 'Directory Scanning', 'medium',
          `${n} x 404 responses within ${c.recon404.windowSec}s`));
      } else if (n > c.recon404.threshold) {
        ipStat.score += 1;
      }
    }

    return alerts;
  }

  processAll(entries) {
    const alerts = [];
    for (const e of entries) alerts.push(...this.process(e));
    return alerts;
  }

  // IPs with risk scores, highest first. "suggestBlock" when over threshold.
  getIpRisk() {
    return [...this.ipStats.values()]
      .filter(s => s.alerts > 0)
      .map(s => ({
        ip: s.ip,
        requests: s.requests,
        alerts: s.alerts,
        score: Math.min(100, s.score),
        types: [...s.types],
        firstSeen: s.firstSeen,
        lastSeen: s.lastSeen,
        suggestBlock: Math.min(100, s.score) >= this.config.riskBlockThreshold
      }))
      .sort((a, b) => b.score - a.score);
  }
}

module.exports = { Detector, DEFAULT_CONFIG };
