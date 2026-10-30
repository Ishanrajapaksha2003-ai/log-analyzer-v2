const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { parseLine, parseLog } = require('../src/parser');
const { Detector } = require('../src/detector');
const { exportBlocklist, isValidIp } = require('../src/blocklist');

const L = (ip, sec, method, p, status, ua = 'Mozilla/5.0') =>
  `${ip} - - [30/Oct/2026:12:${String(Math.floor(sec / 60)).padStart(2, '0')}:${String(sec % 60).padStart(2, '0')} +0000] "${method} ${p} HTTP/1.1" ${status} 512 "-" "${ua}"`;

function run(lines, cfg) {
  const d = new Detector(cfg);
  const alerts = lines.map(parseLine).filter(Boolean).flatMap(e => d.process(e));
  return { d, alerts };
}

test('parser reads combined log format', () => {
  const e = parseLine(L('1.2.3.4', 5, 'GET', '/a?x=1', 200));
  assert.strictEqual(e.ip, '1.2.3.4');
  assert.strictEqual(e.method, 'GET');
  assert.strictEqual(e.status, 200);
  assert.ok(e.time instanceof Date);
});

test('parser skips garbage lines', () => {
  const { entries, skipped } = parseLog('not a log line\n' + L('1.1.1.1', 1, 'GET', '/', 200));
  assert.strictEqual(entries.length, 1);
  assert.strictEqual(skipped, 1);
});

test('normal traffic raises no alerts', () => {
  const lines = Array.from({ length: 50 }, (_, i) => L('10.0.0.1', i, 'GET', '/index.php', 200));
  assert.strictEqual(run(lines).alerts.length, 0);
});

test('detects SQL injection incl. URL-encoded and double-encoded', () => {
  const { alerts } = run([
    L('9.9.9.9', 1, 'GET', "/p?id=1'%20OR%201=1--", 200),
    L('9.9.9.9', 2, 'GET', '/p?id=1%20UNION%20SELECT%20user,pass%20FROM%20users', 200),
    L('9.9.9.9', 3, 'GET', '/p?q=%2527%2520OR%25201%253D1--', 200)
  ]);
  assert.strictEqual(alerts.filter(a => a.type === 'SQL Injection').length, 3);
});

test('detects XSS and path traversal', () => {
  const { alerts } = run([
    L('8.8.8.8', 1, 'GET', '/s?q=<script>alert(1)</script>', 200),
    L('8.8.8.8', 2, 'GET', '/d?f=../../../../etc/passwd', 404),
    L('8.8.8.8', 3, 'GET', '/d?f=..%2f..%2fetc%2fshadow', 404)
  ]);
  assert.strictEqual(alerts.filter(a => a.type === 'XSS').length, 1);
  assert.strictEqual(alerts.filter(a => a.type === 'Path Traversal').length, 2);
});

test('brute force fires once at the threshold, not before', () => {
  const lines = Array.from({ length: 9 }, (_, i) => L('7.7.7.7', i, 'POST', '/login', 401));
  assert.strictEqual(run(lines).alerts.length, 0);
  const more = Array.from({ length: 30 }, (_, i) => L('7.7.7.7', i, 'POST', '/login', 401));
  const { alerts } = run(more);
  assert.strictEqual(alerts.filter(a => a.type === 'Brute Force').length, 1);
});

test('failures spread beyond the window do not trigger brute force', () => {
  const lines = Array.from({ length: 20 }, (_, i) => L('6.6.6.6', i * 30 % 3600, 'POST', '/login', 401));
  lines.sort(); // 30s apart -> never 10 inside 60s
  assert.strictEqual(run(lines).alerts.filter(a => a.type === 'Brute Force').length, 0);
});

test('scanner user agent and 404 scanning detected', () => {
  const lines = Array.from({ length: 20 }, (_, i) => L('5.5.5.5', i, 'GET', `/x${i}`, 404, 'sqlmap/1.7'));
  const { alerts } = run(lines);
  assert.ok(alerts.some(a => a.type === 'Scanner Tool'));
  assert.ok(alerts.some(a => a.type === 'Directory Scanning'));
});

test('risk scoring suggests blocking attackers only', () => {
  const lines = [
    ...Array.from({ length: 20 }, (_, i) => L('10.0.0.5', i, 'GET', '/', 200)),
    L('4.4.4.4', 1, 'GET', "/p?id=1' OR 1=1--", 200),
    L('4.4.4.4', 2, 'GET', '/p?id=1 UNION SELECT 1,2', 200)
  ];
  const { d } = run(lines);
  const risk = d.getIpRisk();
  assert.strictEqual(risk.length, 1);
  assert.strictEqual(risk[0].ip, '4.4.4.4');
  assert.ok(risk[0].suggestBlock);
});

test('configurable thresholds are honoured', () => {
  const lines = Array.from({ length: 5 }, (_, i) => L('3.3.3.3', i, 'POST', '/login', 401));
  const { alerts } = run(lines, { bruteForce: { threshold: 5 } });
  assert.strictEqual(alerts.filter(a => a.type === 'Brute Force').length, 1);
});

test('blocklist export validates IPs and formats', () => {
  assert.ok(isValidIp('203.0.113.50'));
  assert.ok(!isValidIp('999.1.1.1'));
  assert.ok(!isValidIp('1.1.1.1; rm -rf /'));
  assert.strictEqual(exportBlocklist(['1.2.3.4', 'evil;rm'], 'nginx'), 'deny 1.2.3.4;\n');
  assert.match(exportBlocklist(['1.2.3.4'], 'iptables'), /iptables -A INPUT -s 1\.2\.3\.4 -j DROP/);
});

test('full sample log: each simulated attacker is caught, no normal user flagged', () => {
  const file = path.join(__dirname, '..', 'samples', 'access.log');
  const { entries } = parseLog(fs.readFileSync(file, 'utf8'));
  const d = new Detector();
  d.processAll(entries);
  const byIp = Object.fromEntries(d.getIpRisk().map(r => [r.ip, r]));
  assert.ok(byIp['203.0.113.50'].types.includes('Brute Force'));
  assert.ok(byIp['198.51.100.23'].types.includes('SQL Injection'));
  assert.ok(byIp['198.51.100.77'].types.includes('XSS'));
  assert.ok(byIp['192.0.2.99'].types.includes('Path Traversal'));
  assert.ok(byIp['203.0.113.200'].types.includes('Directory Scanning'));
  assert.ok(!Object.keys(byIp).some(ip => ip.startsWith('192.168.1.')), 'normal users must not be flagged');
});
