// Connected dashboard: detection runs on the Node server, this page only renders.
// Data arrives over Socket.io ('state', 'alert') and REST (/api/...).
const $ = id => document.getElementById(id);
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const SEV_VAR = { critical: 'var(--crit)', high: 'var(--high)', medium: 'var(--med)', low: 'var(--low)' };
const TYPE_VAR = { 'SQL Injection': 'var(--crit)', 'XSS': 'var(--high)', 'Path Traversal': 'var(--med)', 'Brute Force': 'var(--accent)', 'Directory Scanning': 'var(--low)', 'Scanner Tool': 'var(--muted)' };

let last = null; // latest state from the server

// ---------- socket ----------
const socket = io();
socket.on('connect', () => setConn(true));
socket.on('disconnect', () => setConn(false));
socket.on('state', s => { last = s; render(s); });
socket.on('alert', toast);

function setConn(on) {
  const t = $('connTag');
  t.textContent = on ? 'server connected' : 'server offline';
  t.className = 'tag' + (on ? ' live' : '');
}

function toast(a) {
  const el = document.createElement('div');
  el.className = 'toast';
  el.style.borderLeftColor = SEV_VAR[a.severity] || 'var(--crit)';
  el.innerHTML = '<b>' + esc(a.type) + '</b> from <span class="mono">' + esc(a.ip) + '</span><br><span class="muted">' + esc(a.detail) + '</span>';
  const box = $('toasts'); box.prepend(el);
  while (box.children.length > 3) box.lastChild.remove();
  setTimeout(() => el.remove(), 4500);
}

// ---------- rendering ----------
function bars(values, labels, colorVar) {
  const W = 720, H = 84, L = 8, R = 8, T = 6, B = 16;
  const max = Math.max(1, ...values);
  const n = values.length || 1, slot = (W - L - R) / n, bw = Math.max(2, Math.min(34, slot * 0.7));
  let g = '';
  [0, 0.5, 1].forEach(f => { const y = T + (H - T - B) * (1 - f); g += '<line class="grid-line" x1="' + L + '" x2="' + (W - R) + '" y1="' + y + '" y2="' + y + '"/>'; });
  values.forEach((v, i) => {
    const h = (H - T - B) * v / max, x = L + slot * i + (slot - bw) / 2;
    if (v > 0) g += '<rect x="' + x.toFixed(1) + '" y="' + (H - B - h).toFixed(1) + '" width="' + bw.toFixed(1) + '" height="' + h.toFixed(1) + '" fill="' + colorVar + '" rx="1"/>';
    if (n <= 14 || i % Math.ceil(n / 12) === 0) g += '<text x="' + (x + bw / 2).toFixed(1) + '" y="' + (H - 3) + '" text-anchor="middle">' + esc(labels[i]) + '</text>';
  });
  return '<svg viewBox="0 0 ' + W + ' ' + H + '" role="img" aria-label="Bar chart">' + g + '</svg>';
}

function approvedIps(s) { return s.ipRisk.filter(r => r.decision === 'approved').map(r => r.ip); }

function exportText(ips, fmt) {
  const ok = ip => /^(\d{1,3}\.){3}\d{1,3}$/.test(ip) ? ip.split('.').every(n => +n <= 255) : (ip.includes(':') && /^[0-9a-fA-F:]+$/.test(ip));
  const l = ips.filter(ok);
  if (!l.length) return '';
  if (fmt === 'nginx') return l.map(i => 'deny ' + i + ';').join('\n');
  if (fmt === 'htaccess') return 'Order Allow,Deny\nAllow from all\n' + l.map(i => 'Deny from ' + i).join('\n');
  if (fmt === 'iptables') return l.map(i => 'iptables -A INPUT -s ' + i + ' -j DROP').join('\n');
  return l.join('\n');
}

function render(s) {
  $('srcName').textContent = s.source;
  const tag = $('srcTag');
  tag.textContent = s.simulating ? 'streaming' : 'from server';
  tag.className = 'tag' + (s.simulating ? ' live' : '');
  $('btnSim').disabled = s.simulating;

  const open = s.ipRisk.filter(r => r.suggestBlock && !r.decision).length;
  $('kReq').textContent = s.totals.requests.toLocaleString();
  $('kAlerts').textContent = s.totals.alerts.toLocaleString();
  $('kCrit').textContent = s.bySeverity.critical || 0;
  $('kIps').textContent = s.ipRisk.length;
  $('kBlock').textContent = open;

  // timeline: server sends sparse minutes, fill gaps so the axis is honest
  const tl = new Map(s.timeline.map(t => [t.minute, t]));
  const keys = s.timeline.map(t => t.minute);
  if (keys.length) {
    const start = Date.parse(keys[0] + ':00Z'), end = Date.parse(keys[keys.length - 1] + ':00Z');
    const mins = []; for (let t = start; t <= end && mins.length < 240; t += 60000) mins.push(new Date(t).toISOString().slice(0, 16));
    const labels = mins.map(k => k.slice(11));
    const rv = mins.map(k => (tl.get(k) || {}).requests || 0), av = mins.map(k => (tl.get(k) || {}).alerts || 0);
    $('chartReq').innerHTML = bars(rv, labels, 'var(--accent)');
    $('chartAlt').innerHTML = bars(av, labels, 'var(--crit)');
    $('reqMax').textContent = 'peak ' + Math.max(...rv) + ' / min';
    $('altMax').textContent = 'peak ' + Math.max(...av) + ' / min';
  } else {
    $('chartReq').innerHTML = $('chartAlt').innerHTML = '<div class="empty">No data yet. Upload a log or run the simulation.</div>';
    $('reqMax').textContent = $('altMax').textContent = '';
  }

  const types = Object.entries(s.byType).sort((a, b) => b[1] - a[1]), tmax = types.length ? types[0][1] : 1;
  $('types').innerHTML = types.length ? types.map(([t, n]) =>
    '<div class="type-row"><span>' + esc(t) + '</span><div class="bar"><i style="width:' + (n / tmax * 100) + '%;background:' + (TYPE_VAR[t] || 'var(--muted)') + '"></i></div><b>' + n + '</b></div>').join('')
    : '<div class="empty">No attacks detected</div>';

  $('ipNote').textContent = open ? open + ' awaiting a decision' : '';
  $('ipBody').innerHTML = s.ipRisk.length ? s.ipRisk.map(r => {
    const col = r.score >= 75 ? 'var(--crit)' : r.score >= 50 ? 'var(--high)' : 'var(--med)';
    const ip = esc(r.ip);
    let act;
    if (r.decision === 'approved') act = '<span class="state-b">Blocked</span> <button class="sm" data-ip="' + ip + '" data-d="clear">Undo</button>';
    else if (r.decision === 'rejected') act = '<span class="state-i">Ignored</span> <button class="sm" data-ip="' + ip + '" data-d="clear">Undo</button>';
    else if (r.suggestBlock) act = '<div class="row-actions"><button class="sm danger" data-ip="' + ip + '" data-d="approved">Block</button><button class="sm" data-ip="' + ip + '" data-d="rejected">Ignore</button></div>';
    else act = '<span class="state-i">Watching</span>';
    return '<tr><td class="mono">' + ip + '</td><td><div class="risk"><div class="bar"><i style="width:' + r.score + '%;background:' + col + '"></i></div><b>' + r.score + '</b></div></td>' +
      '<td class="muted">' + esc(r.types.join(', ')) + '</td><td>' + act + '</td></tr>';
  }).join('') : '<tr><td colspan="4" class="empty">No suspicious IPs</td></tr>';

  $('feedNote').textContent = s.totals.alerts > s.recentAlerts.length ? 'latest ' + s.recentAlerts.length + ' of ' + s.totals.alerts : '';
  $('feedBody').innerHTML = s.recentAlerts.length ? s.recentAlerts.map(a =>
    '<tr><td class="mono muted">' + esc(new Date(a.time).toISOString().slice(11, 19)) + '</td><td class="mono">' + esc(a.ip) + '</td><td><span class="sev ' + esc(a.severity) + '">' + esc(a.type) + '</span></td><td class="mono muted">' + esc(a.path) + '</td></tr>').join('')
    : '<tr><td colspan="4" class="empty">No alerts</td></tr>';

  const ips = approvedIps(s);
  $('expOut').value = exportText(ips, $('fmt').value);
  $('expNote').textContent = ips.length + ' IP' + (ips.length === 1 ? '' : 's');
  $('btnCopyBlock').disabled = $('btnDownload').disabled = !ips.length;

  const c = s.config;
  for (const [id, v] of [['bfT', c.bruteForce.threshold], ['bfW', c.bruteForce.windowSec], ['rcT', c.recon404.threshold], ['rcW', c.recon404.windowSec], ['riskT', c.riskBlockThreshold]]) {
    if (document.activeElement.id !== id) $(id).value = v;
  }
}

async function loadHistory() {
  try {
    const rows = await (await fetch('/api/history')).json();
    $('histBody').innerHTML = rows.length ? rows.map(r =>
      '<tr><td>' + esc(new Date(r.created_at).toLocaleString()) + '</td><td>' + esc(r.source) + '</td><td class="num">' + esc(r.total_requests) + '</td><td class="num">' + esc(r.total_alerts) + '</td></tr>').join('')
      : '<tr><td colspan="4" class="empty">No saved analyses yet</td></tr>';
  } catch (e) { /* server offline */ }
}

// ---------- actions ----------
async function uploadText(text, name) {
  const fd = new FormData();
  fd.append('logfile', new Blob([text], { type: 'text/plain' }), name);
  const r = await fetch('/api/upload', { method: 'POST', body: fd });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || 'Upload failed');
  loadHistory();
  return j;
}

$('btnUpload').onclick = () => $('fileIn').click();
$('fileIn').onchange = async ev => {
  const f = ev.target.files[0]; if (!f) return;
  try { await uploadText(await f.text(), f.name); }
  catch (e) { $('pasteBox').hidden = false; $('pasteMsg').textContent = e.message; }
  ev.target.value = '';
};
$('btnPaste').onclick = () => { $('pasteBox').hidden = !$('pasteBox').hidden; $('pasteMsg').textContent = ''; if (!$('pasteBox').hidden) $('pasteArea').focus(); };
$('btnClosePaste').onclick = () => { $('pasteBox').hidden = true; };
$('btnAnalyzePaste').onclick = async () => {
  try { await uploadText($('pasteArea').value, 'Pasted log'); $('pasteBox').hidden = true; }
  catch (e) { $('pasteMsg').textContent = e.message; }
};
$('btnSim').onclick = async () => { const r = await fetch('/api/simulate', { method: 'POST' }); if (!r.ok) alert_msg((await r.json()).error); };
$('btnReset').onclick = () => fetch('/api/reset', { method: 'POST' });
function alert_msg(m) { $('pasteBox').hidden = false; $('pasteMsg').textContent = m; }

$('ipBody').addEventListener('click', e => {
  const b = e.target.closest('button[data-ip]'); if (!b) return;
  fetch('/api/blocklist/' + encodeURIComponent(b.dataset.ip), {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ decision: b.dataset.d }) });
});
$('fmt').onchange = () => last && render(last);
$('btnDownload').onclick = () => { location.href = '/api/blocklist/export?format=' + encodeURIComponent($('fmt').value); };
$('btnCsv').onclick = () => { location.href = '/api/alerts/export'; };
$('btnCopyBlock').onclick = async () => {
  try { await navigator.clipboard.writeText($('expOut').value); $('copyMsg').textContent = 'Blocklist copied.'; }
  catch (e) { $('expOut').select(); $('copyMsg').textContent = 'Clipboard blocked. The text is selected: press Ctrl+C.'; }
};
$('btnApply').onclick = async () => {
  const n = id => +$(id).value;
  await fetch('/api/config', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({
    bruteForce: { threshold: n('bfT'), windowSec: n('bfW') }, recon404: { threshold: n('rcT'), windowSec: n('rcW') }, riskBlockThreshold: n('riskT') }) });
  $('cfgMsg').textContent = 'Saved. Applies to the next log you analyze or stream.';
};

loadHistory(); setInterval(loadHistory, 15000);
