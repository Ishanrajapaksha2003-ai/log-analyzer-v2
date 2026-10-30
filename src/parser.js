// Parses Apache / Nginx "combined" access log lines.
// Example:
// 192.168.1.5 - - [30/Oct/2026:12:33:01 +0530] "GET /index.php?id=1 HTTP/1.1" 200 1234 "-" "Mozilla/5.0"

const LINE_RE =
  /^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+)\s+(.*?)\s+(HTTP\/[\d.]+)" (\d{3}) (\d+|-)(?: "([^"]*)" "([^"]*)")?/;

const MONTHS = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };

function parseTimestamp(raw) {
  // 30/Oct/2026:12:33:01 +0530
  const m = raw.match(/^(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})$/);
  if (!m) return null;
  const [, d, mon, y, hh, mm, ss, sign, oh, om] = m;
  const utc = Date.UTC(+y, MONTHS[mon], +d, +hh, +mm, +ss);
  const offsetMin = (sign === '-' ? -1 : 1) * (+oh * 60 + +om);
  return new Date(utc - offsetMin * 60000);
}

function safeDecode(s) {
  let out = s;
  // decode up to twice to catch double-encoded payloads
  for (let i = 0; i < 2; i++) {
    try {
      const d = decodeURIComponent(out.replace(/\+/g, ' '));
      if (d === out) break;
      out = d;
    } catch {
      break;
    }
  }
  return out;
}

function parseLine(line) {
  const m = LINE_RE.exec(line.trim());
  if (!m) return null;
  const time = parseTimestamp(m[2]);
  if (!time) return null;
  return {
    ip: m[1],
    time,
    method: m[3],
    path: m[4],
    decodedPath: safeDecode(m[4]),
    status: parseInt(m[6], 10),
    bytes: m[7] === '-' ? 0 : parseInt(m[7], 10),
    referer: m[8] || '-',
    userAgent: m[9] || '-',
    raw: line.trim()
  };
}

function parseLog(text) {
  const entries = [];
  let skipped = 0;
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim()) continue;
    const e = parseLine(line);
    if (e) entries.push(e);
    else skipped++;
  }
  entries.sort((a, b) => a.time - b.time);
  return { entries, skipped };
}

module.exports = { parseLine, parseLog };
