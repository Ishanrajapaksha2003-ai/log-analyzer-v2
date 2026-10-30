// Generates realistic access-log lines mixed with simulated attacks (for demos and tests).
const MON = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
const pad = n => String(n).padStart(2, '0');

function fmt(d) {
  return `${pad(d.getUTCDate())}/${MON[d.getUTCMonth()]}/${d.getUTCFullYear()}:` +
    `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} +0000`;
}
const line = (ip, d, method, path, status, ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)') =>
  `${ip} - - [${fmt(d)}] "${method} ${path} HTTP/1.1" ${status} ${Math.floor(200 + Math.random() * 5000)} "-" "${ua}"`;

const rnd = arr => arr[Math.floor(Math.random() * arr.length)];
const NORMAL_PATHS = ['/', '/index.php', '/products', '/about', '/contact', '/css/main.css', '/js/app.js', '/images/logo.png'];

// Returns an array of {line} in chronological order starting at `start`.
function generate(start = new Date(Date.now() - 10 * 60000)) {
  const out = [];
  let t = start.getTime();
  const at = off => new Date(t + off * 1000);

  // Normal traffic: ~300 requests from 20 users
  const users = Array.from({ length: 20 }, (_, i) => `192.168.1.${10 + i}`);
  for (let i = 0; i < 300; i++) {
    out.push([i * 2, line(rnd(users), at(i * 2), 'GET', rnd(NORMAL_PATHS), Math.random() < 0.95 ? 200 : 304)]);
  }

  // Brute force from 203.0.113.50 (40 failed logins in 40s)
  for (let i = 0; i < 40; i++) {
    out.push([100 + i, line('203.0.113.50', at(100 + i), 'POST', '/login', 401)]);
  }

  // SQL injection from 198.51.100.23
  const sqli = [
    "/products?id=1' OR 1=1--",
    '/products?id=1 UNION SELECT username,password FROM users',
    '/search?q=%27%20OR%20%271%27%3D%271',
    '/item?id=1;DROP TABLE users',
    '/page?id=1 AND sleep(5)',
    '/product?id=1 UNION ALL SELECT NULL,table_name FROM information_schema.tables'
  ];
  sqli.forEach((p, i) => out.push([200 + i * 3, line('198.51.100.23', at(200 + i * 3), 'GET', p.replace(/ /g, '%20'), 200)]));

  // XSS from 198.51.100.77
  ['/search?q=<script>alert(1)</script>', '/comment?text=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E', '/go?url=javascript:alert(1)']
    .forEach((p, i) => out.push([260 + i * 4, line('198.51.100.77', at(260 + i * 4), 'GET', p, 200)]));

  // Path traversal from 192.0.2.99
  ['/download?file=../../../../etc/passwd', '/view?page=..%2f..%2f..%2fetc%2fshadow', '/static/..\\..\\windows\\win.ini']
    .forEach((p, i) => out.push([300 + i * 2, line('192.0.2.99', at(300 + i * 2), 'GET', p, 404)]));

  // Directory scanner with sqlmap/nikto UA: 60 x 404 in 30s
  for (let i = 0; i < 60; i++) {
    out.push([350 + i * 0.5, line('203.0.113.200', at(350 + i * 0.5), 'GET', `/${rnd(['admin', 'backup', 'wp-admin', '.git', 'phpmyadmin', 'config', 'old'])}${i}`, 404, 'Nikto/2.1.6')]);
  }

  out.sort((a, b) => a[0] - b[0]);
  return out.map(x => x[1]);
}

module.exports = { generate };
