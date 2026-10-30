# Log Analyzer v2

Web-based security log analyzer. Evolution of my C# WinForms **ServerLogApp** into a real-time web platform.

Upload an Apache/Nginx access log (or tail a live one) and the engine detects attacks, scores each source IP, and suggests IPs to block. Alerts appear live on the dashboard through WebSockets.

## Features
- **Detection engine**: SQL injection, XSS, path traversal, brute force (sliding window), directory scanning (404 bursts), attack-tool user agents (sqlmap, nikto, ...). URL-encoded and double-encoded payloads are decoded before matching.
- **IP risk scoring** (0-100) with one-click Block / Ignore and export to **nginx, .htaccess, iptables** or plain list.
- **Live alerts** via Socket.io (toasts + feed), live charts (requests/alerts per minute, attack-type breakdown).
- **Configurable thresholds** from the dashboard.
- **MySQL (XAMPP)** persistence for analyses, alerts and blocklist decisions. Falls back to in-memory storage if MySQL is not running.
- **CSV export** of alerts, sample attack-log generator, unit tests.

## Run
```bash
npm install
# optional: import schema.sql into MySQL (phpMyAdmin or: mysql -u root < schema.sql)
npm run gen-logs        # creates samples/access.log with simulated attacks
npm start               # http://localhost:5000
npm test
```
Then click **Run live simulation** (live demo) or **Upload log file** and pick `samples/access.log`.

The dashboard is served by the Node server itself (public/index.html + public/app.js), so detection, MySQL history, live file tail and blocklist downloads are all connected. Open the page from http://localhost:5000, not from a saved .html file.

Tail a real log file live: `LOG_FILE=/var/log/nginx/access.log npm start`

DB settings via env: `DB_HOST`, `DB_USER`, `DB_PASS`, `DB_NAME` (defaults: localhost / root / empty / log_analyzer).

Send live lines from another process:
```bash
curl -X POST localhost:5000/api/ingest -H "Content-Type: application/json" \
     -d '{"line":"1.2.3.4 - - [30/Oct/2026:12:00:00 +0000] \"GET /?id=1%27%20OR%201=1-- HTTP/1.1\" 200 512 \"-\" \"curl\""}'
```

## Architecture
```
access.log / upload / POST /api/ingest / file tail
        -> parser.js -> detector.js (stateful rules + risk score)
        -> db.js (MySQL or memory)  -> Socket.io -> dashboard (Chart.js)
```

## Detection results on the bundled sample (412 requests, 5 attackers)
All 5 simulated attackers detected and suggested for blocking; 0 false positives on 20 normal users (see `tests/detector.test.js`).

## Known limitations / roadmap
- No login/JWT on the dashboard yet (should sit behind auth before exposing publicly).
- Rules are regex/threshold based, so they can be evaded and may false-positive; they are a triage aid, not a WAF.
- Next: JWT + roles, GeoIP map, email alerts, Docker, ML anomaly detection.

## Deploy (Render free plan)
1. Push this folder to a GitHub repository (`node_modules` is git-ignored).
2. render.com -> New -> Web Service -> pick the repo. Build command `npm install`, start command `npm start`, plan Free.
3. Environment variables (required for a public site):
   - `DASHBOARD_PASSWORD` = a long random password (turns on login; user name defaults to `admin`, change with `DASHBOARD_USER`)
   - optional MySQL: `DB_HOST`, `DB_USER`, `DB_PASS`, `DB_NAME` (without them the app uses in-memory storage)
4. Open the `onrender.com` URL, sign in, then use "Run live simulation".
