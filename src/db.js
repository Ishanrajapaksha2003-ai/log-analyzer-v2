// Storage layer. Uses MySQL (XAMPP) when reachable, otherwise falls back to memory
// so the app always runs for demos.
const mysql = require('mysql2/promise');

let pool = null;
const mem = { analyses: [], alerts: [], blocklist: new Map(), nextId: 1 };

async function init() {
  try {
    const p = mysql.createPool({
      host: process.env.DB_HOST || 'localhost',
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASS || '',
      database: process.env.DB_NAME || 'log_analyzer',
      connectTimeout: 3000
    });
    await p.query('SELECT 1');
    pool = p;
    console.log('[db] MySQL connected');
  } catch (e) {
    console.log(`[db] MySQL unavailable (${e.code || e.message}) - using in-memory storage`);
  }
  return !!pool;
}

const toSql = d => new Date(d).toISOString().slice(0, 19).replace('T', ' ');

async function saveAnalysis(source, totalRequests, alerts) {
  if (pool) {
    const [r] = await pool.query(
      'INSERT INTO analyses (source, total_requests, total_alerts) VALUES (?,?,?)',
      [source, totalRequests, alerts.length]);
    const id = r.insertId;
    if (alerts.length) {
      const rows = alerts.map(a => [id, toSql(a.time), a.ip, a.type, a.severity,
        a.detail, a.path, a.status, a.userAgent]);
      await pool.query(
        'INSERT INTO alerts (analysis_id,event_time,ip,type,severity,detail,path,status_code,user_agent) VALUES ?',
        [rows]);
    }
    return id;
  }
  const id = mem.nextId++;
  mem.analyses.unshift({ id, source, total_requests: totalRequests, total_alerts: alerts.length, created_at: new Date() });
  alerts.forEach(a => mem.alerts.push({ ...a, analysis_id: id }));
  return id;
}

async function getHistory(limit = 10) {
  if (pool) {
    const [rows] = await pool.query('SELECT * FROM analyses ORDER BY id DESC LIMIT ?', [limit]);
    return rows;
  }
  return mem.analyses.slice(0, limit);
}

async function setDecision(ip, decision, score = 0) {
  if (pool) {
    await pool.query(
      `INSERT INTO blocklist (ip, decision, risk_score) VALUES (?,?,?)
       ON DUPLICATE KEY UPDATE decision=VALUES(decision), risk_score=VALUES(risk_score)`,
      [ip, decision, score]);
  } else {
    mem.blocklist.set(ip, { ip, decision, risk_score: score });
  }
}

async function clearDecision(ip) {
  if (pool) await pool.query('DELETE FROM blocklist WHERE ip = ?', [ip]);
  else mem.blocklist.delete(ip);
}

async function getDecisions() {
  if (pool) {
    const [rows] = await pool.query('SELECT ip, decision, risk_score FROM blocklist');
    return rows;
  }
  return [...mem.blocklist.values()];
}

module.exports = { init, saveAnalysis, getHistory, setDecision, clearDecision, getDecisions };
