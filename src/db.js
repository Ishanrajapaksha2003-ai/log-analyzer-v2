// Storage layer (PostgreSQL). If no database is configured or reachable, the app falls back
// to in-memory storage so it always runs for demos.
//
// Configure with DATABASE_URL (Neon / Supabase connection string) or DB_HOST, DB_PORT, DB_USER, DB_PASS, DB_NAME.
const { Pool } = require('pg');

let pool = null;
const mem = { analyses: [], alerts: [], blocklist: new Map(), nextId: 1 };

function poolConfig() {
  const url = process.env.DATABASE_URL;
  // Hosted databases need an encrypted connection. Set DB_SSL=false for a local database.
  const useSsl = process.env.DB_SSL === 'false' ? false : !!url || process.env.DB_SSL === 'true';
  const base = url
    ? { connectionString: url }
    : {
        host: process.env.DB_HOST,
        port: parseInt(process.env.DB_PORT || '5432', 10),
        user: process.env.DB_USER || 'postgres',
        password: process.env.DB_PASS || '',
        database: process.env.DB_NAME || 'log_analyzer'
      };
  return { ...base, ssl: useSsl ? { rejectUnauthorized: true } : undefined, connectionTimeoutMillis: 10000, max: 5 };
}

async function ensureSchema(p) {
  await p.query(`CREATE TABLE IF NOT EXISTS analyses (
    id SERIAL PRIMARY KEY,
    source VARCHAR(255) NOT NULL,
    total_requests INT NOT NULL,
    total_alerts INT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )`);
  await p.query(`CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    analysis_id INT REFERENCES analyses(id) ON DELETE CASCADE,
    event_time TIMESTAMPTZ NOT NULL,
    ip VARCHAR(45) NOT NULL,
    type VARCHAR(40) NOT NULL,
    severity VARCHAR(10) NOT NULL CHECK (severity IN ('low','medium','high','critical')),
    detail VARCHAR(255),
    path VARCHAR(400),
    status_code SMALLINT,
    user_agent VARCHAR(255)
  )`);
  await p.query('CREATE INDEX IF NOT EXISTS idx_alerts_ip ON alerts (ip)');
  await p.query('CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts (type)');
  await p.query('CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts (event_time)');
  await p.query('CREATE INDEX IF NOT EXISTS idx_alerts_analysis ON alerts (analysis_id)');
  await p.query(`CREATE TABLE IF NOT EXISTS blocklist (
    ip VARCHAR(45) PRIMARY KEY,
    decision VARCHAR(10) NOT NULL CHECK (decision IN ('approved','rejected')),
    risk_score SMALLINT NOT NULL DEFAULT 0,
    decided_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )`);
}

async function init() {
  const configured = process.env.DATABASE_URL || process.env.DB_HOST;
  if (!configured) {
    console.log('[db] no database configured (set DATABASE_URL) - using in-memory storage');
    return false;
  }
  try {
    const p = new Pool(poolConfig());
    // Hosted databases close idle connections; without this handler that would crash the process.
    p.on('error', err => console.error('[db] idle connection error:', err.message));
    await p.query('SELECT 1');
    await ensureSchema(p);
    pool = p;
    console.log('[db] PostgreSQL connected');
  } catch (e) {
    console.log(`[db] PostgreSQL unavailable (${e.code || e.message}) - using in-memory storage`);
  }
  return !!pool;
}

async function saveAnalysis(source, totalRequests, alerts) {
  if (pool) {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const r = await client.query(
        'INSERT INTO analyses (source, total_requests, total_alerts) VALUES ($1,$2,$3) RETURNING id',
        [source, totalRequests, alerts.length]);
      const id = r.rows[0].id;
      const CHUNK = 500; // 9 params per row, stays far below Postgres' 65535 parameter limit
      for (let i = 0; i < alerts.length; i += CHUNK) {
        const part = alerts.slice(i, i + CHUNK);
        const params = [];
        const values = part.map((a, k) => {
          const o = k * 9;
          params.push(id, new Date(a.time).toISOString(), a.ip, a.type, a.severity, a.detail, a.path, a.status, a.userAgent);
          return `($${o + 1},$${o + 2},$${o + 3},$${o + 4},$${o + 5},$${o + 6},$${o + 7},$${o + 8},$${o + 9})`;
        });
        await client.query(
          `INSERT INTO alerts (analysis_id,event_time,ip,type,severity,detail,path,status_code,user_agent) VALUES ${values.join(',')}`,
          params);
      }
      await client.query('COMMIT');
      return id;
    } catch (e) {
      await client.query('ROLLBACK').catch(() => {});
      throw e;
    } finally {
      client.release();
    }
  }
  const id = mem.nextId++;
  mem.analyses.unshift({ id, source, total_requests: totalRequests, total_alerts: alerts.length, created_at: new Date() });
  alerts.forEach(a => mem.alerts.push({ ...a, analysis_id: id }));
  return id;
}

async function getHistory(limit = 10) {
  if (pool) {
    const r = await pool.query('SELECT * FROM analyses ORDER BY id DESC LIMIT $1', [limit]);
    return r.rows;
  }
  return mem.analyses.slice(0, limit);
}

async function setDecision(ip, decision, score = 0) {
  if (pool) {
    await pool.query(
      `INSERT INTO blocklist (ip, decision, risk_score) VALUES ($1,$2,$3)
       ON CONFLICT (ip) DO UPDATE SET decision = EXCLUDED.decision, risk_score = EXCLUDED.risk_score, decided_at = now()`,
      [ip, decision, score]);
  } else {
    mem.blocklist.set(ip, { ip, decision, risk_score: score });
  }
}

async function clearDecision(ip) {
  if (pool) await pool.query('DELETE FROM blocklist WHERE ip = $1', [ip]);
  else mem.blocklist.delete(ip);
}

async function getDecisions() {
  if (pool) {
    const r = await pool.query('SELECT ip, decision, risk_score FROM blocklist');
    return r.rows;
  }
  return [...mem.blocklist.values()];
}

module.exports = { init, saveAnalysis, getHistory, setDecision, clearDecision, getDecisions };
