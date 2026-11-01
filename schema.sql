-- PostgreSQL schema. The app creates these tables automatically on start,
-- so you only need this file if you want to create them by hand:
--   psql "$DATABASE_URL" -f schema.sql

CREATE TABLE IF NOT EXISTS analyses (
    id SERIAL PRIMARY KEY,
    source VARCHAR(255) NOT NULL,
    total_requests INT NOT NULL,
    total_alerts INT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS alerts (
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
);
CREATE INDEX IF NOT EXISTS idx_alerts_ip ON alerts (ip);
CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts (type);
CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts (event_time);
CREATE INDEX IF NOT EXISTS idx_alerts_analysis ON alerts (analysis_id);

CREATE TABLE IF NOT EXISTS blocklist (
    ip VARCHAR(45) PRIMARY KEY,
    decision VARCHAR(10) NOT NULL CHECK (decision IN ('approved','rejected')),
    risk_score SMALLINT NOT NULL DEFAULT 0,
    decided_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
