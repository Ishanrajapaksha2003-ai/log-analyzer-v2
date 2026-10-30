-- Run once in phpMyAdmin (XAMPP) or: mysql -u root < schema.sql
CREATE DATABASE IF NOT EXISTS log_analyzer CHARACTER SET utf8mb4;
USE log_analyzer;

CREATE TABLE IF NOT EXISTS analyses (
    id INT AUTO_INCREMENT PRIMARY KEY,
    source VARCHAR(255) NOT NULL,
    total_requests INT NOT NULL,
    total_alerts INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS alerts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    analysis_id INT NULL,
    event_time DATETIME NOT NULL,
    ip VARCHAR(45) NOT NULL,
    type VARCHAR(40) NOT NULL,
    severity ENUM('low','medium','high','critical') NOT NULL,
    detail VARCHAR(255),
    path VARCHAR(400),
    status_code SMALLINT,
    user_agent VARCHAR(255),
    INDEX idx_ip (ip),
    INDEX idx_type (type),
    INDEX idx_time (event_time),
    FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS blocklist (
    ip VARCHAR(45) PRIMARY KEY,
    decision ENUM('approved','rejected') NOT NULL,
    risk_score TINYINT NOT NULL DEFAULT 0,
    decided_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
