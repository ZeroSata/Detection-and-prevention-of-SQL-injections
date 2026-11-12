-- =============================================================================
-- DB Security Lab — схема БД (PostgreSQL 15+)
-- Выполняется официальным entrypoint образа postgres от имени POSTGRES_USER
-- (= app_admin, роль администрирования/миграций). Роли и права — 02_roles.sh.
-- =============================================================================

BEGIN;

-- --- Пользователи демо-приложения (пароли ТОЛЬКО в виде bcrypt-хэшей) -------
CREATE TABLE IF NOT EXISTS users (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username      VARCHAR(64)   NOT NULL UNIQUE,
    password_hash TEXT          NOT NULL,
    full_name     VARCHAR(128)  NOT NULL DEFAULT '',
    role          VARCHAR(32)   NOT NULL DEFAULT 'user',
    is_active     BOOLEAN       NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ   NOT NULL DEFAULT now()
);

-- --- Демо-таблица для поиска -------------------------------------------------
CREATE TABLE IF NOT EXISTS products (
    id          BIGINT        GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name        VARCHAR(160)  NOT NULL,
    category    VARCHAR(64)   NOT NULL DEFAULT 'general',
    price       NUMERIC(10,2) NOT NULL DEFAULT 0,
    description TEXT          NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ   NOT NULL DEFAULT now()
);

-- --- Журнал аудита HTTP-запросов и результатов WAF/СУБД ----------------------
CREATE TABLE IF NOT EXISTS audit_logs (
    id               BIGINT       GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ts               TIMESTAMPTZ  NOT NULL DEFAULT now(),
    source_ip        VARCHAR(64)  NOT NULL DEFAULT 'unknown',
    endpoint         VARCHAR(200) NOT NULL,
    mode             VARCHAR(16)  NOT NULL DEFAULT 'other',  -- insecure|secure|dashboard|other
    waf_enabled      BOOLEAN      NOT NULL DEFAULT FALSE,
    raw_input        TEXT         NOT NULL DEFAULT '',
    generated_sql    TEXT         NOT NULL DEFAULT '',
    result_status    VARCHAR(16)  NOT NULL DEFAULT 'ok',     -- ok|error|blocked
    status_code      INTEGER      NOT NULL DEFAULT 0,
    response_time_ms INTEGER      NOT NULL DEFAULT 0,
    error_detail     TEXT         NOT NULL DEFAULT ''
);

-- --- Инциденты ИБ (корреляция событии аудита) --------------------------------
CREATE TABLE IF NOT EXISTS incidents (
    id           BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ts           TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    source_ip    VARCHAR(64) NOT NULL,
    attack_type  VARCHAR(48) NOT NULL,   -- tautology|union|comment|stacked|time_based|error_based|recon|obfuscation|quote|semicolon|keyword
    payload      TEXT        NOT NULL,
    matched_rule VARCHAR(64) NOT NULL,
    risk_level   VARCHAR(16) NOT NULL DEFAULT 'medium', -- low|medium|high|critical
    status       VARCHAR(16) NOT NULL DEFAULT 'new',    -- new|investigating|closed
    repeat_count INTEGER     NOT NULL DEFAULT 1,
    escalated    BOOLEAN     NOT NULL DEFAULT FALSE,
    audit_log_id BIGINT      REFERENCES audit_logs(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_ts     ON audit_logs (ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_ip     ON audit_logs (source_ip);
CREATE INDEX IF NOT EXISTS idx_audit_status ON audit_logs (result_status);
CREATE INDEX IF NOT EXISTS idx_audit_mode   ON audit_logs (mode);
CREATE INDEX IF NOT EXISTS idx_incidents_ts     ON incidents (ts DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_risk   ON incidents (risk_level);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents (status);
CREATE INDEX IF NOT EXISTS idx_incidents_ip     ON incidents (source_ip);

COMMIT;
