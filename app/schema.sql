-- Unicode 双向文本审计记录表
CREATE TABLE IF NOT EXISTS audits (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    filename      TEXT,
    text_sha256   TEXT NOT NULL,
    text_bytes    INTEGER NOT NULL,
    char_count    INTEGER NOT NULL,
    risk_level    TEXT NOT NULL CHECK (
                    risk_level IN ('none', 'low', 'medium', 'high', 'critical')
                  ),
    statistics    TEXT NOT NULL,  -- JSON
    report        TEXT NOT NULL,  -- 完整审计结果 JSON
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_audits_risk       ON audits (risk_level);
CREATE INDEX IF NOT EXISTS idx_audits_filename   ON audits (filename);
CREATE INDEX IF NOT EXISTS idx_audits_created_at ON audits (created_at);
