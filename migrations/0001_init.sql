CREATE TABLE scans (
  id TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  language TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  completed_at INTEGER,
  source_key TEXT NOT NULL,
  sarif_key TEXT,
  model_id TEXT NOT NULL,
  model_version TEXT NOT NULL,
  prompt_hash TEXT,
  ruleset_version TEXT
);

CREATE TABLE findings (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  cwe TEXT,
  severity TEXT NOT NULL,
  confidence TEXT,
  evidence TEXT,
  verdict TEXT,
  message TEXT NOT NULL,
  file TEXT NOT NULL,
  start_line INTEGER NOT NULL,
  end_line INTEGER NOT NULL,
  snippet TEXT,
  explanation TEXT,
  remediation TEXT,
  FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE job_keys (
  scan_id TEXT PRIMARY KEY,
  key_ciphertext TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE audit_log (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL,
  event TEXT NOT NULL,
  detail_json TEXT,
  at INTEGER NOT NULL
);

CREATE INDEX idx_findings_scan ON findings(scan_id);
CREATE INDEX idx_audit_scan ON audit_log(scan_id);
