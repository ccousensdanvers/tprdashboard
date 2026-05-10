-- Historical trend snapshots and risk finding lifecycle history for D1 dashboard visualizations.

CREATE TABLE IF NOT EXISTS domain_score_snapshots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  vendor_primary_hostname TEXT NOT NULL,
  hostname TEXT NOT NULL,
  automated_score INTEGER,
  scanned_at TEXT,
  captured_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_domain_score_snapshots_captured
ON domain_score_snapshots(captured_at);

CREATE INDEX IF NOT EXISTS idx_domain_score_snapshots_domain
ON domain_score_snapshots(vendor_primary_hostname, hostname);

CREATE TABLE IF NOT EXISTS domain_risk_count_snapshots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  vendor_primary_hostname TEXT NOT NULL,
  hostname TEXT NOT NULL,
  critical_count INTEGER DEFAULT 0,
  high_count INTEGER DEFAULT 0,
  medium_count INTEGER DEFAULT 0,
  low_count INTEGER DEFAULT 0,
  failed_check_count INTEGER DEFAULT 0,
  waived_check_count INTEGER DEFAULT 0,
  total_check_count INTEGER DEFAULT 0,
  captured_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_domain_risk_count_snapshots_captured
ON domain_risk_count_snapshots(captured_at);

CREATE TABLE IF NOT EXISTS category_snapshots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  category TEXT NOT NULL,
  failed_check_count INTEGER DEFAULT 0,
  affected_vendor_count INTEGER DEFAULT 0,
  captured_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_category_snapshots_captured
ON category_snapshots(captured_at);

CREATE TABLE IF NOT EXISTS risk_findings_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  finding_key TEXT UNIQUE NOT NULL,
  vendor_primary_hostname TEXT NOT NULL,
  hostname TEXT NOT NULL,
  check_id TEXT,
  title TEXT,
  category TEXT,
  risk_type TEXT,
  risk_subtype TEXT,
  severity INTEGER,
  severity_name TEXT,
  first_seen_at TEXT,
  last_seen_at TEXT,
  resolved_at TEXT,
  status TEXT DEFAULT 'open',
  raw_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_risk_findings_history_status
ON risk_findings_history(status);

CREATE INDEX IF NOT EXISTS idx_risk_findings_history_vendor
ON risk_findings_history(vendor_primary_hostname, hostname);
