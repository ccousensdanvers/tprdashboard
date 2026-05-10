-- Initial Cloudflare D1 schema for UpGuard domain risk ingestion.
-- TODO(snapshot-history): add immutable vendor_snapshot and check_result_snapshot tables for longitudinal trend analysis.
-- TODO(remediation): add assignment, status, due-date, and evidence tables for remediation workflows.
-- TODO(change-feeds): add event tables for score/check/category deltas consumed by municipal executive reporting.

CREATE TABLE IF NOT EXISTS vendors (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  hostname TEXT UNIQUE NOT NULL,
  automated_score INTEGER,
  scanned_at TEXT,
  labels_json TEXT,
  a_records_json TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS check_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  vendor_hostname TEXT NOT NULL,
  check_id TEXT,
  title TEXT,
  description TEXT,
  category TEXT,
  risk_type TEXT,
  risk_subtype TEXT,
  severity INTEGER,
  severity_name TEXT,
  passed INTEGER,
  checked_at TEXT,
  actual_json TEXT,
  expected_json TEXT,
  sources_json TEXT,
  raw_json TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS waived_check_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  vendor_hostname TEXT NOT NULL,
  check_id TEXT,
  title TEXT,
  description TEXT,
  category TEXT,
  risk_type TEXT,
  risk_subtype TEXT,
  severity INTEGER,
  severity_name TEXT,
  passed INTEGER,
  checked_at TEXT,
  actual_json TEXT,
  expected_json TEXT,
  sources_json TEXT,
  raw_json TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ingestion_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  started_at TEXT,
  completed_at TEXT,
  vendor_count INTEGER,
  success_count INTEGER,
  failure_count INTEGER,
  status TEXT,
  error_json TEXT
);

CREATE TABLE IF NOT EXISTS ingestion_errors (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  hostname TEXT,
  error_message TEXT,
  status_code INTEGER,
  response_body TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_check_results_vendor_hostname ON check_results(vendor_hostname);
CREATE INDEX IF NOT EXISTS idx_check_results_failed_severity ON check_results(passed, severity, severity_name);
CREATE INDEX IF NOT EXISTS idx_check_results_category ON check_results(category);
CREATE INDEX IF NOT EXISTS idx_check_results_risk_type ON check_results(risk_type);
CREATE INDEX IF NOT EXISTS idx_waived_check_results_vendor_hostname ON waived_check_results(vendor_hostname);
CREATE INDEX IF NOT EXISTS idx_ingestion_errors_hostname ON ingestion_errors(hostname);
