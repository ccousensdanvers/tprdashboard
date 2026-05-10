-- Domain-centric Cloudflare D1 schema for UpGuard vendor/domain endpoint ingestion.
-- Legacy tables from 0001_initial.sql are intentionally left in place.

CREATE TABLE IF NOT EXISTS vendor_domains (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  vendor_primary_hostname TEXT NOT NULL,
  hostname TEXT NOT NULL,
  automated_score INTEGER,
  scanned_at TEXT,
  labels_json TEXT NOT NULL DEFAULT '[]',
  a_records_json TEXT NOT NULL DEFAULT '[]',
  raw_json TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(vendor_primary_hostname, hostname)
);

CREATE TABLE IF NOT EXISTS domain_check_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  vendor_primary_hostname TEXT NOT NULL,
  hostname TEXT NOT NULL,
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
  actual_json TEXT NOT NULL DEFAULT '[]',
  expected_json TEXT NOT NULL DEFAULT '[]',
  sources_json TEXT NOT NULL DEFAULT '[]',
  raw_json TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_domain_check_results_domain
ON domain_check_results(vendor_primary_hostname, hostname);

CREATE INDEX IF NOT EXISTS idx_domain_check_results_failed
ON domain_check_results(passed, severity, severity_name);

CREATE INDEX IF NOT EXISTS idx_domain_check_results_category
ON domain_check_results(category);

CREATE TABLE IF NOT EXISTS domain_waived_check_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  vendor_primary_hostname TEXT NOT NULL,
  hostname TEXT NOT NULL,
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
  actual_json TEXT NOT NULL DEFAULT '[]',
  expected_json TEXT NOT NULL DEFAULT '[]',
  sources_json TEXT NOT NULL DEFAULT '[]',
  raw_json TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_domain_waived_check_results_domain
ON domain_waived_check_results(vendor_primary_hostname, hostname);

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
