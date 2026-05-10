-- UpGuard portfolio risk profile, active vendor risks, and vendor risk diff/change-feed schema.

CREATE TABLE IF NOT EXISTS portfolio_risk_profile_snapshots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  portfolio_name TEXT NOT NULL,
  portfolio_id TEXT,
  total_vendors INTEGER,
  raw_json TEXT,
  captured_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS portfolio_common_risks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  snapshot_id INTEGER NOT NULL,
  title TEXT,
  finding TEXT,
  category TEXT,
  risk_type TEXT,
  risk_subtype TEXT,
  severity INTEGER,
  severity_name TEXT,
  affected_vendor_count INTEGER,
  affected_domain_count INTEGER,
  raw_json TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS vendor_active_risks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  vendor_primary_hostname TEXT NOT NULL,
  risk_key TEXT,
  title TEXT,
  finding TEXT,
  category TEXT,
  risk_type TEXT,
  risk_subtype TEXT,
  severity INTEGER,
  severity_name TEXT,
  first_detected TEXT,
  affected_hostnames_json TEXT NOT NULL DEFAULT '[]',
  waived INTEGER DEFAULT 0,
  raw_json TEXT,
  captured_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_vendor_active_risks_vendor
ON vendor_active_risks(vendor_primary_hostname);

CREATE INDEX IF NOT EXISTS idx_vendor_active_risks_severity
ON vendor_active_risks(severity, severity_name);

CREATE TABLE IF NOT EXISTS vendor_risk_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  vendor_primary_hostname TEXT NOT NULL,
  event_type TEXT,
  title TEXT,
  finding TEXT,
  category TEXT,
  risk_type TEXT,
  risk_subtype TEXT,
  severity INTEGER,
  severity_name TEXT,
  affected_hostnames_json TEXT NOT NULL DEFAULT '[]',
  event_start TEXT,
  event_end TEXT,
  raw_json TEXT,
  captured_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_vendor_risk_events_vendor
ON vendor_risk_events(vendor_primary_hostname);

CREATE INDEX IF NOT EXISTS idx_vendor_risk_events_captured
ON vendor_risk_events(captured_at);
