-- Add source details captured from the UpGuard vendor risk diff endpoint.
ALTER TABLE vendor_risk_events ADD COLUMN sources_json TEXT NOT NULL DEFAULT '[]';
