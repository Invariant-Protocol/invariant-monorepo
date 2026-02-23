-- crates/invariant_server/migrations/20260223000000_offline_policies.sql

-- Add shadow mode and JSONB offline policy definitions
ALTER TABLE api_clients
  ADD COLUMN IF NOT EXISTS shadow_mode BOOLEAN DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS offline_policy JSONB NULL;

-- Create an audit table for offline access reconciliation
CREATE TABLE IF NOT EXISTS api_client_offline_audit (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    api_key VARCHAR(64) NOT NULL REFERENCES api_clients(api_key),
    endpoint VARCHAR(255) NOT NULL,
    snapshot_payload JSONB NOT NULL,
    processed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    suspicious BOOLEAN DEFAULT FALSE
);

CREATE INDEX idx_offline_audit_key ON api_client_offline_audit(api_key);