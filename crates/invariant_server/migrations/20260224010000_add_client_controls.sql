-- crates/invariant_server/migrations/20260224010000_add_client_controls.sql
-- Add dynamic controls to api_clients
ALTER TABLE api_clients
  ADD COLUMN IF NOT EXISTS requests_per_second integer DEFAULT 10,
  ADD COLUMN IF NOT EXISTS burst_capacity integer DEFAULT 20,
  ADD COLUMN IF NOT EXISTS monthly_quota bigint DEFAULT 0,
  ADD COLUMN IF NOT EXISTS enforcement_mode text DEFAULT 'enforce';