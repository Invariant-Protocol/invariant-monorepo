-- crates/invariant_server/migrations/20260224030000_api_client_secrets_cleanup.sql
-- Ensure secret_wrapped has created_at if it was missed in earlier migrations
ALTER TABLE api_client_secrets
  ADD COLUMN IF NOT EXISTS created_at timestamptz DEFAULT now();