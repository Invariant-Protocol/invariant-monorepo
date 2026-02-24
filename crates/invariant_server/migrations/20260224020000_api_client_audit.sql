-- crates/invariant_server/migrations/20260224020000_api_client_audit.sql
-- Audit trail table for partner lifecycle & admin actions
CREATE TABLE IF NOT EXISTS api_client_audit (
    id bigserial PRIMARY KEY,
    timestamp timestamptz NOT NULL DEFAULT now(),
    actor_id uuid NULL, 
    target_client_id uuid NULL,
    action text NOT NULL,
    reason text NULL,
    details jsonb NULL
);
CREATE INDEX IF NOT EXISTS idx_api_client_audit_target ON api_client_audit (target_client_id);