-- crates/invariant_b2b/migrations/20260301000002_outbox_and_telemetry.sql

-- 1. The Transactional Outbox
-- Solves the "Dual Write" problem. When an API Key is revoked in the B2B portal,
-- we write the revocation intent here in the SAME database transaction.
-- A background Rust worker polls this table and safely pushes it to Redis/Core Engine.
CREATE TABLE IF NOT EXISTS b2b_event_outbox (
    id BIGSERIAL PRIMARY KEY,
    aggregate_type VARCHAR(50) NOT NULL, -- e.g., 'ApiKey'
    aggregate_id UUID NOT NULL,
    event_type VARCHAR(50) NOT NULL,     -- e.g., 'KeyRevoked', 'KeyProvisioned'
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at TIMESTAMPTZ,            -- Null means pending
    error_log TEXT
);

CREATE INDEX idx_outbox_unprocessed ON b2b_event_outbox(created_at) WHERE processed_at IS NULL;

-- 2. Attestation Metrics (Designed for TimescaleDB compatibility)
-- If TimescaleDB is installed, this table can be converted to an hypertable.
-- It stores aggregated hour-level rollups from the Redis pipeline.
CREATE TABLE IF NOT EXISTS b2b_attestation_metrics (
    time_bucket TIMESTAMPTZ NOT NULL,
    org_id UUID NOT NULL REFERENCES b2b_organizations(id) ON DELETE CASCADE,
    api_key_id UUID REFERENCES b2b_api_keys(id) ON DELETE CASCADE,
    tier VARCHAR(50) NOT NULL, -- 'TITANIUM', 'STEEL', 'SOFTWARE'
    decision VARCHAR(20) NOT NULL, -- 'allow', 'allow_shadow', 'deny'
    request_count BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (time_bucket, org_id, api_key_id, tier, decision)
);

-- Enable RLS on Metrics
ALTER TABLE b2b_attestation_metrics ENABLE ROW LEVEL SECURITY;
ALTER TABLE b2b_attestation_metrics FORCE ROW LEVEL SECURITY;

CREATE POLICY isolate_metrics_by_tenant ON b2b_attestation_metrics
    FOR ALL
    USING (org_id = NULLIF(current_setting('rls.tenant_id', TRUE), '')::UUID);