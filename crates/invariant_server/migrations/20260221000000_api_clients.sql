-- crates/invariant_server/migrations/20260221000000_api_clients.sql
CREATE TABLE IF NOT EXISTS api_clients (
    client_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_key VARCHAR(64) UNIQUE NOT NULL,
    hmac_secret VARCHAR(128) NOT NULL,
    cert_fingerprint VARCHAR(64) NOT NULL,
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'suspended')),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_api_clients_key ON api_clients(api_key);