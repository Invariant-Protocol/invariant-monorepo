-- crates/invariant_server/migrations/20260224000000_api_client_v2.sql

-- 1. Enable Cryptographic Functions
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- 2. Create Certificate Lifecycle Table
CREATE TABLE IF NOT EXISTS api_client_certs (
    cert_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_client_id UUID NOT NULL REFERENCES api_clients(client_id) ON DELETE CASCADE,
    fingerprint VARCHAR(64) NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    raw_pem TEXT,
    UNIQUE(api_client_id, fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_api_client_certs_fingerprint ON api_client_certs(fingerprint);

-- 3. Create Secrets Lifecycle Table (Stored as BYTEA for future KMS wrapping)
CREATE TABLE IF NOT EXISTS api_client_secrets (
    secret_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_client_id UUID NOT NULL REFERENCES api_clients(client_id) ON DELETE CASCADE,
    secret_wrapped BYTEA NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    active BOOLEAN DEFAULT TRUE
);

CREATE INDEX IF NOT EXISTS idx_api_client_secrets_client ON api_client_secrets(api_client_id);

-- 4. Safely Migrate Existing Data
INSERT INTO api_client_certs(api_client_id, fingerprint, issued_at)
SELECT client_id, cert_fingerprint, created_at
FROM api_clients
WHERE cert_fingerprint IS NOT NULL AND cert_fingerprint != 'PENDING_PROVISIONING'
ON CONFLICT DO NOTHING;

INSERT INTO api_client_secrets(api_client_id, secret_wrapped, created_at)
SELECT client_id, convert_to(hmac_secret, 'UTF8'), created_at
FROM api_clients
WHERE hmac_secret IS NOT NULL
ON CONFLICT DO NOTHING;

-- 5. Harden and Expand the Core `api_clients` Table
ALTER TABLE api_clients
  DROP COLUMN IF EXISTS cert_fingerprint,
  DROP COLUMN IF EXISTS hmac_secret,
  ADD COLUMN IF NOT EXISTS partner_id UUID,
  ADD COLUMN IF NOT EXISTS rate_limit_per_hour INT DEFAULT 3600,
  ADD COLUMN IF NOT EXISTS burst_limit INT DEFAULT 100,
  ADD COLUMN IF NOT EXISTS last_used TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS contact_email TEXT;