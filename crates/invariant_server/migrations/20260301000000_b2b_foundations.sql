-- crates/invariant_b2b/migrations/20260301000000_b2b_foundations.sql

-- 1. Enums
CREATE TYPE org_role AS ENUM ('owner', 'admin', 'developer', 'billing');
CREATE TYPE key_status AS ENUM ('active', 'rolling', 'revoked');

-- 2. Organizations (The Tenant Root)
CREATE TABLE IF NOT EXISTS b2b_organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    billing_plan VARCHAR(50) NOT NULL DEFAULT 'hobbyist',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 3. Users (Mapped from an external IdP like Auth0/Supabase)
CREATE TABLE IF NOT EXISTS b2b_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ext_id VARCHAR(255) UNIQUE NOT NULL, -- The ID from the Identity Provider
    email VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 4. Organization Memberships (RBAC)
CREATE TABLE IF NOT EXISTS b2b_organization_users (
    org_id UUID NOT NULL REFERENCES b2b_organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES b2b_users(id) ON DELETE CASCADE,
    role org_role NOT NULL DEFAULT 'developer',
    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (org_id, user_id)
);
CREATE INDEX idx_org_users_user_id ON b2b_organization_users(user_id);

-- 5. API Keys (B2B Metadata Representation)
-- NOTE: The actual KMS ciphertext is provisioned into the `api_clients` table
-- used by the Core Engine via the Outbox event bridge. This table tracks the UI state.
CREATE TABLE IF NOT EXISTS b2b_api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES b2b_organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    key_prefix VARCHAR(16) NOT NULL, -- e.g., 'pk_live_AbCd'
    status key_status NOT NULL DEFAULT 'active',
    enforcement_mode VARCHAR(20) NOT NULL DEFAULT 'shadow', -- 'shadow' or 'enforce'
    created_by UUID REFERENCES b2b_users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ
);
CREATE INDEX idx_b2b_keys_org ON b2b_api_keys(org_id);