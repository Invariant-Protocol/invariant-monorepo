-- crates/invariant_b2b/migrations/20260301000001_rls_policies.sql

-- 1. Enable RLS on Tenant-Bound Tables
ALTER TABLE b2b_api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE b2b_organization_users ENABLE ROW LEVEL SECURITY;
-- (b2b_organizations and b2b_users are typically accessed via explicit joins 
--  in auth middleware, so we leave them open to the backend service role, 
--  but strictly lock the operational data.)

-- 2. Define the RLS Policies
-- These policies rely on a session variable `rls.tenant_id` being set
-- by the Rust Axum middleware before any query is executed.

CREATE POLICY isolate_api_keys_by_tenant ON b2b_api_keys
    FOR ALL
    USING (org_id = NULLIF(current_setting('rls.tenant_id', TRUE), '')::UUID);

CREATE POLICY isolate_org_users_by_tenant ON b2b_organization_users
    FOR ALL
    USING (org_id = NULLIF(current_setting('rls.tenant_id', TRUE), '')::UUID);

-- 3. Force RLS for the table owner (ensures the db connection pool respects it)
ALTER TABLE b2b_api_keys FORCE ROW LEVEL SECURITY;
ALTER TABLE b2b_organization_users FORCE ROW LEVEL SECURITY;