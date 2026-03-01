// crates/invariant_b2b/src/handlers/orgs.rs
/*
 * Copyright (c) 2026 Invariant Protocol.
 */

use axum::{extract::{Extension, Path}, Json};
use uuid::Uuid;
use crate::state::SharedB2bState;
use crate::error::B2bError;
use crate::auth::rls_layer::TenantContext;
use crate::models::domain::{Organization, OrganizationMember};

pub async fn get_org_details_handler(
    Path(org_id): Path<Uuid>,
    Extension(state): Extension<SharedB2bState>,
    Extension(ctx): Extension<TenantContext>,
) -> Result<Json<Organization>, B2bError> {
    
    let mut tx = ctx.begin_rls_tx(&state.pool).await?;

    let org = sqlx::query_as!(
        Organization,
        "SELECT id, name, billing_plan, created_at, updated_at FROM b2b_organizations WHERE id = $1",
        org_id
    )
    .fetch_optional(&mut *tx).await.map_err(B2bError::Database)?
    .ok_or_else(|| B2bError::NotFound("Organization not found".into()))?;

    tx.commit().await.map_err(B2bError::Database)?;
    Ok(Json(org))
}

pub async fn list_members_handler(
    Path(_org_id): Path<Uuid>,
    Extension(state): Extension<SharedB2bState>,
    Extension(ctx): Extension<TenantContext>,
) -> Result<Json<Vec<OrganizationMember>>, B2bError> {
    
    let mut tx = ctx.begin_rls_tx(&state.pool).await?;

    // 🛡️ FIX: Appended `!` to `role` to force SQLx to resolve it as a non-optional String
    let members = sqlx::query_as!(
        OrganizationMember,
        r#"SELECT org_id, user_id, role::text as "role!", joined_at FROM b2b_organization_users ORDER BY joined_at ASC"#
    )
    .fetch_all(&mut *tx).await.map_err(B2bError::Database)?;

    tx.commit().await.map_err(B2bError::Database)?;
    Ok(Json(members))
}