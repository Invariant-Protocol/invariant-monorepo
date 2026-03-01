// crates/invariant_b2b/src/handlers/users.rs
/*
 * Copyright (c) 2026 Invariant Protocol.
 */

use axum::{extract::Extension, Json};
use crate::state::SharedB2bState;
use crate::error::B2bError;
use crate::auth::rls_layer::TenantContext;
use crate::models::domain::User;

/// GET /api/v1/orgs/{org_id}/users/me
pub async fn get_me_handler(
    Extension(state): Extension<SharedB2bState>,
    Extension(ctx): Extension<TenantContext>,
) -> Result<Json<User>, B2bError> {
    
    let mut tx = ctx.begin_rls_tx(&state.pool).await?;

    let user = sqlx::query_as!(
        User,
        "SELECT id, ext_id, email, name, created_at FROM b2b_users WHERE id = $1",
        ctx.user_id
    )
    .fetch_optional(&mut *tx)
    .await
    .map_err(B2bError::Database)?
    .ok_or_else(|| B2bError::NotFound("User profile not found".into()))?;

    tx.commit().await.map_err(B2bError::Database)?;

    Ok(Json(user))
}