// crates/invariant_b2b/src/handlers/keys.rs
/*
 * Copyright (c) 2026 Invariant Protocol.
 */

use axum::{
    extract::{Extension, Path},
    http::StatusCode,
    Json,
};
use uuid::Uuid;
use crate::state::SharedB2bState;
use crate::error::B2bError;
use crate::auth::rls_layer::TenantContext;
use crate::auth::rbac::OrgRole;
use crate::models::dto::{CreateApiKeyRequest, ApiKeyResponse, RevokeApiKeyRequest};
use tracing::{info, instrument};

/// POST /api/v1/orgs/{org_id}/keys
#[instrument(skip(state, ctx, req))]
pub async fn create_key_handler(
    Extension(state): Extension<SharedB2bState>,
    Extension(ctx): Extension<TenantContext>,
    Json(req): Json<CreateApiKeyRequest>,
) -> Result<(StatusCode, Json<ApiKeyResponse>), B2bError> {
    
    // 🛡️ FIX: Utilizing the fully implemented RBAC model
    OrgRole::from_str(&ctx.role).can_manage_keys()?;

    if req.name.is_empty() || req.name.len() > 50 {
        return Err(B2bError::Internal("Invalid key name".into())); 
    }

    let response = crate::db::keys::create_api_key(&state.pool, &ctx, &req).await?;
    
    info!(
        org_id = %ctx.org_id, 
        user_id = %ctx.user_id, 
        key_id = %response.id, 
        "New API Key Provisioned"
    );

    Ok((StatusCode::CREATED, Json(response)))
}

/// GET /api/v1/orgs/{org_id}/keys
#[instrument(skip(state, ctx))]
pub async fn list_keys_handler(
    Extension(state): Extension<SharedB2bState>,
    Extension(ctx): Extension<TenantContext>,
) -> Result<Json<Vec<ApiKeyResponse>>, B2bError> {
    
    let keys = crate::db::keys::list_api_keys(&state.pool, &ctx).await?;
    Ok(Json(keys))
}

/// DELETE /api/v1/orgs/{org_id}/keys/{key_id}
#[instrument(skip(state, ctx))]
pub async fn revoke_key_handler(
    Path((_org_id, key_id)): Path<(Uuid, Uuid)>,
    Extension(state): Extension<SharedB2bState>,
    Extension(ctx): Extension<TenantContext>,
    Json(req): Json<RevokeApiKeyRequest>,
) -> Result<StatusCode, B2bError> {
    
    // 🛡️ FIX: Utilizing the fully implemented RBAC model
    OrgRole::from_str(&ctx.role).can_manage_keys()?;

    crate::db::keys::revoke_api_key(&state.pool, &ctx, key_id, &req.reason).await?;
    
    info!(
        org_id = %ctx.org_id, 
        key_id = %key_id, 
        "API Key Revoked"
    );

    Ok(StatusCode::OK)
}