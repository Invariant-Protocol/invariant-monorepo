// crates/invariant_b2b/src/auth/rls_layer.rs
/*
 * Copyright (c) 2026 Invariant Protocol.
 */

use axum::{
    extract::Request,
    http::header::HeaderMap,
    middleware::Next,
    response::Response,
    Extension,
};
use uuid::Uuid;
use sqlx::{PgPool, Postgres, Transaction};
use crate::state::SharedB2bState;
use crate::error::B2bError;
use tracing::warn;

#[derive(Debug, Clone)]
pub struct TenantContext {
    pub user_id: Uuid,
    pub org_id: Uuid,
    pub role: String,
}

impl TenantContext {
    pub async fn begin_rls_tx<'a>(&self, pool: &PgPool) -> Result<Transaction<'a, Postgres>, B2bError> {
        let mut tx = pool.begin().await.map_err(B2bError::Database)?;

        sqlx::query("SELECT set_config('rls.tenant_id', $1, true)")
            .bind(self.org_id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(B2bError::Database)?;

        Ok(tx)
    }
}

pub async fn tenancy_middleware(
    Extension(state): Extension<SharedB2bState>,
    headers: HeaderMap,
    mut req: Request,
    next: Next,
) -> Result<Response, B2bError> {
    
    let auth_header = headers.get("Authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| B2bError::Unauthorized("Missing Authorization header".into()))?;

    if !auth_header.starts_with("Bearer ") {
        return Err(B2bError::Unauthorized("Invalid token format".into()));
    }
    let token = &auth_header[7..];

    let ext_subject_id = crate::auth::jwt::validate_and_extract_sub(token, &state.jwt_secret)?;

    let target_org_id_str = headers.get("X-Organization-Id")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| B2bError::Forbidden("Missing X-Organization-Id header".into()))?;
    
    let target_org_id = Uuid::parse_str(target_org_id_str)
        .map_err(|_| B2bError::Forbidden("Invalid Organization ID format".into()))?;

    let membership = sqlx::query!(
        r#"
        SELECT u.id as user_id, ou.role::text as role_str
        FROM b2b_users u
        JOIN b2b_organization_users ou ON u.id = ou.user_id
        WHERE u.ext_id = $1 AND ou.org_id = $2
        "#,
        ext_subject_id,
        target_org_id
    )
    .fetch_optional(&state.pool)
    .await.map_err(B2bError::Database)?;

    match membership {
        Some(record) => {
            let context = TenantContext {
                user_id: record.user_id,
                org_id: target_org_id,
                role: record.role_str.unwrap_or_else(|| "developer".to_string()),
            };

            req.extensions_mut().insert(context);
            Ok(next.run(req).await)
        }
        None => {
            warn!("Unauthorized cross-tenant access attempt by ext_id: {}", ext_subject_id);
            Err(B2bError::Forbidden("You do not have access to this organization.".into()))
        }
    }
}