// crates/invariant_b2b/src/auth/rate_limit.rs
/*
 * Copyright (c) 2026 Invariant Protocol.
 */

use axum::{
    extract::Request,
    middleware::Next,
    response::Response,
    Extension,
};
use crate::state::SharedB2bState;
use crate::error::B2bError;
use crate::auth::rls_layer::TenantContext;
use tracing::warn;

/// Protects the B2B APIs from abuse by rate-limiting based on the authenticated User ID.
pub async fn b2b_rate_limit_middleware(
    Extension(state): Extension<SharedB2bState>,
    Extension(ctx): Extension<TenantContext>,
    req: Request,
    next: Next,
) -> Result<Response, B2bError> {
    
    // B2B Dashboard limit: 20 requests per second, burst of 50.
    let allowed = state.rate_limiter.acquire(&ctx.user_id.to_string(), 20.0, 50).await
        .map_err(|e| {
            warn!("Redis rate limiter failed: {}", e);
            B2bError::Internal("Rate limiter unavailable".into())
        })?;

    if !allowed {
        warn!("Rate limit exceeded for B2B user: {}", ctx.user_id);
        return Err(B2bError::TooManyRequests);
    }

    Ok(next.run(req).await)
}