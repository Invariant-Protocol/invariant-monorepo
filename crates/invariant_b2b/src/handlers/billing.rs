// crates/invariant_b2b/src/handlers/billing.rs
/*
 * Copyright (c) 2026 Invariant Protocol.
 */

use axum::{extract::Extension, Json};
use serde::Serialize;
use crate::state::SharedB2bState;
use crate::error::B2bError;
use crate::auth::rls_layer::TenantContext;
use crate::auth::rbac::OrgRole;

#[derive(Serialize)]
pub struct BillingUsage {
    pub plan: String,
    pub current_month_attestations: i64,
    pub monthly_quota: i64,
}

pub async fn get_billing_usage_handler(
    Extension(state): Extension<SharedB2bState>,
    Extension(ctx): Extension<TenantContext>,
) -> Result<Json<BillingUsage>, B2bError> {
    
    OrgRole::from_str(&ctx.role).can_view_billing()?;

    let mut tx = ctx.begin_rls_tx(&state.pool).await?;

    let org_plan = sqlx::query!("SELECT billing_plan FROM b2b_organizations WHERE id = $1", ctx.org_id)
        .fetch_one(&mut *tx).await.map_err(B2bError::Database)?;

    // 🛡️ FIX: Cast SUM to BIGINT so SQLx parses it strictly as i64, bypassing NUMERIC reqs.
    let usage = sqlx::query!(
        r#"
        SELECT COALESCE(SUM(request_count)::BIGINT, 0) as "total_requests!"
        FROM b2b_attestation_metrics
        WHERE time_bucket >= date_trunc('month', NOW())
        "#
    )
    .fetch_one(&mut *tx).await.map_err(B2bError::Database)?;

    tx.commit().await.map_err(B2bError::Database)?;

    let quota = match org_plan.billing_plan.as_str() {
        "hobbyist" => 1_000,
        "growth" => 50_000,
        "enterprise" => 1_000_000,
        _ => 0,
    };

    Ok(Json(BillingUsage {
        plan: org_plan.billing_plan,
        current_month_attestations: usage.total_requests, // 🛡️ FIX: Clean mapped i64
        monthly_quota: quota,
    }))
}