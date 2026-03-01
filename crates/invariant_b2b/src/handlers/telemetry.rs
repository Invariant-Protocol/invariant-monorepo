// crates/invariant_b2b/src/handlers/telemetry.rs
/*
 * Copyright (c) 2026 Invariant Protocol.
 */

use axum::{extract::{Extension, Query}, Json};
use serde::Deserialize;
use crate::state::SharedB2bState;
use crate::error::B2bError;
use crate::auth::rls_layer::TenantContext;
use crate::models::domain::TelemetryDataPoint;

#[derive(Deserialize)]
pub struct TelemetryQuery {
    pub days_lookback: Option<i32>,
}

pub async fn get_telemetry_handler(
    Query(query): Query<TelemetryQuery>,
    Extension(state): Extension<SharedB2bState>,
    Extension(ctx): Extension<TenantContext>,
) -> Result<Json<Vec<TelemetryDataPoint>>, B2bError> {
    
    let days = query.days_lookback.unwrap_or(7);
    let mut tx = ctx.begin_rls_tx(&state.pool).await?;

    // This queries the TimescaleDB hypertable. RLS ensures they only see their org's stats.
    let metrics = sqlx::query_as!(
        TelemetryDataPoint,
        r#"
        SELECT time_bucket, tier, decision, request_count
        FROM b2b_attestation_metrics
        WHERE time_bucket >= NOW() - make_interval(days => $1)
        ORDER BY time_bucket DESC
        "#,
        days
    )
    .fetch_all(&mut *tx).await.map_err(B2bError::Database)?;

    tx.commit().await.map_err(B2bError::Database)?;
    Ok(Json(metrics))
}