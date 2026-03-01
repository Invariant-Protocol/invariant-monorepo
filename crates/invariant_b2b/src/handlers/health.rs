// crates/invariant_b2b/src/handlers/health.rs
/*
 * Copyright (c) 2026 Invariant Protocol.
 */

use axum::{extract::Extension, Json};
use crate::state::SharedB2bState;
use serde_json::{json, Value};

/// Deep Health Check endpoint.
/// Actively pings the Database and Redis to ensure the B2B Service is fully operational.
pub async fn health_check_handler(
    Extension(state): Extension<SharedB2bState>,
) -> Json<Value> {
    
    // Ping PostgreSQL
    let db_ok = sqlx::query("SELECT 1").execute(&state.pool).await.is_ok();
    
    // Ping Redis
    let redis_ok = async {
        let mut conn = state.redis.get_multiplexed_async_connection().await.ok()?;
        let pong: String = redis::cmd("PING").query_async(&mut conn).await.ok()?;
        Some(pong == "PONG")
    }.await.unwrap_or(false);

    let status = if db_ok && redis_ok { "operational" } else { "degraded" };

    Json(json!({
        "service": "invariant_b2b",
        "status": status,
        "infrastructure": {
            "postgres": if db_ok { "connected" } else { "disconnected" },
            "redis_event_bus": if redis_ok { "connected" } else { "disconnected" }
        },
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}