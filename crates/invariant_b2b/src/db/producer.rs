// crates/invariant_b2b/src/db/producer.rs
/*
 * Copyright (c) 2026 Invariant Protocol.
 *
 * Publishes invalidation events to Redis. The Core Engine listens to these
 * events to instantly drop revoked keys from its high-speed Moka cache.
 */

use redis::AsyncCommands;
use tracing::error;

pub async fn publish_cache_invalidation(
    redis_client: &redis::Client,
    api_key: &str,
) -> Result<(), crate::error::B2bError> {
    let mut conn = redis_client
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| crate::error::B2bError::Internal(format!("Redis connection failed: {}", e)))?;

    // The Core Engine listens on this channel to flush `moka`
    let channel = "invariant:events:key_revoked";
    
    let _: () = conn.publish(channel, api_key).await.map_err(|e| {
        error!("Failed to publish cache invalidation for key {}: {}", api_key, e);
        crate::error::B2bError::Internal("Cache invalidation dispatch failed".into())
    })?;

    Ok(())
}