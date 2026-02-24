// crates/invariant_server/src/state.rs
/*
 * Copyright (c) 2026 Invariant Protocol.
 *
 * This source code is licensed under the Business Source License (BSL 1.1) 
 * found in the LICENSE.md file in the root directory of this source tree.
 */

use std::sync::Arc;
use aws_sdk_kms::Client as KmsClient;
use moka::future::Cache;

use invariant_engine::InvariantEngine;
use crate::db::PostgresStorage;
use crate::impls::RedisNonceManager;
use crate::rate_limiter::RateLimiter;
use redis::Client as RedisClient;
use sqlx::PgPool;

pub type SharedState = Arc<AppState>;

pub struct AppState {
    pub engine: InvariantEngine<PostgresStorage, RedisNonceManager>,
    pub redis: RedisClient,
    pub pool: PgPool, 
    pub admin_secret: String, // 🛡️ Loaded once at startup for thread-safe access

    // KMS client and key cache for envelope encryption
    pub kms_client: KmsClient,
    
    /// Cache mapping ciphertext_blob (base64) -> plaintext bytes.
    /// Entries expire after a configured TTL to balance performance and security.
    pub key_cache: Cache<String, Vec<u8>>,

    // Rate limiter wrapper for Redis token bucket
    pub rate_limiter: RateLimiter,
}