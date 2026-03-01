// crates/invariant_b2b/src/state.rs
/*
 * Copyright (c) 2026 Invariant Protocol.
 */

use sqlx::PgPool;
use std::sync::Arc;
use crate::rate_limiter::RateLimiter;

pub type SharedB2bState = Arc<B2bState>;

pub struct B2bState {
    pub pool: PgPool,
    pub rate_limiter: RateLimiter,
    pub jwt_secret: String, 
    #[allow(dead_code)]
    pub redis: redis::Client, 
}

impl B2bState {
    pub fn new(pool: PgPool, redis: redis::Client, jwt_secret: String) -> Self {
        let rate_limiter = RateLimiter::new(redis.clone());
        Self { pool, redis, rate_limiter, jwt_secret }
    }
}