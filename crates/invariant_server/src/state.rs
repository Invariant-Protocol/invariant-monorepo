// crates/invariant_server/src/state.rs
/*
 * Copyright (c) 2026 Invariant Protocol.
 *
 * This source code is licensed under the Business Source License (BSL 1.1) 
 * found in the LICENSE.md file in the root directory of this source tree.
 */

use std::sync::Arc;
use invariant_engine::InvariantEngine;
use crate::db::PostgresStorage;
use crate::impls::RedisNonceManager;
use redis::Client as RedisClient;
use sqlx::PgPool;

pub type SharedState = Arc<AppState>;

pub struct AppState {
    pub engine: InvariantEngine<PostgresStorage, RedisNonceManager>,
    pub redis: RedisClient,
    pub pool: PgPool, 
}