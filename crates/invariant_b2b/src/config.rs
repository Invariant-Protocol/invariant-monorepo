// crates/invariant_b2b/src/config.rs
/*
 * Copyright (c) 2026 Invariant Protocol.
 */

use std::env;

#[derive(Debug, Clone)]
pub struct B2bConfig {
    pub database_url: String,
    pub redis_url: String,
    pub jwt_secret: String,
    pub admin_api_secret: String, // Required to encrypt keys for the Core Engine
    pub port: u16,
}

impl B2bConfig {
    pub fn load_from_env() -> Self {
        Self {
            database_url: env::var("DATABASE_URL").expect("DATABASE_URL must be set"),
            redis_url: env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into()),
            jwt_secret: env::var("B2B_JWT_SECRET").expect("B2B_JWT_SECRET must be set"),
            admin_api_secret: env::var("ADMIN_API_SECRET").expect("ADMIN_API_SECRET must be set"),
            port: env::var("B2B_PORT").unwrap_or_else(|_| "3001".to_string()).parse().expect("Invalid port"),
        }
    }
}