// crates/invariant_b2b/src/models/dto.rs
/*
 * Copyright (c) 2026 Invariant Protocol.
 */

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

// --- API Keys ---

#[derive(Deserialize, Debug)]
pub struct CreateApiKeyRequest {
    pub name: String,
    pub enforcement_mode: String, // "shadow" or "enforce"
}

#[derive(Serialize, Debug)]
pub struct ApiKeyResponse {
    pub id: Uuid,
    pub name: String,
    pub key_prefix: String,
    pub status: String,
    pub enforcement_mode: String,
    pub created_at: DateTime<Utc>,
    
    /// ONLY populated immediately after creation. Never returned again.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plaintext_secret: Option<String>, 
}

#[derive(Deserialize, Debug)]
pub struct RevokeApiKeyRequest {
    pub reason: String,
}