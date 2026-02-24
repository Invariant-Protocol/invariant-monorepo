// crates/invariant_server/src/handlers/secrets.rs
/*
 * Copyright (c) 2026 Invariant Protocol.
 *
 * Secret rotation handler
 *
 * Endpoint: POST /admin/clients/{client_id}/rotate-secret
 * Requires admin_auth_middleware (Bearer ADMIN_API_SECRET).
 *
 * Behavior:
 * - Calls KMS GenerateDataKey with configured CMK (provided via env).
 * - Stores ciphertext_blob in api_client_secrets (active=true).
 * - Marks previous active secret rows for that client as active=false.
 * - Returns plaintext (base64) to caller once (over TLS). Caller must show it to partner.
 */

use axum::{extract::{Path, Extension, Json}, http::StatusCode};
use serde::Deserialize;
use crate::state::SharedState;
use tracing::error;
use base64::{engine::general_purpose, Engine as _};
use uuid::Uuid;

#[derive(Deserialize)]
pub struct RotateRequest {
    /// Optional: reason for rotation to store in the audit logs (e.g., "compromise", "scheduled_rotation")
    pub reason: Option<String>,
}

pub async fn rotate_hmac_secret_handler(
    Extension(state): Extension<SharedState>,
    Path(client_id): Path<Uuid>,
    Json(req): Json<RotateRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, String)> {
    
    // CMK ID must be present in env
    let kms_key_id = std::env::var("KMS_CMK_ID").map_err(|_| {
        error!("KMS_CMK_ID not configured in environment");
        (StatusCode::INTERNAL_SERVER_ERROR, "KMS_CMK_ID not configured".to_string())
    })?;

    // Generate new data key
    let kms_helper = crate::kms::KmsHelper::new(state.kms_client.clone(), state.key_cache.clone());
    let (plaintext, ciphertext_blob) = kms_helper.generate_data_key(&kms_key_id).await
        .map_err(|e| {
            error!("KMS generate_data_key failed: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "KMS failure".to_string())
        })?;

    // Begin DB transaction: insert new secret and mark previous active=false
    let mut tx = state.pool.begin().await.map_err(|e| {
        error!("DB begin failed: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "DB failure".to_string())
    })?;

    // Deactivate previous secrets
    let _ = sqlx::query!("UPDATE api_client_secrets SET active = false WHERE api_client_id = $1 AND active = true", client_id)
        .execute(&mut *tx).await.map_err(|e| { 
            error!("DB update failed: {}", e); 
            (StatusCode::INTERNAL_SERVER_ERROR, "DB failure".to_string()) 
        })?;

    // Insert new ciphertext blob
    let _ = sqlx::query!("INSERT INTO api_client_secrets (api_client_id, secret_wrapped, active, created_at) VALUES ($1, $2, true, NOW())",
        client_id, ciphertext_blob)
        .execute(&mut *tx).await.map_err(|e| { 
            error!("DB insert secret failed: {}", e); 
            (StatusCode::INTERNAL_SERVER_ERROR, "DB failure".to_string()) 
        })?;

    tx.commit().await.map_err(|e| { 
        error!("DB commit failed: {}", e); 
        (StatusCode::INTERNAL_SERVER_ERROR, "DB failure".to_string()) 
    })?;

    // Audit log
    let storage = crate::db::PostgresStorage::new(state.pool.clone());
    storage.insert_client_audit(None, Some(client_id), "rotate_secret", req.reason.as_deref(), None).await;

    // Return plaintext base64 to caller once (over TLS)
    let plaintext_b64 = general_purpose::STANDARD.encode(&plaintext);
    Ok((StatusCode::OK, Json(serde_json::json!({ 
        "secret_base64": plaintext_b64,
        "message": "Secret rotated successfully. This plaintext will only be displayed once."
    }))))
}