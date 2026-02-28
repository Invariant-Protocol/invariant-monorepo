// crates/invariant_server/src/handlers/secrets.rs
/*
 * Copyright (c) 2026 Invariant Protocol.
 *
 * Secret rotation handler
 *
 * Endpoint: POST /admin/keys/{client_id}/rotate-secret
 * Requires admin_auth_middleware (Bearer ADMIN_API_SECRET).
 */

use axum::{extract::{Path, Extension, Json}, http::StatusCode};
use serde::Deserialize;
use crate::state::SharedState;
use tracing::error;
use rand::{Rng, thread_rng};
use rand::distributions::Alphanumeric;
use uuid::Uuid;

#[derive(Deserialize)]
pub struct RotateRequest {
    pub reason: Option<String>,
}

pub async fn rotate_hmac_secret_handler(
    Extension(state): Extension<SharedState>,
    Path(client_id): Path<Uuid>,
    Json(req): Json<RotateRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, String)> {
    
    let kms_key_id = std::env::var("KMS_CMK_ID").map_err(|_| {
        error!("KMS_CMK_ID not configured in environment");
        (StatusCode::INTERNAL_SERVER_ERROR, "KMS_CMK_ID not configured".to_string())
    })?;

    // Generate an alphanumeric string matching Flutter's expectations
    let new_secret: String = thread_rng().sample_iter(&Alphanumeric).take(64).map(char::from).collect();

    let kms_helper = crate::kms::KmsHelper::new(state.kms_client.clone(), state.key_cache.clone());
    let ciphertext_blob = kms_helper.encrypt(&kms_key_id, new_secret.as_bytes()).await
        .map_err(|e| {
            error!("KMS encrypt failed: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "KMS failure".to_string())
        })?;

    let mut tx = state.pool.begin().await.map_err(|e| {
        error!("DB begin failed: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "DB failure".to_string())
    })?;

    let _ = sqlx::query!("UPDATE api_client_secrets SET active = false WHERE api_client_id = $1 AND active = true", client_id)
        .execute(&mut *tx).await.map_err(|e| { 
            error!("DB update failed: {}", e); 
            (StatusCode::INTERNAL_SERVER_ERROR, "DB failure".to_string()) 
        })?;

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

    let storage = crate::db::PostgresStorage::new(state.pool.clone());
    storage.insert_client_audit(None, Some(client_id), "rotate_secret", req.reason.as_deref(), None).await;

    // Output the raw string so it aligns with Flutter's utf8.encode(hmacSecret)
    Ok((StatusCode::OK, Json(serde_json::json!({ 
        "hmac_secret": new_secret,
        "message": "Secret rotated successfully. This plaintext will only be displayed once."
    }))))
}