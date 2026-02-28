// crates/invariant_server/src/handlers/admin.rs

use axum::{Extension, Json, http::StatusCode};
use serde::{Deserialize, Serialize};
use crate::state::SharedState;
use crate::error_response::AppError;
use rand::{Rng, thread_rng};
use rand::distributions::Alphanumeric;

#[derive(Serialize)]
pub struct ApiClientRecord {
    pub client_id: uuid::Uuid,
    pub api_key: String,
    pub status: Option<String>, 
    pub shadow_mode: Option<bool>, 
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Serialize)]
pub struct GenerateKeyResponse {
    pub api_key: String,
    pub hmac_secret: String,
}

#[derive(Deserialize)]
pub struct RevokeKeyRequest {
    pub api_key: String,
}

#[derive(Serialize)]
pub struct MigrationResponse {
    pub migrated_count: u64,
    pub skipped_count: u64,
}

pub async fn generate_client_key_handler(
    Extension(state): Extension<SharedState>,
) -> Result<(StatusCode, Json<GenerateKeyResponse>), AppError> {
    let kms_key_id = std::env::var("KMS_CMK_ID").map_err(|_| anyhow::anyhow!("KMS_CMK_ID not configured"))?;
    
    let api_key: String = thread_rng().sample_iter(&Alphanumeric).take(32).map(char::from).collect();
    let api_key = format!("pk_live_{}", api_key);

    // 1. Generate an alphanumeric string to match Flutter's expected `utf8.encode(hmacSecret)` logic
    let hmac_secret: String = thread_rng().sample_iter(&Alphanumeric).take(64).map(char::from).collect();

    // 2. Explicitly encrypt the UTF-8 bytes to generate the KMS Blob
    let kms_helper = crate::kms::KmsHelper::new(state.kms_client.clone(), state.key_cache.clone());
    let ciphertext_blob = kms_helper.encrypt(&kms_key_id, hmac_secret.as_bytes()).await
        .map_err(|e| anyhow::anyhow!("KMS Encryption failed: {}", e))?;

    let default_policy = serde_json::json!({
        "enabled": false,
        "grace_seconds": 300,
        "allowed_endpoints": ["/verify", "/heartbeat"],
        "rate_per_minute": 60
    });

    let mut tx = state.pool.begin().await.map_err(|e| anyhow::anyhow!("Tx init failed: {}", e))?;

    let record = sqlx::query!(
        "INSERT INTO api_clients (api_key, status, shadow_mode, offline_policy) VALUES ($1, 'active', true, $2) RETURNING client_id",
        api_key, default_policy
    )
    .fetch_one(&mut *tx).await.map_err(|e| anyhow::anyhow!("Client Insert Error: {}", e))?;
    
    // 3. Insert the true KMS ciphertext into the database
    sqlx::query!(
        "INSERT INTO api_client_secrets (api_client_id, secret_wrapped) VALUES ($1, $2)",
        record.client_id, ciphertext_blob
    )
    .execute(&mut *tx).await.map_err(|e| anyhow::anyhow!("Secret Insert Error: {}", e))?;

    tx.commit().await.map_err(|e| anyhow::anyhow!("Tx Commit failed: {}", e))?;

    Ok((StatusCode::CREATED, Json(GenerateKeyResponse { api_key, hmac_secret })))
}

pub async fn revoke_client_key_handler(
    Extension(state): Extension<SharedState>,
    Json(payload): Json<RevokeKeyRequest>,
) -> Result<StatusCode, AppError> {
    let mut tx = state.pool.begin().await.map_err(|e| anyhow::anyhow!("Tx init failed: {}", e))?;

    let result = sqlx::query!("UPDATE api_clients SET status = 'revoked', revoked_at = NOW() WHERE api_key = $1", payload.api_key)
        .execute(&mut *tx).await.map_err(|e| anyhow::anyhow!("DB Error: {}", e))?;

    if result.rows_affected() == 0 {
        return Ok(StatusCode::NOT_FOUND);
    }

    sqlx::query!("UPDATE api_client_certs SET revoked = true WHERE api_client_id = (SELECT client_id FROM api_clients WHERE api_key = $1)", payload.api_key)
        .execute(&mut *tx).await.map_err(|e| anyhow::anyhow!("Cert Revoke Error: {}", e))?;

    sqlx::query!("UPDATE api_client_secrets SET active = false WHERE api_client_id = (SELECT client_id FROM api_clients WHERE api_key = $1)", payload.api_key)
        .execute(&mut *tx).await.map_err(|e| anyhow::anyhow!("Secret Revoke Error: {}", e))?;

    tx.commit().await.map_err(|e| anyhow::anyhow!("Tx Commit failed: {}", e))?;

    Ok(StatusCode::OK)
}

pub async fn list_client_keys_handler(
    Extension(state): Extension<SharedState>,
) -> Result<Json<Vec<ApiClientRecord>>, AppError> {
    let records = sqlx::query_as!(
        ApiClientRecord,
        "SELECT client_id, api_key, status, shadow_mode, created_at FROM api_clients ORDER BY created_at DESC LIMIT 100"
    )
    .fetch_all(&state.pool).await.map_err(|e| anyhow::anyhow!("DB Error: {}", e))?;

    Ok(Json(records))
}

/// One-off migration endpoint to repair the V2 migration contamination.
/// Finds raw plaintext secrets, encrypts them via KMS, and saves the ciphertext.
pub async fn migrate_legacy_secrets_handler(
    Extension(state): Extension<SharedState>,
) -> Result<(StatusCode, Json<MigrationResponse>), AppError> {
    let kms_key_id = std::env::var("KMS_CMK_ID").map_err(|_| anyhow::anyhow!("KMS_CMK_ID not configured"))?;
    let kms_helper = crate::kms::KmsHelper::new(state.kms_client.clone(), state.key_cache.clone());

    let records = sqlx::query!("SELECT secret_id, secret_wrapped FROM api_client_secrets WHERE active = true")
        .fetch_all(&state.pool)
        .await
        .map_err(|e| anyhow::anyhow!("DB Fetch Error: {}", e))?;

    let mut migrated_count = 0;
    let mut skipped_count = 0;

    for record in records {
        // AWS KMS ciphertexts for AES-256 Data Keys are typically ~180+ bytes.
        // If it's under 150 bytes, it is definitively a raw UTF-8 plaintext string.
        if record.secret_wrapped.len() < 150 {
            let ciphertext_blob = kms_helper.encrypt(&kms_key_id, &record.secret_wrapped).await
                .map_err(|e| anyhow::anyhow!("KMS Encryption failed during migration: {}", e))?;

            sqlx::query!(
                "UPDATE api_client_secrets SET secret_wrapped = $1 WHERE secret_id = $2",
                ciphertext_blob, record.secret_id
            )
            .execute(&state.pool)
            .await
            .map_err(|e| anyhow::anyhow!("DB Update Error: {}", e))?;

            migrated_count += 1;
        } else {
            skipped_count += 1;
        }
    }

    Ok((StatusCode::OK, Json(MigrationResponse { migrated_count, skipped_count })))
}