// crates/invariant_b2b/src/db/outbox.rs
/*
 * Copyright (c) 2026 Invariant Protocol.
 */

use sqlx::PgPool;
use std::time::Duration;
use tracing::{info, error, warn};
use aes_gcm::{aead::{Aead, KeyInit, OsRng}, Aes256Gcm, aead::AeadCore};
use sha2::{Sha256, Digest};

fn encrypt_secret_local(admin_secret: &str, plaintext: &str) -> anyhow::Result<Vec<u8>> {
    let mut hasher = Sha256::new();
    hasher.update(admin_secret.as_bytes());
    let derived_key = hasher.finalize();

    let cipher = Aes256Gcm::new_from_slice(&derived_key)
        .map_err(|_| anyhow::anyhow!("Invalid key length derived"))?;
    
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    
    let encrypted = cipher.encrypt(&nonce, plaintext.as_bytes())
        .map_err(|_| anyhow::anyhow!("AES-GCM encryption failed"))?;
    
    let mut blob = Vec::with_capacity(12 + encrypted.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&encrypted);
    Ok(blob)
}

// 🛡️ FIX: Helper function providing a Result boundary for the `?` operator
async fn process_outbox_event(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    redis_client: &redis::Client,
    admin_secret: &str,
    event_type: &str,
    payload: &serde_json::Value,
) -> anyhow::Result<()> {
    match event_type {
        "KeyProvisioned" => {
            let api_key = payload["full_api_key"].as_str().unwrap_or_default();
            let plaintext = payload["plaintext_secret"].as_str().unwrap_or_default();
            let mode = payload["mode"].as_str().unwrap_or("shadow");
            let is_shadow = mode == "shadow";

            let ciphertext = encrypt_secret_local(admin_secret, plaintext)?;

            let default_policy = serde_json::json!({"enabled": false, "grace_seconds": 300, "allowed_endpoints": ["/verify"], "rate_per_minute": 60});

            let core_record = sqlx::query!(
                "INSERT INTO api_clients (api_key, status, shadow_mode, offline_policy) VALUES ($1, 'active', $2, $3) RETURNING client_id",
                api_key, is_shadow, default_policy
            ).fetch_one(&mut **tx).await?;

            sqlx::query!(
                "INSERT INTO api_client_secrets (api_client_id, secret_wrapped, active) VALUES ($1, $2, true)",
                core_record.client_id, ciphertext
            ).execute(&mut **tx).await?;

            info!("✅ Provisioned Key to Core Engine: {}", api_key);
            Ok(())
        },
        "KeyRevoked" => {
            let b2b_key_id = payload["b2b_key_id"].as_str().unwrap_or_default();
            let b2b_uuid = uuid::Uuid::parse_str(b2b_key_id).unwrap_or_default();

            if let Ok(b2b_record) = sqlx::query!("SELECT key_prefix FROM b2b_api_keys WHERE id = $1", b2b_uuid).fetch_one(&mut **tx).await {
                let search_pattern = format!("{}%", b2b_record.key_prefix);
                
                if let Ok(core_record) = sqlx::query!("SELECT client_id, api_key FROM api_clients WHERE api_key LIKE $1", search_pattern).fetch_one(&mut **tx).await {
                    
                    sqlx::query!("UPDATE api_clients SET status = 'revoked', revoked_at = NOW() WHERE client_id = $1", core_record.client_id).execute(&mut **tx).await?;
                    sqlx::query!("UPDATE api_client_secrets SET active = false WHERE api_client_id = $1", core_record.client_id).execute(&mut **tx).await?;
                    sqlx::query!("UPDATE api_client_certs SET revoked = true WHERE api_client_id = $1", core_record.client_id).execute(&mut **tx).await?;

                    let _ = crate::db::producer::publish_cache_invalidation(redis_client, &core_record.api_key).await;
                    info!("✅ Revoked Key in Core Engine: {}", core_record.api_key);
                }
            }
            Ok(())
        },
        _ => {
            warn!("Unknown event type: {}", event_type);
            Ok(())
        }
    }
}

pub async fn start_outbox_worker(pool: PgPool, redis_client: redis::Client, admin_secret: String) {
    info!("🚀 Transactional Outbox Worker started.");
    let mut interval = tokio::time::interval(Duration::from_secs(2));

    loop {
        interval.tick().await;
        
        let event = match sqlx::query!(
            r#"
            SELECT id, event_type, payload
            FROM b2b_event_outbox
            WHERE processed_at IS NULL
            ORDER BY created_at ASC
            FOR UPDATE SKIP LOCKED
            LIMIT 1
            "#
        )
        .fetch_optional(&pool)
        .await {
            Ok(Some(e)) => e,
            Ok(None) => continue, 
            Err(e) => {
                error!("Outbox fetch error: {}", e);
                continue;
            }
        };

        let mut tx = match pool.begin().await {
            Ok(tx) => tx,
            Err(e) => { error!("Worker tx failed: {}", e); continue; }
        };

        let result = process_outbox_event(&mut tx, &redis_client, &admin_secret, &event.event_type, &event.payload).await;

        match result {
            Ok(_) => {
                let _ = sqlx::query!("UPDATE b2b_event_outbox SET processed_at = NOW() WHERE id = $1", event.id).execute(&mut *tx).await;
            }
            Err(e) => {
                let err_str = e.to_string();
                let _ = sqlx::query!("UPDATE b2b_event_outbox SET error_log = $1 WHERE id = $2", err_str, event.id).execute(&mut *tx).await;
            }
        }
        
        let _ = tx.commit().await;
    }
}