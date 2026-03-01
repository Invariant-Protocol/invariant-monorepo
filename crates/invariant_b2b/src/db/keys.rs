// crates/invariant_b2b/src/db/keys.rs
/*
 * Copyright (c) 2026 Invariant Protocol.
 */

use sqlx::PgPool;
use uuid::Uuid;
use crate::error::B2bError;
use crate::auth::rls_layer::TenantContext;
use crate::models::dto::{CreateApiKeyRequest, ApiKeyResponse};
use rand::{Rng, thread_rng};
use rand::distributions::Alphanumeric;

pub async fn create_api_key(
    pool: &PgPool,
    ctx: &TenantContext,
    req: &CreateApiKeyRequest,
) -> Result<ApiKeyResponse, B2bError> {
    
    let mut tx = ctx.begin_rls_tx(pool).await?;

    let key_val: String = thread_rng().sample_iter(&Alphanumeric).take(32).map(char::from).collect();
    let api_key_str = format!("pk_live_{}", key_val);
    let secret: String = thread_rng().sample_iter(&Alphanumeric).take(64).map(char::from).collect();
    let prefix = &api_key_str[0..12];

    // 🛡️ FIX: Cast 'active' to key_status, and cast the returned status to text!
    let record = sqlx::query!(
        r#"
        INSERT INTO b2b_api_keys (org_id, name, key_prefix, status, enforcement_mode, created_by)
        VALUES ($1, $2, $3, 'active'::key_status, $4, $5)
        RETURNING id, name, key_prefix, status::text as "status!", enforcement_mode, created_at
        "#,
        ctx.org_id,
        req.name,
        prefix,
        req.enforcement_mode,
        ctx.user_id
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(B2bError::Database)?;

    let payload = serde_json::json!({
        "b2b_key_id": record.id,
        "full_api_key": api_key_str,
        "plaintext_secret": secret,
        "mode": req.enforcement_mode
    });

    sqlx::query!(
        r#"
        INSERT INTO b2b_event_outbox (aggregate_type, aggregate_id, event_type, payload)
        VALUES ('ApiKey', $1, 'KeyProvisioned', $2)
        "#,
        record.id,
        payload
    )
    .execute(&mut *tx)
    .await
    .map_err(B2bError::Database)?;

    tx.commit().await.map_err(B2bError::Database)?;

    Ok(ApiKeyResponse {
        id: record.id,
        name: record.name,
        key_prefix: api_key_str, 
        status: record.status, // 🛡️ FIX: No longer needs .to_string()
        enforcement_mode: record.enforcement_mode,
        created_at: record.created_at,
        plaintext_secret: Some(secret),
    })
}

pub async fn list_api_keys(
    pool: &PgPool,
    ctx: &TenantContext,
) -> Result<Vec<ApiKeyResponse>, B2bError> {
    
    let mut tx = ctx.begin_rls_tx(pool).await?;

    // 🛡️ FIX: Cast to text and enforce non-null with "status_str!"
    let records = sqlx::query!(
        r#"
        SELECT id, name, key_prefix, status::text as "status_str!", enforcement_mode, created_at
        FROM b2b_api_keys
        ORDER BY created_at DESC
        "#
    )
    .fetch_all(&mut *tx)
    .await
    .map_err(B2bError::Database)?;

    tx.commit().await.map_err(B2bError::Database)?;

    let keys = records.into_iter().map(|r| ApiKeyResponse {
        id: r.id,
        name: r.name,
        key_prefix: r.key_prefix,
        status: r.status_str,
        enforcement_mode: r.enforcement_mode,
        created_at: r.created_at,
        plaintext_secret: None, 
    }).collect();

    Ok(keys)
}

pub async fn revoke_api_key(
    pool: &PgPool,
    ctx: &TenantContext,
    key_id: Uuid,
    reason: &str,
) -> Result<(), B2bError> {
    
    let mut tx = ctx.begin_rls_tx(pool).await?;

    let result = sqlx::query!(
        r#"
        UPDATE b2b_api_keys 
        SET status = 'revoked', revoked_at = NOW() 
        WHERE id = $1 AND status = 'active'
        "#,
        key_id
    )
    .execute(&mut *tx)
    .await
    .map_err(B2bError::Database)?;

    if result.rows_affected() == 0 {
        return Err(B2bError::NotFound("Key not found or already revoked".into()));
    }

    let payload = serde_json::json!({
        "b2b_key_id": key_id,
        "reason": reason,
        "revoked_by": ctx.user_id
    });

    sqlx::query!(
        r#"
        INSERT INTO b2b_event_outbox (aggregate_type, aggregate_id, event_type, payload)
        VALUES ('ApiKey', $1, 'KeyRevoked', $2)
        "#,
        key_id,
        payload
    )
    .execute(&mut *tx)
    .await
    .map_err(B2bError::Database)?;

    tx.commit().await.map_err(B2bError::Database)?;
    Ok(())
}