// crates/invariant_server/src/auth.rs
/*
 * Copyright (c) 2026 Invariant Protocol.
 *
 * This source code is licensed under the Business Source License (BSL 1.1) 
 * found in the LICENSE.md file in the root directory of this source tree.
 */

use axum::{
    extract::Request,
    http::{StatusCode, header::HeaderMap},
    middleware::Next,
    response::Response,
    Extension,
};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use redis::AsyncCommands;
use crate::state::SharedState;

type HmacSha256 = Hmac<Sha256>;

#[allow(dead_code)]
#[derive(serde::Deserialize, Debug, Clone)]
pub struct OfflinePolicy {
    pub enabled: bool,
    pub grace_seconds: i64,
    pub allowed_endpoints: Vec<String>,
    pub rate_per_minute: u64,
}

#[allow(dead_code)]
#[derive(Clone)]
pub struct ValidatedClient {
    pub client_id: uuid::Uuid,
    pub api_key: String,
    pub is_offline_fallback: bool,
    pub shadow_mode: bool,
}

// 🛡️ Admin Route Protection
pub async fn admin_auth_middleware(
    Extension(state): Extension<SharedState>,
    headers: HeaderMap,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = headers.get("Authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if auth_header == format!("Bearer {}", state.admin_secret) {
        Ok(next.run(req).await)
    } else {
        tracing::warn!("🚨 Unauthorized access attempt to /admin router");
        Err(StatusCode::UNAUTHORIZED)
    }
}

pub async fn verify_hmac_middleware(
    Extension(state): Extension<SharedState>,
    headers: HeaderMap,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let api_key = headers.get("X-Invariant-ApiKey").and_then(|v| v.to_str().ok()).ok_or(StatusCode::UNAUTHORIZED)?;
    let timestamp_str = headers.get("X-Invariant-Timestamp").and_then(|v| v.to_str().ok()).ok_or(StatusCode::UNAUTHORIZED)?;
    let nonce = headers.get("X-Invariant-Nonce").and_then(|v| v.to_str().ok()).ok_or(StatusCode::UNAUTHORIZED)?;
    let signature = headers.get("X-Invariant-Signature").and_then(|v| v.to_str().ok()).ok_or(StatusCode::UNAUTHORIZED)?;
    let is_offline_req = headers.get("X-Invariant-Offline").and_then(|v| v.to_str().ok()) == Some("true");

    let decoded_sig = hex::decode(signature).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let client_ts: u64 = timestamp_str.parse().map_err(|_| StatusCode::UNAUTHORIZED)?;
    let server_ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    if client_ts.abs_diff(server_ts) > 300 {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // 🛡️ Identity Binding & Observability
    // Tracks if the request was terminated at an AWS Edge or natively by Rustls
    let (peer_fingerprint, routing_source) = if let Some(v) = headers.get("x-amzn-mtls-clientcert-thumbprint") {
        (v.to_str().ok().map(|s| s.to_string()), "AWS_ALB")
    } else if let Some(v) = headers.get("X-Client-Cert-Fingerprint") {
        (v.to_str().ok().map(|s| s.to_string()), "NATIVE_SDK")
    } else {
        (None, "UNKNOWN")
    };

    let peer_fingerprint = peer_fingerprint.ok_or_else(|| {
        tracing::error!("Missing mTLS fingerprint for API Key: {}. (SDK must explicitly send X-Client-Cert-Fingerprint when bypassing ALB)", api_key);
        StatusCode::UNAUTHORIZED
    })?;

    tracing::debug!(
        api_key = %api_key,
        source = %routing_source,
        "Resolving mTLS Identity"
    );

    let record = sqlx::query!(
        r#"
        SELECT 
            ac.client_id, 
            ac.shadow_mode, 
            ac.offline_policy,
            ac.rate_limit_per_hour,
            acs.secret_wrapped
        FROM api_clients ac
        JOIN api_client_certs acc ON ac.client_id = acc.api_client_id
        JOIN api_client_secrets acs ON ac.client_id = acs.api_client_id
        WHERE ac.api_key = $1 
          AND ac.status = 'active'
          AND acc.fingerprint = $2
          AND acc.revoked = false
          AND acs.active = true
        "#,
        api_key,
        peer_fingerprint
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .ok_or(StatusCode::UNAUTHORIZED)?;

    if is_offline_req {
        let policy: OfflinePolicy = match record.offline_policy {
            Some(json) => serde_json::from_value(json).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
            None => return Err(StatusCode::FORBIDDEN),
        };

        if !policy.enabled { return Err(StatusCode::FORBIDDEN); }

        let path = req.uri().path();
        if !policy.allowed_endpoints.iter().any(|e| path.starts_with(e)) {
            return Err(StatusCode::FORBIDDEN);
        }

        let mut conn = state.redis.get_multiplexed_async_connection().await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let minute_window = server_ts / 60;
        let rate_key = format!("offline_rate:{}:{}", api_key, minute_window);

        let current_usage: u64 = conn.incr(&rate_key, 1).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        if current_usage == 1 {
            let _: () = conn.expire(&rate_key, 60).await.unwrap_or(());
        }

        if current_usage > policy.rate_per_minute {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }

        let snapshot_str = headers.get("X-Invariant-Offline-Snapshot").and_then(|v| v.to_str().ok()).unwrap_or("{}");
        let parsed_snapshot: serde_json::Value = serde_json::from_str(snapshot_str).unwrap_or_else(|_| serde_json::json!({}));
            
        let api_key_clone = api_key.to_string();
        let path_clone = path.to_string();
        let pool = state.pool.clone();

        tokio::spawn(async move {
            let _ = sqlx::query!(
                "INSERT INTO api_client_offline_audit (api_key, endpoint, snapshot_payload) VALUES ($1, $2, $3)",
                api_key_clone, path_clone, parsed_snapshot
            )
            .execute(&pool).await;
        });
    }

    let mut conn = state.redis.get_multiplexed_async_connection().await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let nonce_key = format!("invariant:nonce:{}:{}", api_key, nonce);
    
    let is_new: bool = redis::cmd("SET").arg(&nonce_key).arg("1").arg("NX").arg("EX").arg(300)
        .query_async(&mut conn).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if !is_new {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let (parts, body) = req.into_parts();
    
    let bytes = axum::body::to_bytes(body, 1_048_576).await.map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;

    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let body_hash = hex::encode(hasher.finalize());

    let host = headers.get("host").and_then(|v| v.to_str().ok()).unwrap_or("16.171.151.222");
    let canonical_string = format!(
        "{}\n{}\n{}\nhost:{}\n{}\n{}\n{}",
        parts.method.as_str(), parts.uri.path(), parts.uri.query().unwrap_or(""), host, body_hash, timestamp_str, nonce
    );

    let mut mac = HmacSha256::new_from_slice(&record.secret_wrapped).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    mac.update(canonical_string.as_bytes());

    let is_shadow = record.shadow_mode.unwrap_or(false);
    if mac.verify_slice(&decoded_sig).is_err() {
        if !is_shadow { return Err(StatusCode::UNAUTHORIZED); }
    }

    let pool_clone = state.pool.clone();
    let cid = record.client_id;
    tokio::spawn(async move {
        let _ = sqlx::query!("UPDATE api_clients SET last_used = NOW() WHERE client_id = $1", cid)
            .execute(&pool_clone).await;
    });

    let mut req = Request::from_parts(parts, axum::body::Body::from(bytes));
    
    req.extensions_mut().insert(ValidatedClient {
        client_id: record.client_id,
        api_key: api_key.to_string(),
        is_offline_fallback: is_offline_req,
        shadow_mode: is_shadow,
    });

    Ok(next.run(req).await)
}