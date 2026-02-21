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
use crate::state::SharedState;

type HmacSha256 = Hmac<Sha256>;

pub async fn verify_hmac_middleware(
    Extension(state): Extension<SharedState>,
    headers: HeaderMap,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // 1. Extract Required Headers
    let api_key = headers.get("X-Invariant-ApiKey").and_then(|v| v.to_str().ok()).ok_or(StatusCode::UNAUTHORIZED)?;
    let timestamp_str = headers.get("X-Invariant-Timestamp").and_then(|v| v.to_str().ok()).ok_or(StatusCode::UNAUTHORIZED)?;
    let nonce = headers.get("X-Invariant-Nonce").and_then(|v| v.to_str().ok()).ok_or(StatusCode::UNAUTHORIZED)?;
    let signature = headers.get("X-Invariant-Signature").and_then(|v| v.to_str().ok()).ok_or(StatusCode::UNAUTHORIZED)?;
    let mode = headers.get("X-Invariant-Mode").and_then(|v| v.to_str().ok()).unwrap_or("enforce");

    // Decode incoming hex signature early (fail-closed)
    let decoded_sig = match hex::decode(signature) {
        Ok(bytes) => bytes,
        Err(_) => {
            tracing::warn!("Invalid hex signature format for API Key: {}", api_key);
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    // 2. Validate Timestamp Skew (Strict 300-second TTL)
    let client_ts: u64 = timestamp_str.parse().map_err(|_| StatusCode::UNAUTHORIZED)?;
    let server_ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    if client_ts.abs_diff(server_ts) > 300 {
        tracing::warn!("Request rejected: Timestamp skew exceeded 300 seconds.");
        return Err(StatusCode::UNAUTHORIZED);
    }

    // 3. Prevent Replay Attacks using Atomic Redis Execution
    let mut conn = state.redis.get_multiplexed_async_connection().await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let redis_key = format!("invariant:nonce:{}", nonce);
    
    let is_new: bool = redis::cmd("SET").arg(&redis_key).arg("1").arg("NX").arg("EX").arg(300)
        .query_async(&mut conn).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if !is_new {
        tracing::error!("Replay attack detected. Nonce {} already consumed.", nonce);
        return Err(StatusCode::UNAUTHORIZED);
    }

    // 4. Secure Lookup of HMAC Symmetric Secret
    let secret_record = sqlx::query!("SELECT hmac_secret FROM api_clients WHERE api_key = $1 AND status = 'active'", api_key)
        .fetch_optional(&state.pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let secret = match secret_record {
        Some(record) => record.hmac_secret,
        None => {
            tracing::warn!("Invalid or revoked API Key: {}", api_key);
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    // 5. Extract and Hash the HTTP Request Body
    let (parts, body) = req.into_parts();
    let bytes = axum::body::to_bytes(body, usize::MAX).await.map_err(|_| StatusCode::BAD_REQUEST)?;

    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let body_hash = hex::encode(hasher.finalize());

    // 6. Construct the Canonical String
    let method = parts.method.as_str();
    let path = parts.uri.path();
    let query = parts.uri.query().unwrap_or("");
    
    let host = headers.get("host").and_then(|v| v.to_str().ok()).unwrap_or("16.171.151.222");
    
    let canonical_string = format!(
        "{}\n{}\n{}\nhost:{}\n{}\n{}\n{}",
        method, path, query, host, body_hash, timestamp_str, nonce
    );

    // 7 & 8. Compute HMAC and Perform Constant-Time Comparison
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    mac.update(canonical_string.as_bytes());

    if mac.verify_slice(&decoded_sig).is_err() {
        tracing::warn!("Signature mismatch for API Key: {}", api_key);
        if mode == "enforce" {
            return Err(StatusCode::UNAUTHORIZED);
        } else {
            tracing::info!("Shadow Mode: Permitting invalid signature for telemetry.");
        }
    }

    // 9. Reconstruct the request and pass execution to the inner service
    let req = Request::from_parts(parts, axum::body::Body::from(bytes));
    Ok(next.run(req).await)
}