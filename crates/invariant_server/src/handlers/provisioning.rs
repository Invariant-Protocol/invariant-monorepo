// crates/invariant_server/src/handlers/provisioning.rs
/*
 * Copyright (c) 2026 Invariant Protocol.
 *
 * This module runs on the Enrollment Gate (Port 8444).
 * It authenticates SDK bootstrapping requests via physical Hardware Attestation.
 */

use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use crate::state::SharedState;
use crate::error_response::AppError;
use sha2::{Sha256, Digest};
use rcgen::{CertificateParams, KeyPair, Certificate};
use rand::{Rng, thread_rng};
use redis::AsyncCommands;
use crate::kms::KmsHelper;
use std::env;
use utoipa::ToSchema; // 🛡️ Added

#[derive(Deserialize, ToSchema)] // 🛡️ Added ToSchema
pub struct ProvisionRequest {
    pub api_key: String,
    pub csr_pem: String,
    
    // 🛡️ The True Trust Anchors for Enrollment
    pub public_key: Vec<u8>,
    pub attestation_chain: Vec<Vec<u8>>,
    pub nonce: Vec<u8>,
}

#[derive(Serialize, ToSchema)] // 🛡️ Added ToSchema
pub struct ProvisioningResponse {
    pub client_certificate_pem: String,
    pub hmac_secret: String,
    pub shadow_mode: bool,
    pub offline_policy: Option<serde_json::Value>, 
}

/// GET /provision/challenge
/// Generates a single-use 32-byte nonce bound to the TEE Attestation generation.
#[utoipa::path(
    get,
    path = "/provision/challenge",
    responses(
        (status = 200, description = "Challenge generated", body = inline(serde_json::Value))
    )
)]
pub async fn get_provision_challenge_handler(
    Extension(state): Extension<SharedState>,
) -> Result<Json<serde_json::Value>, AppError> {
    let mut conn = state.redis.get_multiplexed_async_connection().await
        .map_err(|e| anyhow::anyhow!("Redis Error: {}", e))?;

    let (nonce_hex, redis_key) = {
        let mut rng = thread_rng();
        let mut nonce_bytes = [0u8; 32];
        rng.fill(&mut nonce_bytes);
        let hex_val = hex::encode(nonce_bytes);
        (hex_val.clone(), format!("prov_nonce:{}", hex_val))
    };

    let _: () = conn.set_ex(&redis_key, "true", 300).await
        .map_err(|e| anyhow::anyhow!("Challenge Generation Failed: {}", e))?;

    Ok(Json(serde_json::json!({ "nonce": nonce_hex })))
}

/// POST /provision
/// Validates the Silicon, signs the CSR, and delegates the HMAC secret.
#[utoipa::path(
    post,
    path = "/provision",
    request_body = ProvisionRequest,
    responses(
        (status = 200, description = "Client Provisioned", body = inline(ProvisioningResponse)),
        (status = 400, description = "Invalid Attestation or Challenge"),
        (status = 401, description = "Unauthorized API Key")
    )
)]
pub async fn provision_sdk_handler(
    Extension(state): Extension<SharedState>,
    Json(payload): Json<ProvisionRequest>,
) -> Result<Json<ProvisioningResponse>, AppError> {
    
    // 1. NONCE FINALITY
    let mut conn = state.redis.get_multiplexed_async_connection().await
        .map_err(|e| anyhow::anyhow!("Redis connection failed: {}", e))?;

    let nonce_hex = hex::encode(&payload.nonce);
    let redis_key = format!("prov_nonce:{}", nonce_hex);
    
    let val: Option<String> = conn.get_del(&redis_key).await.unwrap_or(None);
    if val.is_none() {
        return Err(anyhow::anyhow!("Invalid or expired challenge").into());
    }

    // 🛡️ 2. HARDWARE VERIFICATION
    let metadata = invariant_engine::validate_attestation_chain(
        &payload.attestation_chain,
        &payload.public_key,
        Some(&payload.nonce)
    ).map_err(|e| anyhow::anyhow!("Hardware Attestation Failed: {}", e))?;

    tracing::info!(
        "Device passed hardware checks during provisioning: {} - {} [{}]", 
        metadata.brand.as_deref().unwrap_or("Unknown"), 
        metadata.device.as_deref().unwrap_or("Unknown"),
        metadata.trust_tier
    );

    // 3. FETCH CLIENT DETAILS
    let record = sqlx::query!(
        r#"
        SELECT 
            ac.client_id, 
            ac.shadow_mode, 
            ac.offline_policy,
            acs.secret_wrapped
        FROM api_clients ac
        JOIN api_client_secrets acs ON ac.client_id = acs.api_client_id
        WHERE ac.api_key = $1 
          AND ac.status = 'active'
          AND acs.active = true
        "#,
        payload.api_key
    )
    .fetch_optional(&state.pool).await.map_err(|e| anyhow::anyhow!("DB Error: {}", e))?
    .ok_or_else(|| anyhow::anyhow!("Invalid or inactive API Key"))?;

    // 4. DECRYPT HMAC SECRET VIA KMS
    let kms_helper = KmsHelper::new(state.kms_client.clone(), state.key_cache.clone());
    let key_bytes = kms_helper.decrypt_cached(&record.secret_wrapped).await
        .map_err(|_| anyhow::anyhow!("Failed to retrieve client secret"))?;
    let hmac_secret_str = String::from_utf8(key_bytes).map_err(|_| anyhow::anyhow!("Invalid secret encoding"))?;

    // 🛡️ 5. SIGN THE CSR (Memory-injected Intermediate CA)
    let ca_cert_pem = std::fs::read_to_string("certs/ca.crt").map_err(|_| anyhow::anyhow!("CA Cert missing"))?;
    let ca_key_pem = env::var("SERVER_CA_KEY_PEM")
        .map_err(|_| anyhow::anyhow!("CRITICAL: SERVER_CA_KEY_PEM not found in environment"))?;
    
    let ca_key_pem_clean = ca_key_pem.replace("\\n", "\n");

    let ca_keypair = KeyPair::from_pem(&ca_key_pem_clean).map_err(|_| anyhow::anyhow!("Invalid CA Key"))?;
    let ca_cert_params = CertificateParams::from_ca_cert_pem(&ca_cert_pem, ca_keypair)
        .map_err(|_| anyhow::anyhow!("Failed to load CA Params"))?;
    let ca_cert = Certificate::from_params(ca_cert_params)
        .map_err(|_| anyhow::anyhow!("Failed to initialize CA Certificate"))?;

    let sdk_csr = rcgen::CertificateSigningRequest::from_pem(&payload.csr_pem)
        .map_err(|_| anyhow::anyhow!("Invalid CSR provided by SDK"))?;
    
    let client_cert = sdk_csr.serialize_der_with_signer(&ca_cert)
        .map_err(|_| anyhow::anyhow!("Failed to sign cert"))?;
    
    let client_cert_pem = pem::encode(&pem::Pem::new("CERTIFICATE", client_cert));
    let cert_fingerprint = hex::encode(Sha256::digest(client_cert_pem.as_bytes()));

    // 6. REGISTER CERTIFICATE
    sqlx::query("INSERT INTO api_client_certs (api_client_id, fingerprint, raw_pem) VALUES ($1, $2, $3)")
        .bind(record.client_id)
        .bind(cert_fingerprint)
        .bind(&client_cert_pem)
        .execute(&state.pool).await.map_err(|e| anyhow::anyhow!("DB Error: {}", e))?;

    let storage = crate::db::PostgresStorage::new(state.pool.clone());
    storage.insert_client_audit(None, Some(record.client_id), "provisioned_sdk", Some("Hardware bound mTLS cert issued"), None).await;

    tracing::info!("✅ Provisioned new mTLS Cert & Delegated HMAC for SDK: {}", payload.api_key);

    Ok(Json(ProvisioningResponse {
        client_certificate_pem: client_cert_pem,
        hmac_secret: hmac_secret_str,
        shadow_mode: record.shadow_mode.unwrap_or(false),
        offline_policy: record.offline_policy,
    }))
}