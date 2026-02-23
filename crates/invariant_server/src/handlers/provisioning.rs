// crates/invariant_server/src/handlers/provisioning.rs
/*
 * Copyright (c) 2026 Invariant Protocol.
 */

use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use crate::state::SharedState;
use crate::error_response::AppError;
use sha2::{Sha256, Digest};
use rcgen::{CertificateParams, KeyPair, Certificate};

#[derive(Deserialize)]
pub struct ProvisionRequest {
    pub api_key: String,
    pub csr_pem: String,
}

#[derive(Serialize)]
pub struct ProvisioningResponse {
    pub client_certificate_pem: String,
    pub hmac_secret: String,
    pub shadow_mode: bool,
    pub offline_policy: Option<serde_json::Value>, 
}

pub async fn provision_sdk_handler(
    Extension(state): Extension<SharedState>,
    Json(payload): Json<ProvisionRequest>,
) -> Result<Json<ProvisioningResponse>, AppError> {
    
    // 1. Verify API Key and fetch linked Active Secret
    let record: Option<(uuid::Uuid, String, bool, Option<serde_json::Value>, Vec<u8>)> = sqlx::query_as(
        r#"
        SELECT ac.client_id, ac.status, ac.shadow_mode, ac.offline_policy, acs.secret_wrapped
        FROM api_clients ac
        JOIN api_client_secrets acs ON ac.client_id = acs.api_client_id
        WHERE ac.api_key = $1 AND acs.active = true
        "#
    )
    .bind(&payload.api_key)
    .fetch_optional(&state.pool).await.map_err(|e| anyhow::anyhow!("DB Error: {}", e))?;

    let (client_id, status, shadow_mode, offline_policy, secret_wrapped) = record
        .ok_or_else(|| anyhow::anyhow!("Invalid API Key or No Active Secret"))?;

    if status != "active" {
        return Err(anyhow::anyhow!("API Key revoked").into());
    }

    let hmac_secret_str = String::from_utf8(secret_wrapped)
        .map_err(|_| anyhow::anyhow!("Failed to decode HMAC secret bytes"))?;

    // 3. Load Server's Root CA (Reads from disk, binds private key, initializes CA)
    let ca_cert_pem = std::fs::read_to_string("certs/ca.crt").map_err(|_| anyhow::anyhow!("CA Cert missing"))?;
    let ca_key_pem = std::fs::read_to_string("certs/ca.key").map_err(|_| anyhow::anyhow!("CA Key missing"))?;
    
    let ca_keypair = KeyPair::from_pem(&ca_key_pem).map_err(|_| anyhow::anyhow!("Invalid CA Key"))?;
    let ca_cert_params = CertificateParams::from_ca_cert_pem(&ca_cert_pem, ca_keypair)
        .map_err(|_| anyhow::anyhow!("Failed to load CA Params"))?;
    
    // 🛡️ FIXED: Build the finalized Certificate object required for signing
    let ca_cert = Certificate::from_params(ca_cert_params)
        .map_err(|_| anyhow::anyhow!("Failed to initialize CA Certificate"))?;

    // 4. Sign the SDK's CSR using the CA Certificate
    let sdk_csr = rcgen::CertificateSigningRequest::from_pem(&payload.csr_pem)
        .map_err(|_| anyhow::anyhow!("Invalid CSR provided by SDK"))?;
    
    // 🛡️ FIXED: Pass the `&Certificate` reference to match expected type signature
    let client_cert = sdk_csr.serialize_der_with_signer(&ca_cert)
        .map_err(|_| anyhow::anyhow!("Failed to sign cert"))?;
    
    let client_cert_pem = pem::encode(&pem::Pem::new("CERTIFICATE", client_cert));

    let cert_fingerprint = hex::encode(Sha256::digest(client_cert_pem.as_bytes()));

    // 5. Insert Cert into Lifecycle Table (Links Cert to Client)
    sqlx::query("INSERT INTO api_client_certs (api_client_id, fingerprint, raw_pem) VALUES ($1, $2, $3)")
        .bind(client_id)
        .bind(cert_fingerprint)
        .bind(&client_cert_pem)
        .execute(&state.pool).await.map_err(|e| anyhow::anyhow!("DB Error: {}", e))?;

    tracing::info!("✅ Provisioned new mTLS Cert for SDK: {}", payload.api_key);

    Ok(Json(ProvisioningResponse {
        client_certificate_pem: client_cert_pem,
        hmac_secret: hmac_secret_str,
        shadow_mode,
        offline_policy,
    }))
}