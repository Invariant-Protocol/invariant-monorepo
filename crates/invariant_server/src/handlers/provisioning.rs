// crates/invariant_server/src/handlers/provisioning.rs
/*
 * Copyright (c) 2026 Invariant Protocol.
 *
 * This source code is licensed under the Business Source License (BSL 1.1) 
 * found in the LICENSE.md file in the root directory of this source tree.
 */

use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use crate::state::SharedState;
use crate::error_response::AppError;
use crate::auth::ValidatedClient;
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
    pub shadow_mode: bool,
    pub offline_policy: Option<serde_json::Value>, 
}

pub async fn provision_sdk_handler(
    Extension(state): Extension<SharedState>,
    Extension(client): Extension<ValidatedClient>,
    Json(payload): Json<ProvisionRequest>,
) -> Result<Json<ProvisioningResponse>, AppError> {
    
    // The middleware has already cryptographically verified the client's API Key and HMAC signature.
    if client.api_key != payload.api_key {
        return Err(anyhow::anyhow!("Payload API Key mismatch").into());
    }

    // Retrieve the offline policy to return to the SDK
    let record = sqlx::query!(
        "SELECT offline_policy FROM api_clients WHERE client_id = $1",
        client.client_id
    )
    .fetch_one(&state.pool).await.map_err(|e| anyhow::anyhow!("DB Error: {}", e))?;

    // Load Server's Root CA 
    let ca_cert_pem = std::fs::read_to_string("certs/ca.crt").map_err(|_| anyhow::anyhow!("CA Cert missing"))?;
    let ca_key_pem = std::fs::read_to_string("certs/ca.key").map_err(|_| anyhow::anyhow!("CA Key missing"))?;
    
    let ca_keypair = KeyPair::from_pem(&ca_key_pem).map_err(|_| anyhow::anyhow!("Invalid CA Key"))?;
    let ca_cert_params = CertificateParams::from_ca_cert_pem(&ca_cert_pem, ca_keypair)
        .map_err(|_| anyhow::anyhow!("Failed to load CA Params"))?;
    
    let ca_cert = Certificate::from_params(ca_cert_params)
        .map_err(|_| anyhow::anyhow!("Failed to initialize CA Certificate"))?;

    // Sign the SDK's CSR
    let sdk_csr = rcgen::CertificateSigningRequest::from_pem(&payload.csr_pem)
        .map_err(|_| anyhow::anyhow!("Invalid CSR provided by SDK"))?;
    
    let client_cert = sdk_csr.serialize_der_with_signer(&ca_cert)
        .map_err(|_| anyhow::anyhow!("Failed to sign cert"))?;
    
    let client_cert_pem = pem::encode(&pem::Pem::new("CERTIFICATE", client_cert));
    let cert_fingerprint = hex::encode(Sha256::digest(client_cert_pem.as_bytes()));

    // Insert Cert into Lifecycle Table
    sqlx::query("INSERT INTO api_client_certs (api_client_id, fingerprint, raw_pem) VALUES ($1, $2, $3)")
        .bind(client.client_id)
        .bind(cert_fingerprint)
        .bind(&client_cert_pem)
        .execute(&state.pool).await.map_err(|e| anyhow::anyhow!("DB Error: {}", e))?;

    tracing::info!("✅ Provisioned new mTLS Cert for SDK: {}", client.api_key);

    // Notice we DO NOT return the hmac_secret. The client proved they already have it.
    Ok(Json(ProvisioningResponse {
        client_certificate_pem: client_cert_pem,
        shadow_mode: client.shadow_mode,
        offline_policy: record.offline_policy,
    }))
}