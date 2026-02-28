// crates/invariant_shared/src/genesis.rs
/*
 * Copyright (c) 2026 Invariant Protocol
 * Use of this software is governed by the MIT License.
 */

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// The initial payload to create a new Identity.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)] 
pub struct GenesisRequest {
    /// The P-256 Public Key generated in StrongBox/TEE.
    pub public_key: Vec<u8>,

    /// The Android KeyStore Attestation Certificate Chain.
    pub attestation_chain: Vec<Vec<u8>>,

    /// The cryptographic nonce (challenge) issued by the server.
    pub nonce: Vec<u8>,

    /// 🛡️ FALLBACK: The OS-reported brand (if hardware attestation omits it)
    #[serde(default)]
    pub software_brand: Option<String>,

    /// 🛡️ FALLBACK: The OS-reported model
    #[serde(default)]
    pub software_model: Option<String>,

    /// 🛡️ FALLBACK: The OS-reported product code
    #[serde(default)]
    pub software_product: Option<String>,
}