// crates/invariant_engine/src/core.rs
/*
 * Copyright (c) 2026 Invariant Protocol.
 *
 * This source code is licensed under the Business Source License (BSL 1.1) 
 * found in the LICENSE.md file in the root directory of this source tree.
 */

use invariant_shared::{Heartbeat, IdentityStatus, GenesisRequest, ReAttestationRequest, Identity, Network};
use crate::ports::{IdentityStorage, NonceStorage};
use crate::error::EngineError;
use crate::crypto;        
use crate::attestation; 
use chrono::{Utc, Duration};
use uuid::Uuid;

const MAX_TIMESTAMP_DRIFT_SECONDS: i64 = 120; // 2 Minutes
const ATTESTATION_TTL_DAYS: i64 = 7; // 🛡️ TRUST DECAY: Re-prove hardware every 7 days

#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub network: Network,
    pub genesis_version: u16,
}

pub struct InvariantEngine<S: IdentityStorage, N: NonceStorage> {
    storage: S,
    nonce_storage: N, // 🛡️ NEW
    config: EngineConfig, 
}

impl<S: IdentityStorage, N: NonceStorage> InvariantEngine<S, N> {
    pub fn new(storage: S, nonce_storage: N, config: EngineConfig) -> Self { 
        Self { storage, nonce_storage, config } 
    }
    
    pub fn get_storage(&self) -> &S { &self.storage }

    pub async fn check_identity(&self, id: Uuid) -> Result<bool, EngineError> {
        let identity = self.storage.get_identity(&id).await?;
        Ok(identity.is_some())
    }

    pub async fn process_genesis(&self, request: GenesisRequest) -> Result<Identity, EngineError> {
        // 1. Cheap Check
        if let Some(existing) = self.storage.get_identity_by_public_key(&request.public_key).await? {
            return Ok(existing); 
        }

        // 2. Expensive Check (Hardware Attestation)
        let metadata = attestation::validate_attestation_chain(
            &request.attestation_chain, 
            &request.public_key,
            Some(&request.nonce)
        )?;

        // 🛡️ MERGE LOGIC: Hardware Truth > Software Fallback
        // If the TEE didn't provide hardware IDs, we gracefully degrade to the OS-reported strings.
        let final_brand = metadata.brand.or(request.software_brand);
        let final_device = metadata.device.or(request.software_model);
        let final_product = metadata.product.or(request.software_product);

        // 3. Construct Identity
        let now = Utc::now();
        let identity = Identity {
            id: Uuid::new_v4(),
            public_key: request.public_key,
            continuity_score: 0,
            streak: 0,
            is_genesis_eligible: false,
            username: None,
            fcm_token: None, 
            created_at: now,
            last_heartbeat: now,
            last_attestation: now, // 🛡️ Initialize Trust Timer
            status: IdentityStatus::Active,
            
            // Assign the resolved metadata
            hardware_brand: final_brand,
            hardware_device: final_device,
            hardware_product: final_product,
            
            genesis_version: self.config.genesis_version,
            network: self.config.network.clone(),
        };

        // 4. Persistence
        self.storage.save_identity(&identity).await?;
        
        Ok(identity)
    }

    /// The "Secure Tap" Verification Processor
    pub async fn process_heartbeat(&self, heartbeat: Heartbeat) -> Result<u64, EngineError> {
        let identity = self.storage
            .get_identity(&heartbeat.identity_id)
            .await?
            .ok_or(EngineError::IdentityNotFound(heartbeat.identity_id))?;

        if identity.status == IdentityStatus::Revoked {
             return Err(EngineError::Storage("Identity is Revoked".into()));
        }

        // 🛡️ 1. NONCE FINALITY (Anti-Replay)
        if !self.nonce_storage.consume_nonce(&heartbeat.nonce, 300).await? {
            return Err(EngineError::ReplayDetected);
        }

        // 🛡️ 2. TRUST DECAY CHECK (Anti-Rooting Persistence)
        let days_since_attest = Utc::now()
            .signed_duration_since(identity.last_attestation)
            .num_days();

        if days_since_attest > ATTESTATION_TTL_DAYS {
            return Err(EngineError::AttestationRequired);
        }

        // 3. RATE LIMIT CHECK (Cheap Rejection)
        let min_interval = Duration::minutes(1380); // 23 Hours
        
        if identity.continuity_score > 0 {
            let time_since_last = heartbeat.timestamp.signed_duration_since(identity.last_heartbeat);
            if time_since_last < min_interval {
                 return Err(EngineError::RateLimitExceeded);
            }
        }

        // 4. NONCE-BOUND CRYPTO CHECK
        let payload_str = format!("{}|{}|{}", 
            heartbeat.identity_id, 
            hex::encode(&heartbeat.nonce),
            heartbeat.timestamp.to_rfc3339()
        );
        
        crypto::verify_signature(
            &identity.public_key,
            payload_str.as_bytes(),
            &heartbeat.device_signature
        )?;

        // 5. TIMESTAMP SANITY CHECK
        let now = Utc::now();
        let sig_age = now.signed_duration_since(heartbeat.timestamp);
        
        if sig_age.num_seconds() > MAX_TIMESTAMP_DRIFT_SECONDS {
             return Err(EngineError::StaleHeartbeat(format!("Timestamp too old (>{}s)", MAX_TIMESTAMP_DRIFT_SECONDS)));
        }
        if sig_age.num_seconds() < -30 {
            return Err(EngineError::StaleHeartbeat("Timestamp in the future (>30s)".into()));
        }

        // 6. Update Score
        let new_score = self.storage.log_heartbeat(&identity, &heartbeat).await?;
        Ok(new_score)
    }

    /// 🛡️ NEW: Trust Refresh Handler
    pub async fn process_reattestation(&self, request: ReAttestationRequest) -> Result<(), EngineError> {
        // 1. Verify Binding (Identity must exist)
        let mut identity = self.storage.get_identity(&request.id).await?
            .ok_or(EngineError::IdentityNotFound(request.id))?;

        // 2. Verify Key Continuity (Must match registered key)
        if identity.public_key != request.public_key {
            return Err(EngineError::InvalidAttestation("Public Key mismatch during re-attestation".into()));
        }

        // 3. Verify Hardware Attestation (Expensive)
        attestation::validate_attestation_chain(
            &request.attestation_chain, 
            &request.public_key,
            Some(&request.nonce)
        )?;

        // 4. Refresh Trust Timer
        identity.last_attestation = Utc::now();
        if identity.status == IdentityStatus::Stale {
            identity.status = IdentityStatus::Active;
        }
        
        // 5. Persistence
        self.storage.save_identity(&identity).await?;
        
        Ok(())
    }

    pub async fn validate_action_signature(
        &self, 
        identity_id: Uuid, 
        payload_hash: &[u8],
        nonce: &[u8],
        signature: &[u8]
    ) -> Result<bool, EngineError> {
        let identity = self.storage
            .get_identity(&identity_id)
            .await?
            .ok_or(EngineError::IdentityNotFound(identity_id))?;

        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(nonce);
        signed_data.extend_from_slice(payload_hash);

        match crypto::verify_signature(
            &identity.public_key, 
            &signed_data, 
            signature
        ) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}