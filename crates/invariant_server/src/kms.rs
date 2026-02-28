// crates/invariant_server/src/kms.rs
/*
 * Copyright (c) 2026 Invariant Protocol.
 *
 * KMS envelope encryption helper (AWS & Local Fallback)
 */

use anyhow::anyhow;
use aws_sdk_kms::Client as KmsClient;
use moka::future::Cache;
use base64::{engine::general_purpose, Engine as _};
use std::sync::Arc;
use aws_smithy_types::Blob as SmithyBlob;

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce as GcmNonce, aead::AeadCore
};
use sha2::{Sha256, Digest};

#[derive(Clone)]
pub struct KmsHelper {
    pub client: KmsClient,
    pub cache: Arc<Cache<String, Vec<u8>>>,
}

impl KmsHelper {
    pub fn new(client: KmsClient, cache: Cache<String, Vec<u8>>) -> Self {
        Self { client, cache: Arc::new(cache) }
    }

    /// Derives a 32-byte AES-256 key from the ADMIN_API_SECRET
    fn get_local_cipher() -> anyhow::Result<Aes256Gcm> {
        let admin_secret = std::env::var("ADMIN_API_SECRET")
            .map_err(|_| anyhow!("ADMIN_API_SECRET must be set for local KMS"))?;
        
        let mut hasher = Sha256::new();
        hasher.update(admin_secret.as_bytes());
        let derived_key = hasher.finalize();
        
        // FIX: Use `new_from_slice` which safely returns a Result rather than panicking on invalid lengths.
        Aes256Gcm::new_from_slice(&derived_key).map_err(|_| anyhow!("Invalid derived key length"))
    }

    pub async fn decrypt_cached(&self, ciphertext_blob: &[u8]) -> anyhow::Result<Vec<u8>> {
        let key_id = std::env::var("KMS_CMK_ID").unwrap_or_default();
        let cache_key = general_purpose::STANDARD.encode(ciphertext_blob);

        if let Some(v) = self.cache.get(&cache_key).await {
            return Ok(v);
        }

        let bytes = if key_id == "local" {
            // --- LOCAL AES-256-GCM DECRYPTION ---
            if ciphertext_blob.len() < 12 { return Err(anyhow!("Invalid local ciphertext blob")); }
            let (nonce_bytes, ciphertext) = ciphertext_blob.split_at(12);
            
            let cipher = Self::get_local_cipher()?;
            
            // FIX: Explicitly convert the slice into a 12-byte array first using TryInto
            // to satisfy the new generic-array 1.x strictness.
            let nonce_arr: [u8; 12] = nonce_bytes.try_into().map_err(|_| anyhow!("Invalid nonce blob"))?;
            let nonce = GcmNonce::from(nonce_arr);
            
            cipher.decrypt(&nonce, ciphertext).map_err(|_| anyhow!("Local AES-GCM decrypt failed"))?
        } else {
            // --- AWS KMS DECRYPTION ---
            let blob = SmithyBlob::new(ciphertext_blob.to_vec());
            let resp = self.client.decrypt().ciphertext_blob(blob).send().await
                .map_err(|e| anyhow!("KMS decrypt failed: {}", e))?;
            
            resp.plaintext.ok_or_else(|| anyhow!("No plaintext"))?.into_inner()
        };

        self.cache.insert(cache_key, bytes.clone()).await;
        Ok(bytes)
    }

    pub async fn encrypt(&self, key_id: &str, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        if key_id == "local" {
            // --- LOCAL AES-256-GCM ENCRYPTION ---
            let cipher = Self::get_local_cipher()?;
            let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 12-byte random nonce
            
            let encrypted = cipher.encrypt(&nonce, plaintext).map_err(|_| anyhow!("Local AES-GCM encrypt failed"))?;
            
            let mut blob = Vec::with_capacity(12 + encrypted.len());
            blob.extend_from_slice(&nonce);
            blob.extend_from_slice(&encrypted);
            Ok(blob)
        } else {
            // --- AWS KMS ENCRYPTION ---
            let blob = SmithyBlob::new(plaintext.to_vec());
            let resp = self.client.encrypt().key_id(key_id).plaintext(blob).send().await
                .map_err(|e| anyhow!("KMS encrypt failed: {}", e))?;
            
            Ok(resp.ciphertext_blob.ok_or_else(|| anyhow!("No ciphertext"))?.into_inner())
        }
    }
}