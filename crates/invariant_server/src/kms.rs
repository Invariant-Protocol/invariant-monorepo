// crates/invariant_server/src/kms.rs
/*
 * Copyright (c) 2026 Invariant Protocol.
 *
 * KMS envelope encryption helper
 */

use anyhow::anyhow;
use aws_sdk_kms::Client as KmsClient;
use moka::future::Cache;
use base64::{engine::general_purpose, Engine as _};
use std::sync::Arc;
use aws_smithy_types::Blob as SmithyBlob;

#[derive(Clone)]
pub struct KmsHelper {
    pub client: KmsClient,
    pub cache: Arc<Cache<String, Vec<u8>>>,
    // Cache TTL is managed globally by the Moka cache builder in main.rs
}

impl KmsHelper {
    pub fn new(client: KmsClient, cache: Cache<String, Vec<u8>>) -> Self {
        Self { 
            client, 
            cache: Arc::new(cache) 
        }
    }

    pub async fn decrypt_cached(&self, ciphertext_blob: &[u8]) -> anyhow::Result<Vec<u8>> {
        let key = general_purpose::STANDARD.encode(ciphertext_blob);

        if let Some(v) = self.cache.get(&key).await {
            return Ok(v);
        }

        let blob = SmithyBlob::new(ciphertext_blob.to_vec());
        let resp = self.client
            .decrypt()
            .ciphertext_blob(blob)
            .send()
            .await
            .map_err(|e| anyhow!("KMS decrypt failed: {}", e))?;

        let plaintext_stream = resp.plaintext
            .ok_or_else(|| anyhow!("KMS decrypt returned no plaintext"))?;

        let bytes = plaintext_stream.into_inner();
        self.cache.insert(key.clone(), bytes.clone()).await;

        Ok(bytes)
    }

    pub async fn generate_data_key(&self, key_id: &str) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        let resp = self.client
            .generate_data_key()
            .key_id(key_id)
            .key_spec(aws_sdk_kms::types::DataKeySpec::Aes256)
            .send()
            .await
            .map_err(|e| anyhow!("KMS generate_data_key failed: {}", e))?;

        let plaintext = resp.plaintext
            .ok_or_else(|| anyhow!("generate_data_key returned no plaintext"))?
            .into_inner();

        let ciphertext_blob = resp.ciphertext_blob
            .ok_or_else(|| anyhow!("generate_data_key returned no ciphertext_blob"))?
            .into_inner();

        Ok((plaintext, ciphertext_blob))
    }
}