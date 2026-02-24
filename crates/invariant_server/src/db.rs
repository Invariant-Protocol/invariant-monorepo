// crates/invariant_server/src/db.rs
/*
 * Copyright (c) 2026 Invariant Protocol.
 *
 * This source code is licensed under the Business Source License (BSL 1.1) 
 * found in the LICENSE.md file in the root directory of this source tree.
 */

use async_trait::async_trait;
use sqlx::{PgPool, Row};
use uuid::Uuid;
use invariant_engine::{IdentityStorage, EngineError};
use invariant_shared::{Identity, Heartbeat, IdentityStatus};
use sha2::{Sha256, Digest};
use tracing::error;

pub struct PostgresStorage {
    pub pool: PgPool,
}

impl PostgresStorage {
    pub fn new(pool: PgPool) -> Self { Self { pool } }

    /// 🛡️ NEW: Insert an audit event into api_client_audit table. 
    /// This is used by auth middleware and admin handlers for compliance logging.
    pub async fn insert_client_audit(
        &self, 
        actor_id: Option<Uuid>, 
        target_client_id: Option<Uuid>, 
        action: &str, 
        reason: Option<&str>, 
        details: Option<serde_json::Value>
    ) {
        let _ = sqlx::query!(
            r#"
            INSERT INTO api_client_audit (timestamp, actor_id, target_client_id, action, reason, details)
            VALUES (NOW(), $1, $2, $3, $4, $5)
            "#,
            actor_id,
            target_client_id,
            action,
            reason,
            details
        )
        .execute(&self.pool)
        .await
        .map_err(|e| error!("Failed to insert client audit: {}", e));
    }
}

#[async_trait]
impl IdentityStorage for PostgresStorage {
    async fn get_identity(&self, id: &Uuid) -> Result<Option<Identity>, EngineError> {
        let result = sqlx::query(r#"
            SELECT id, public_key, continuity_score, streak, created_at, last_heartbeat, last_attestation, status,
                   hardware_brand, hardware_device_hash, hardware_product,
                   genesis_version, network, username, is_genesis_eligible, fcm_token
            FROM identities WHERE id = $1
        "#)
        .bind(id).fetch_optional(&self.pool).await.map_err(|e| EngineError::Storage(e.to_string()))?;
        
        map_row_to_identity(result)
    }

    async fn get_identity_by_public_key(&self, public_key: &[u8]) -> Result<Option<Identity>, EngineError> {
        let result = sqlx::query(r#"
            SELECT id, public_key, continuity_score, streak, created_at, last_heartbeat, last_attestation, status,
                   hardware_brand, hardware_device_hash, hardware_product,
                   genesis_version, network, username, is_genesis_eligible, fcm_token
            FROM identities WHERE public_key = $1
        "#)
        .bind(public_key).fetch_optional(&self.pool).await.map_err(|e| EngineError::Storage(e.to_string()))?;
        
        map_row_to_identity(result)
    }

    async fn save_identity(&self, identity: &Identity) -> Result<(), EngineError> {
        let status_str = match identity.status {
            IdentityStatus::Active => "active",
            IdentityStatus::Stale => "stale",
            IdentityStatus::Dormant => "dormant",
            IdentityStatus::Revoked => "revoked",
        };

        let network_str = identity.network.to_string();

        let device_hash = identity.hardware_device.as_ref().map(|raw| {
            let mut hasher = Sha256::new();
            hasher.update(raw.as_bytes());
            hex::encode(hasher.finalize())
        });

        sqlx::query(r#"
            INSERT INTO identities (
                id, public_key, continuity_score, streak, created_at, last_heartbeat, last_attestation, status,
                hardware_brand, hardware_device_hash, hardware_product,
                genesis_version, network, username, is_genesis_eligible, fcm_token
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
            ON CONFLICT (id) DO UPDATE SET 
                status = $8, 
                continuity_score = $3, 
                last_heartbeat = $6,
                last_attestation = $7
        "#)
        .bind(identity.id)
        .bind(&identity.public_key)
        .bind(identity.continuity_score as i64)
        .bind(identity.streak as i64)
        .bind(identity.created_at)
        .bind(identity.last_heartbeat)
        .bind(identity.last_attestation)
        .bind(status_str)
        .bind(&identity.hardware_brand)
        .bind(device_hash)
        .bind(&identity.hardware_product)
        .bind(identity.genesis_version as i16)
        .bind(network_str)
        .bind(&identity.username)
        .bind(identity.is_genesis_eligible)
        .bind(&identity.fcm_token)
        .execute(&self.pool)
        .await
        .map_err(|e| EngineError::Storage(e.to_string()))?;
        
        Ok(())
    }

    async fn log_heartbeat(&self, identity: &Identity, heartbeat: &Heartbeat) -> Result<u64, EngineError> {
        let mut tx = self.pool.begin().await.map_err(|e| EngineError::Storage(e.to_string()))?;

        let row = sqlx::query("
            UPDATE identities 
            SET 
                continuity_score = continuity_score + 1,
                streak = CASE 
                    WHEN NOW() - last_heartbeat < INTERVAL '360 minutes' THEN streak + 1 
                    ELSE 1 
                END,
                last_heartbeat = NOW(), 
                status = 'active'
            WHERE id = $1
            RETURNING continuity_score
        ")
        .bind(identity.id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| EngineError::Storage(e.to_string()))?;

        let new_score: i64 = row.try_get("continuity_score").map_err(|e| EngineError::Storage(e.to_string()))?;

        sqlx::query("INSERT INTO heartbeats (identity_id, device_signature, timestamp) VALUES ($1, $2, $3)")
            .bind(heartbeat.identity_id)
            .bind(&heartbeat.device_signature)
            .bind(heartbeat.timestamp)
            .execute(&mut *tx)
            .await
            .map_err(|e| EngineError::Storage(e.to_string()))?;

        tx.commit().await.map_err(|e| EngineError::Storage(e.to_string()))?;
        Ok(new_score as u64)
    }

    async fn run_reaper(&self) -> Result<u64, EngineError> {
        let result = sqlx::query(r#"
            UPDATE identities SET status = 'dormant', streak = 0
            WHERE status = 'active' AND last_heartbeat < NOW() - INTERVAL '30 days'
        "#).execute(&self.pool).await.map_err(|e| EngineError::Storage(e.to_string()))?;

        Ok(result.rows_affected())
    }

    async fn set_username(&self, id: &Uuid, username: &str) -> Result<bool, EngineError> {
        let result = sqlx::query("UPDATE identities SET username = $1 WHERE id = $2 AND username IS NULL")
            .bind(username)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| EngineError::Storage(e.to_string()))?;
        
        Ok(result.rows_affected() > 0)
    }

    async fn get_leaderboard(&self, limit: i64) -> Result<Vec<Identity>, EngineError> {
        let rows = sqlx::query(r#"
            SELECT id, public_key, continuity_score, streak, created_at, last_heartbeat, last_attestation, status,
                   hardware_brand, hardware_device_hash, hardware_product,
                   genesis_version, network, username, is_genesis_eligible, fcm_token
            FROM identities 
            WHERE status = 'active'
            ORDER BY continuity_score DESC
            LIMIT $1
        "#)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| EngineError::Storage(e.to_string()))?;

        let mut identities = Vec::new();
        for row in rows {
            if let Ok(Some(id)) = map_row_to_identity(Some(row)) {
                identities.push(id);
            }
        }
        Ok(identities)
    }

    async fn update_fcm_token(&self, id: &Uuid, token: &str) -> Result<(), EngineError> {
        sqlx::query("UPDATE identities SET fcm_token = $1 WHERE id = $2")
            .bind(token)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| EngineError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn get_late_fcm_tokens(&self, minutes: i64) -> Result<Vec<String>, EngineError> {
        let rows = sqlx::query(r#"
            SELECT fcm_token FROM identities 
            WHERE status = 'active' AND fcm_token IS NOT NULL
            AND last_heartbeat < NOW() - make_interval(mins => $1)
        "#)
        .bind(minutes as i32)
        .fetch_all(&self.pool).await.map_err(|e| EngineError::Storage(e.to_string()))?;

        Ok(rows.into_iter().filter_map(|r| r.get(0)).collect())
    }
}

fn map_row_to_identity(row: Option<sqlx::postgres::PgRow>) -> Result<Option<Identity>, EngineError> {
    match row {
        Some(row) => {
            let status_str: String = row.try_get("status").unwrap_or_default();
            let status = match status_str.as_str() {
                "active" => IdentityStatus::Active,
                "stale" => IdentityStatus::Stale,
                "dormant" => IdentityStatus::Dormant,
                _ => IdentityStatus::Revoked,
            };

            let net_str: String = row.try_get("network").unwrap_or_else(|_| "testnet".to_string());
            let network = match net_str.as_str() {
                "mainnet" => invariant_shared::Network::Mainnet,
                "dev" => invariant_shared::Network::Dev,
                _ => invariant_shared::Network::Testnet,
            };

            Ok(Some(Identity {
                id: row.try_get("id").map_err(|e| EngineError::Storage(e.to_string()))?,
                public_key: row.try_get("public_key").map_err(|e| EngineError::Storage(e.to_string()))?,
                continuity_score: row.try_get::<i64, _>("continuity_score").unwrap_or(0) as u64,
                streak: row.try_get::<i64, _>("streak").unwrap_or(0) as u64,
                created_at: row.try_get("created_at").map_err(|e| EngineError::Storage(e.to_string()))?,
                last_heartbeat: row.try_get("last_heartbeat").map_err(|e| EngineError::Storage(e.to_string()))?,
                last_attestation: row.try_get("last_attestation").map_err(|e| EngineError::Storage(e.to_string()))?,
                status,
                username: row.try_get("username").ok(),
                is_genesis_eligible: row.try_get("is_genesis_eligible").unwrap_or(false),
                fcm_token: row.try_get("fcm_token").ok(),
                hardware_brand: row.try_get("hardware_brand").ok(),
                hardware_device: row.try_get("hardware_device_hash").ok(),
                hardware_product: row.try_get("hardware_product").ok(),
                genesis_version: row.try_get::<i16, _>("genesis_version").unwrap_or(1) as u16,
                network,
            }))
        }
        None => Ok(None),
    }
}