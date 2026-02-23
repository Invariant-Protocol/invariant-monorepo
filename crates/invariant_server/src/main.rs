// crates/invariant_server/src/main.rs
/*
 * Copyright (c) 2026 Invariant Protocol.
 *
 * This source code is licensed under the Business Source License (BSL 1.1) 
 * found in the LICENSE.md file in the root directory of this source tree.
 */

mod db;
mod impls; 
mod state;
mod tls;
mod auth;
mod handlers;
mod error_response; 
mod api_docs;      
mod services { pub mod push; }

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use sqlx::postgres::PgPoolOptions;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use invariant_engine::{InvariantEngine, IdentityStorage, core::EngineConfig};
use invariant_shared::Network;
use crate::db::PostgresStorage;
use crate::impls::RedisNonceManager; 
use crate::state::AppState;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    
    let log_format = tracing_subscriber::fmt::format()
        .with_level(true)
        .with_target(true)
        .with_thread_ids(false)
        .with_thread_names(false)
        .json(); 

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "invariant_server=info,tower_http=info".into()),
        ))
        .with(tracing_subscriber::fmt::layer().event_format(log_format))
        .init();

    if let Err(e) = services::push::initialize().await {
        tracing::error!("⚠️ Failed to initialize FCM: {}. Wake-up calls disabled.", e);
    }

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = PgPoolOptions::new()
        .max_connections(75) 
        .acquire_timeout(Duration::from_secs(5)) 
        .connect(&database_url)
        .await?;
    
    sqlx::migrate!("./migrations").run(&pool).await?;

    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
    let redis_client = redis::Client::open(redis_url)?;
    let nonce_manager = RedisNonceManager { client: redis_client.clone() };

    let network_str = std::env::var("INVARIANT_NETWORK").unwrap_or_else(|_| "testnet".into());
    let network = match network_str.to_lowercase().as_str() {
        "mainnet" => Network::Mainnet,
        "dev" => Network::Dev,
        _ => Network::Testnet,
    };

    let genesis_version = std::env::var("INVARIANT_GENESIS_VERSION")
        .unwrap_or_else(|_| "1".into())
        .parse::<u16>()
        .expect("Invalid GENESIS_VERSION");

    let admin_secret = std::env::var("ADMIN_API_SECRET")
        .expect("CRITICAL: ADMIN_API_SECRET must be set in production");

    tracing::info!(
        event = "startup",
        network = ?network,
        version = genesis_version,
        "🚀 Booting Invariant Node"
    );

    let storage = PostgresStorage::new(pool.clone());
    let engine_config = EngineConfig { network, genesis_version };
    
    let engine = InvariantEngine::new(storage, nonce_manager, engine_config);
    
    let state = Arc::new(AppState { 
        engine,
        redis: redis_client,
        pool: pool.clone(),
        admin_secret,
    });

    let worker_storage = PostgresStorage::new(pool.clone());
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(900)); 
        loop {
            interval.tick().await;
            
            match worker_storage.get_late_fcm_tokens(24 * 60).await {
                Ok(tokens) => {
                    if !tokens.is_empty() {
                        tracing::info!("🔔 Waking up {} late nodes...", tokens.len());
                        for token in tokens {
                            let t = token.clone(); 
                            tokio::spawn(async move {
                                let _ = services::push::send_wake_up_call(&t).await;
                            });
                        }
                    }
                }
                Err(e) => tracing::error!("Failed to fetch late tokens: {}", e),
            }

            if let Err(e) = worker_storage.run_reaper().await {
                tracing::error!("Reaper failed: {}", e);
            }
        }
    });

    let app = handlers::app_router(state);
    let addr = SocketAddr::from(([0, 0, 0, 0], 8443));
    
    tracing::info!(event = "server_listening", address = %addr, "Invariant Native mTLS Server actively listening");
    
    // NATIVE TLS ENFORCEMENT: The certificates configured here act as the physical bouncer.
    let config = tls::build_tls_config(
        "certs/server.crt",
        "certs/server.key",
        "certs/ca.crt"
    );
    let tls_config = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(config));

    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await?;

    Ok(())
}