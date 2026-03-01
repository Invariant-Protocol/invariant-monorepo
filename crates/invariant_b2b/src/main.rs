// crates/invariant_b2b/src/main.rs
/*
 * Copyright (c) 2026 Invariant Protocol.
 * B2B Enterprise Management Portal - High Availability Control Plane
 */

mod error;
mod state;
mod models;
mod db;
mod auth;
mod handlers;
mod rate_limiter; 

use axum::{
    routing::{get, delete},
    Router, Extension, middleware,
};
use sqlx::postgres::PgPoolOptions;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tower_http::cors::{CorsLayer, Any};
use tower_http::trace::TraceLayer;

use crate::state::B2bState;
use crate::auth::rls_layer::tenancy_middleware;
use crate::auth::rate_limit::b2b_rate_limit_middleware;
use crate::handlers::{
    keys::{create_key_handler, list_keys_handler, revoke_key_handler},
    orgs::{get_org_details_handler, list_members_handler},
    telemetry::get_telemetry_handler,
    billing::get_billing_usage_handler,
    users::get_me_handler,
    health::health_check_handler, // 👈 Import health check
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "invariant_b2b=info,tower_http=info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Initializing Invariant B2B Management Portal...");

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = PgPoolOptions::new()
        .max_connections(50)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&database_url)
        .await?;

    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
    let redis_client = redis::Client::open(redis_url)?;

    let jwt_secret = std::env::var("B2B_JWT_SECRET").expect("CRITICAL: B2B_JWT_SECRET must be set");
    let admin_secret = std::env::var("ADMIN_API_SECRET").expect("CRITICAL: ADMIN_API_SECRET must be set for KMS");

    let state = Arc::new(B2bState::new(pool.clone(), redis_client.clone(), jwt_secret));

    tokio::spawn(db::outbox::start_outbox_worker(pool.clone(), redis_client.clone(), admin_secret));

    let cors = CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any);

    let api_routes = Router::new()
        .route("/:org_id", get(get_org_details_handler))
        .route("/:org_id/users/me", get(get_me_handler)) 
        .route("/:org_id/members", get(list_members_handler))
        .route("/:org_id/keys", get(list_keys_handler).post(create_key_handler))
        .route("/:org_id/keys/:key_id", delete(revoke_key_handler))
        .route("/:org_id/metrics", get(get_telemetry_handler))
        .route("/:org_id/billing/usage", get(get_billing_usage_handler))
        .layer(middleware::from_fn(b2b_rate_limit_middleware))
        .layer(middleware::from_fn(tenancy_middleware)); 

    let app = Router::new()
        .route("/health", get(health_check_handler)) // 👈 Wire deep health check
        .nest("/api/v1/orgs", api_routes)
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .layer(Extension(state));

    let port = std::env::var("B2B_PORT").unwrap_or_else(|_| "3001".to_string());
    let addr: SocketAddr = format!("0.0.0.0:{}", port).parse()?;
    
    tracing::info!("🚀 B2B API Active on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app.into_make_service()).await?;

    Ok(())
}