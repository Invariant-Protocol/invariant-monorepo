// crates/invariant_server/src/handlers/mod.rs
/*
 * Copyright (c) 2026 Invariant Protocol.
 *
 * This source code is licensed under the Business Source License (BSL 1.1) 
 * found in the LICENSE.md file in the root directory of this source tree.
 */

use axum::{Router, routing::{get, post}, extract::Path, http::{StatusCode, HeaderValue, header}, Extension, Json, middleware};
use crate::state::SharedState;
use uuid::Uuid;
use invariant_engine::IdentityStorage;
use chrono::Duration;

use tower::ServiceBuilder;
use tower_http::{
    compression::CompressionLayer,
    timeout::TimeoutLayer,
    trace::TraceLayer,
    set_header::SetResponseHeaderLayer,
};

use utoipa_swagger_ui::SwaggerUi;
use crate::api_docs::ApiDoc;

pub mod genesis;
pub mod heartbeat;
pub mod identity;
pub mod admin; 
pub mod provisioning; 
pub mod secrets; // 🛡️ NEW: Secret Rotation Handler
use crate::auth;

async fn check_identity_handler(
    Path(id): Path<Uuid>,
    Extension(state): Extension<SharedState>,
) -> impl axum::response::IntoResponse {
    match state.engine.get_storage().get_identity(&id).await {
        Ok(Some(identity)) => {
            let next_available = identity.last_heartbeat + Duration::minutes(1380);
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "id": identity.id,
                    "score": identity.continuity_score,
                    "streak": identity.streak,
                    "status": format!("{:?}", identity.status).to_uppercase(),
                    "tier": identity.hardware_device.as_deref().unwrap_or("Hardware TEE"),
                    "username": identity.username, 
                    "is_genesis_eligible": identity.is_genesis_eligible,
                    "next_available": next_available.to_rfc3339(),
                    "last_attestation": identity.last_attestation.to_rfc3339()
                }))
            )
        },
        _ => (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "Identity not found" }))),
    }
}

pub fn app_router(state: SharedState) -> Router {
    let security_headers = ServiceBuilder::new()
        .layer(SetResponseHeaderLayer::overriding(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains; preload"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ));

    // DATA PLANE: Requires mTLS AND HMAC
    let sensitive_routes = Router::new()
        .route("/genesis", post(genesis::genesis_handler))
        .route("/verify", post(genesis::verify_stateless_handler)) 
        .route("/heartbeat", post(heartbeat::heartbeat_handler))
        .route("/identity/reattest", post(identity::reattest_handler))
        .route("/identity/:id/manifest", get(identity::get_manifest_handler))
        .layer(middleware::from_fn(auth::verify_hmac_middleware));

    // CONTROL PLANE: Requires Master Secret
    let admin_routes = Router::new()
        .route("/keys/generate", post(admin::generate_client_key_handler))
        .route("/keys/revoke", post(admin::revoke_client_key_handler))
        .route("/keys/list", get(admin::list_client_keys_handler))
        .route("/keys/:client_id/rotate-secret", post(secrets::rotate_hmac_secret_handler)) // 🛡️ NEW
        .layer(middleware::from_fn(auth::admin_auth_middleware));

    // BOOTSTRAP PLANE: Requires API Key + HMAC (No mTLS required)
    let sdk_routes = Router::new()
        .route("/provision", post(provisioning::provision_sdk_handler))
        .layer(middleware::from_fn(auth::bootstrap_hmac_middleware));

    Router::new()
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", <ApiDoc as utoipa::OpenApi>::openapi()))
        
        .route("/health", get(|| async { "Invariant Node Online" }))
        .route("/heartbeat/challenge", get(heartbeat::get_heartbeat_challenge_handler))
        .route("/genesis/challenge", get(genesis::get_challenge_handler))
        .route("/identity/:id", get(check_identity_handler))
        .route("/identity/claim_username", post(identity::claim_username_handler))
        .route("/identity/push_token", post(identity::update_push_token_handler))
        .route("/leaderboard", get(identity::get_leaderboard_handler))
        
        .nest("/admin", admin_routes)
        .nest("/sdk", sdk_routes)
        .merge(sensitive_routes)
        
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http()) 
                .layer(TimeoutLayer::new(std::time::Duration::from_secs(15)))
                .layer(CompressionLayer::new())
                .layer(security_headers)
                .layer(Extension(state))
        )
}