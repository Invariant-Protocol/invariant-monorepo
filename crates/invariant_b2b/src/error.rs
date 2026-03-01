// crates/invariant_b2b/src/error.rs
/*
 * Copyright (c) 2026 Invariant Protocol.
 */

use axum::{http::StatusCode, response::{IntoResponse, Response}, Json};
use serde_json::json;
use tracing::error;

#[derive(thiserror::Error, Debug)]
pub enum B2bError {
    #[error("Authentication failed: {0}")]
    Unauthorized(String),

    #[error("Access denied: {0}")]
    Forbidden(String),

    #[error("Resource not found: {0}")]
    NotFound(String),

    #[error("Too many requests")]
    TooManyRequests,

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Internal server error: {0}")]
    Internal(String),
}

impl IntoResponse for B2bError {
    fn into_response(self) -> Response {
        let (status, code, message) = match &self {
            B2bError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, "UNAUTHORIZED", msg.clone()),
            B2bError::Forbidden(msg) => (StatusCode::FORBIDDEN, "FORBIDDEN", msg.clone()),
            B2bError::NotFound(msg) => (StatusCode::NOT_FOUND, "NOT_FOUND", msg.clone()),
            B2bError::TooManyRequests => (StatusCode::TOO_MANY_REQUESTS, "RATE_LIMIT_EXCEEDED", "You have exceeded your API request quota.".to_string()),
            B2bError::Database(e) => {
                error!("SQLx Database Error: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "DATABASE_ERROR", "A storage error occurred.".to_string())
            },
            B2bError::Internal(msg) => {
                error!("Internal Error: {}", msg);
                (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "An unexpected error occurred.".to_string())
            }
        };

        let body = Json(json!({
            "error": {
                "code": code,
                "message": message
            }
        }));

        (status, body).into_response()
    }
}