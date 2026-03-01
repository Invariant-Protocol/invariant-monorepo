// crates/invariant_b2b/src/auth/jwt.rs
/*
 * Copyright (c) 2026 Invariant Protocol.
 */

use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};
use crate::error::B2bError;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    pub sub: String, // The external ID from Auth0/Supabase/Clerk
    pub exp: usize,
    pub iat: usize,
}

/// Validates the JWT and returns the 'sub' claim (external User ID).
pub fn validate_and_extract_sub(token: &str, secret: &str) -> Result<String, B2bError> {
    // Note: For production with external IdPs, you would use DecodingKey::from_rsa_components
    // fetching JWKS. For this MVP, we use symmetric HS256 assuming a standard Supabase setup.
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_audience(&["authenticated"]); // Example audience constraint

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    ).map_err(|e| B2bError::Unauthorized(format!("Invalid token: {}", e)))?;

    Ok(token_data.claims.sub)
}