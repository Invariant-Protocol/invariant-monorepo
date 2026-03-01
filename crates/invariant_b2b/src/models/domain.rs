// crates/invariant_b2b/src/models/domain.rs
/*
 * Copyright (c) 2026 Invariant Protocol.
 */

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Debug, Serialize, Deserialize)]
pub struct Organization {
    pub id: Uuid,
    pub name: String,
    pub billing_plan: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub ext_id: String,
    pub email: String,
    pub name: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OrganizationMember {
    pub org_id: Uuid,
    pub user_id: Uuid,
    pub role: String,
    pub joined_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct TelemetryDataPoint {
    pub time_bucket: DateTime<Utc>,
    pub tier: String,
    pub decision: String,
    pub request_count: i64,
}