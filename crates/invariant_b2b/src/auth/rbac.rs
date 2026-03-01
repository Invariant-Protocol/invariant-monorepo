// crates/invariant_b2b/src/auth/rbac.rs
/*
 * Copyright (c) 2026 Invariant Protocol.
 */

use crate::error::B2bError;

#[derive(Debug, PartialEq, Eq)]
pub enum OrgRole {
    Owner,
    Admin,
    Developer,
    Billing,
}

impl OrgRole {
    pub fn from_str(role: &str) -> Self {
        match role.to_lowercase().as_str() {
            "owner" => OrgRole::Owner,
            "admin" => OrgRole::Admin,
            "billing" => OrgRole::Billing,
            _ => OrgRole::Developer,
        }
    }

    /// Determines if the role has privileges to provision/revoke keys.
    pub fn can_manage_keys(&self) -> Result<(), B2bError> {
        match self {
            OrgRole::Owner | OrgRole::Admin => Ok(()),
            _ => Err(B2bError::Forbidden("Requires Admin or Owner privileges.".into())),
        }
    }

    /// Determines if the role has privileges to view financial data.
    pub fn can_view_billing(&self) -> Result<(), B2bError> {
        match self {
            OrgRole::Owner | OrgRole::Admin | OrgRole::Billing => Ok(()),
            _ => Err(B2bError::Forbidden("Requires Billing privileges.".into())),
        }
    }
}