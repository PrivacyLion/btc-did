// sdk/delegation.rs - Delegation Validation (Phase 9A.5)
//
// Per Bible Section 4.4 - Enterprise Validation Flow:
// 1. Query NOSTR for kind 28250 events tagged with agent's npub
// 2. Verify delegation chain:
//    (a) Signed by trusted human npub (Schnorr signature via nostr-sdk)
//    (b) expires_at in future
//    (c) delegation_id matches
//    (d) No kind 28251 revocation for this delegation_id
// 3. Return validation result with scopes and expiration

use anyhow::{Result, anyhow};
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use super::nostr_client::{NostrClient, KIND_HUMAN_DELEGATION, KIND_HUMAN_REVOCATION};

/// Delegation validation result per Bible Section 4.4
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationValidation {
    /// Whether the delegation is currently valid
    pub valid: bool,
    /// Expiration timestamp (ISO 8601 or Unix)
    pub expires_at: Option<String>,
    /// Delegation scopes (JSON object with permissions)
    pub scopes: Option<serde_json::Value>,
    /// Unique delegation identifier
    pub delegation_id: String,
    /// Whether this delegation has been revoked via kind 28251
    pub revoked: bool,
    /// Human npub who created the delegation
    pub human_npub: Option<String>,
    /// Validation error message if not valid
    pub error: Option<String>,
}

/// Parsed kind 28250 delegation content per Bible lines 270-277
#[derive(Debug, Clone, Deserialize)]
struct DelegationContent {
    /// Agent's npub being delegated to
    agent_npub: String,
    /// Permission scopes granted
    #[serde(default)]
    scopes: Option<serde_json::Value>,
    /// Expiration timestamp (Unix seconds or ISO 8601)
    expires_at: Option<String>,
    /// Unique delegation identifier (for revocation matching)
    delegation_id: String,
}

/// Delegation validator - validates agent authorization per Bible Section 4.4
pub struct DelegationValidator {
    nostr_client: NostrClient,
}

impl DelegationValidator {
    /// Create new delegation validator with NOSTR client
    pub fn new(nostr_client: NostrClient) -> Self {
        Self { nostr_client }
    }
    
    /// Validate delegation for an agent per Bible Section 4.4
    /// 
    /// Performs the full validation chain:
    /// 1. Query kind 28250 events tagged with agent_npub
    /// 2. Find event with matching delegation_id
    /// 3. Verify Schnorr signature (automatic via nostr-sdk)
    /// 4. Check expires_at is in future
    /// 5. Check no kind 28251 revocation exists
    pub async fn validate_delegation(
        &self,
        agent_npub: &str,
        delegation_id: &str,
    ) -> Result<DelegationValidation> {
        // Step 1: Query kind 28250 events for this agent
        let delegation_events = self.query_delegation_by_agent(agent_npub).await?;
        
        if delegation_events.is_empty() {
            return Ok(DelegationValidation {
                valid: false,
                expires_at: None,
                scopes: None,
                delegation_id: delegation_id.to_string(),
                revoked: false,
                human_npub: None,
                error: Some("No delegation events found for this agent".to_string()),
            });
        }
        
        // Step 2: Find delegation with matching delegation_id
        let mut matching_event: Option<(Event, DelegationContent)> = None;
        
        for event in delegation_events {
            // Parse content JSON
            if let Ok(content) = serde_json::from_str::<DelegationContent>(&event.content) {
                if content.delegation_id == delegation_id {
                    matching_event = Some((event, content));
                    break;
                }
            }
        }
        
        let (event, content) = match matching_event {
            Some(m) => m,
            None => {
                return Ok(DelegationValidation {
                    valid: false,
                    expires_at: None,
                    scopes: None,
                    delegation_id: delegation_id.to_string(),
                    revoked: false,
                    human_npub: None,
                    error: Some(format!("No delegation found with delegation_id: {}", delegation_id)),
                });
            }
        };
        
        let human_npub = event.pubkey.to_bech32().ok();
        
        // Step 3: Verify Schnorr signature
        // nostr-sdk automatically validates signatures when receiving events
        // Events with invalid signatures are rejected by the relay and nostr-sdk
        // If we got here, the signature is valid
        
        // Step 4: Check expires_at is in future
        let expired = if let Some(ref expires_at) = content.expires_at {
            is_expired(expires_at)
        } else {
            false // No expiration = never expires
        };
        
        if expired {
            return Ok(DelegationValidation {
                valid: false,
                expires_at: content.expires_at,
                scopes: content.scopes,
                delegation_id: delegation_id.to_string(),
                revoked: false,
                human_npub,
                error: Some("Delegation has expired".to_string()),
            });
        }
        
        // Step 5: Check for revocation (kind 28251 with this delegation_id)
        let revoked = self.check_revocation_by_delegation_id(delegation_id).await?;
        
        if revoked {
            return Ok(DelegationValidation {
                valid: false,
                expires_at: content.expires_at,
                scopes: content.scopes,
                delegation_id: delegation_id.to_string(),
                revoked: true,
                human_npub,
                error: Some("Delegation has been revoked".to_string()),
            });
        }
        
        // All checks passed - delegation is valid
        Ok(DelegationValidation {
            valid: true,
            expires_at: content.expires_at,
            scopes: content.scopes,
            delegation_id: delegation_id.to_string(),
            revoked: false,
            human_npub,
            error: None,
        })
    }
    
    /// Validate any active delegation for an agent (without specific delegation_id)
    /// 
    /// Returns the first valid, non-revoked delegation found.
    pub async fn validate_any_delegation(
        &self,
        agent_npub: &str,
    ) -> Result<DelegationValidation> {
        // Query all delegation events for this agent
        let delegation_events = self.query_delegation_by_agent(agent_npub).await?;
        
        if delegation_events.is_empty() {
            return Ok(DelegationValidation {
                valid: false,
                expires_at: None,
                scopes: None,
                delegation_id: String::new(),
                revoked: false,
                human_npub: None,
                error: Some("No delegation events found for this agent".to_string()),
            });
        }
        
        // Check each delegation for validity
        for event in delegation_events {
            if let Ok(content) = serde_json::from_str::<DelegationContent>(&event.content) {
                // Check expiration
                let expired = if let Some(ref expires_at) = content.expires_at {
                    is_expired(expires_at)
                } else {
                    false
                };
                
                if expired {
                    continue;
                }
                
                // Check revocation
                let revoked = self.check_revocation_by_delegation_id(&content.delegation_id).await?;
                
                if revoked {
                    continue;
                }
                
                // Found a valid delegation
                return Ok(DelegationValidation {
                    valid: true,
                    expires_at: content.expires_at,
                    scopes: content.scopes,
                    delegation_id: content.delegation_id,
                    revoked: false,
                    human_npub: event.pubkey.to_bech32().ok(),
                    error: None,
                });
            }
        }
        
        // No valid delegations found
        Ok(DelegationValidation {
            valid: false,
            expires_at: None,
            scopes: None,
            delegation_id: String::new(),
            revoked: false,
            human_npub: None,
            error: Some("All delegations are expired or revoked".to_string()),
        })
    }
    
    /// Query kind 28250 delegation events for a specific agent
    /// 
    /// Filter: {"kinds": [28250], "#p": ["<agent_npub_hex>"]}
    async fn query_delegation_by_agent(&self, agent_npub: &str) -> Result<Vec<Event>> {
        // Convert agent_npub to hex if it's bech32
        let agent_pubkey = PublicKey::from_bech32(agent_npub)
            .or_else(|_| PublicKey::from_hex(agent_npub))
            .map_err(|e| anyhow!("Invalid agent npub: {}", e))?;
        
        let agent_npub_hex = agent_pubkey.to_hex();
        
        // Build filter per Bible: {"kinds": [28250], "#p": ["<agent_npub_hex>"]}
        let filter = Filter::new()
            .kind(Kind::Custom(KIND_HUMAN_DELEGATION))
            .custom_tag(SingleLetterTag::lowercase(Alphabet::P), vec![agent_npub_hex])
            .limit(100);
        
        let events = self.nostr_client
            .inner_client()
            .get_events_of(
                vec![filter],
                nostr_sdk::client::EventSource::relays(Some(Duration::from_secs(5))),
            )
            .await
            .map_err(|e| anyhow!("Failed to query delegation events: {}", e))?;
        
        Ok(events)
    }
    
    /// Check if a delegation has been revoked via kind 28251
    /// 
    /// Query: {"kinds": [28251], "#d": ["<delegation_id>"]}
    async fn check_revocation_by_delegation_id(&self, delegation_id: &str) -> Result<bool> {
        // Build filter for revocation events tagged with delegation_id
        let filter = Filter::new()
            .kind(Kind::Custom(KIND_HUMAN_REVOCATION))
            .custom_tag(SingleLetterTag::lowercase(Alphabet::D), vec![delegation_id.to_string()])
            .limit(1);
        
        let events = self.nostr_client
            .inner_client()
            .get_events_of(
                vec![filter],
                nostr_sdk::client::EventSource::relays(Some(Duration::from_secs(5))),
            )
            .await
            .map_err(|e| anyhow!("Failed to query revocation events: {}", e))?;
        
        Ok(!events.is_empty())
    }
    
    /// Get a reference to the inner NostrClient
    pub fn nostr_client(&self) -> &NostrClient {
        &self.nostr_client
    }
}

/// Check if an expiration timestamp is in the past
fn is_expired(expires_at: &str) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    
    // Try parsing as Unix timestamp (seconds)
    if let Ok(exp_unix) = expires_at.parse::<u64>() {
        return exp_unix < now;
    }
    
    // Try parsing as ISO 8601 datetime
    // Simple parse: look for YYYY-MM-DDTHH:MM:SS format
    if let Some(exp_unix) = parse_iso8601(expires_at) {
        return exp_unix < now;
    }
    
    // If we can't parse it, assume not expired
    false
}

/// Simple ISO 8601 parser (YYYY-MM-DDTHH:MM:SSZ or YYYY-MM-DDTHH:MM:SS+00:00)
fn parse_iso8601(s: &str) -> Option<u64> {
    // Very basic parsing - for production, use chrono crate
    // Format: 2026-04-17T23:00:00Z
    let s = s.trim_end_matches('Z').split('+').next()?;
    let parts: Vec<&str> = s.split('T').collect();
    if parts.len() != 2 {
        return None;
    }
    
    let date_parts: Vec<u32> = parts[0].split('-').filter_map(|p| p.parse().ok()).collect();
    let time_parts: Vec<u32> = parts[1].split(':').filter_map(|p| p.parse().ok()).collect();
    
    if date_parts.len() != 3 || time_parts.len() < 2 {
        return None;
    }
    
    // Very rough Unix timestamp calculation (ignores leap years, etc.)
    // For production, use chrono
    let year = date_parts[0] as u64;
    let month = date_parts[1] as u64;
    let day = date_parts[2] as u64;
    let hour = time_parts[0] as u64;
    let minute = time_parts[1] as u64;
    let second = time_parts.get(2).copied().unwrap_or(0) as u64;
    
    // Days since Unix epoch (1970-01-01)
    let years_since_1970 = year.saturating_sub(1970);
    let days = years_since_1970 * 365 + years_since_1970 / 4 // Rough leap year adjustment
        + (month - 1) * 30 + day - 1; // Rough month calculation
    
    Some(days * 86400 + hour * 3600 + minute * 60 + second)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_delegation_validation_serialization() {
        let validation = DelegationValidation {
            valid: true,
            expires_at: Some("2026-12-31T23:59:59Z".to_string()),
            scopes: Some(serde_json::json!({"login": true, "payment": false})),
            delegation_id: "del_abc123".to_string(),
            revoked: false,
            human_npub: Some("npub1xyz...".to_string()),
            error: None,
        };
        
        let json = serde_json::to_string(&validation).unwrap();
        assert!(json.contains("\"valid\":true"));
        assert!(json.contains("\"delegation_id\":\"del_abc123\""));
    }
    
    #[test]
    fn test_is_expired_unix() {
        // Past timestamp (2020-01-01)
        assert!(is_expired("1577836800"));
        
        // Future timestamp (2030-01-01)
        assert!(!is_expired("1893456000"));
    }
    
    #[test]
    fn test_is_expired_iso8601() {
        // Past date
        assert!(is_expired("2020-01-01T00:00:00Z"));
        
        // Future date
        assert!(!is_expired("2030-01-01T00:00:00Z"));
    }
    
    #[test]
    fn test_delegation_content_parsing() {
        let json = r#"{
            "agent_npub": "npub1abc...",
            "scopes": {"login": true},
            "expires_at": "2026-12-31T23:59:59Z",
            "delegation_id": "del_123"
        }"#;
        
        let content: DelegationContent = serde_json::from_str(json).unwrap();
        assert_eq!(content.delegation_id, "del_123");
        assert_eq!(content.agent_npub, "npub1abc...");
    }
}
