use std::sync::Mutex;

use crate::auth;
use crate::error::{Result, TideCloakError};
use crate::jwt;
use crate::types::{JwtClaims, OidcEndpoints, TideCloakConfig, TokenSet, UserInfo};

/// Buffer time (ms) before expiry to trigger a refresh
const REFRESH_BUFFER_MS: u64 = 30_000;

/// Manages the current token set, providing auto-refresh and claim extraction.
pub struct TokenManager {
    config: TideCloakConfig,
    endpoints: OidcEndpoints,
    tokens: Mutex<Option<TokenSet>>,
}

impl TokenManager {
    pub fn new(config: TideCloakConfig, endpoints: OidcEndpoints) -> Self {
        Self {
            config,
            endpoints,
            tokens: Mutex::new(None),
        }
    }

    /// Store a new token set (e.g., after code exchange)
    pub fn set_tokens(&self, tokens: TokenSet) {
        *self.tokens.lock().unwrap() = Some(tokens);
    }

    /// Clear all tokens (e.g., on logout)
    pub fn clear_tokens(&self) {
        *self.tokens.lock().unwrap() = None;
    }

    /// Get the current token set (clone)
    pub fn get_tokens(&self) -> Option<TokenSet> {
        self.tokens.lock().unwrap().clone()
    }

    /// Check if we currently have tokens
    pub fn has_tokens(&self) -> bool {
        self.tokens.lock().unwrap().is_some()
    }

    /// Check if the access token is expired
    pub fn is_expired(&self) -> bool {
        let guard = self.tokens.lock().unwrap();
        match guard.as_ref() {
            Some(tokens) => now_ms() >= tokens.expires_at,
            None => true,
        }
    }

    /// Check if the access token will expire within the refresh buffer
    pub fn needs_refresh(&self) -> bool {
        let guard = self.tokens.lock().unwrap();
        match guard.as_ref() {
            Some(tokens) => now_ms() >= tokens.expires_at.saturating_sub(REFRESH_BUFFER_MS),
            None => true,
        }
    }

    /// Get a valid access token, refreshing if needed.
    /// Returns None if no tokens are stored and refresh isn't possible.
    pub async fn get_valid_token(&self, dpop_proof: Option<&str>) -> Result<String> {
        // Check if refresh is needed
        if self.needs_refresh() {
            self.try_refresh(dpop_proof).await?;
        }

        let guard = self.tokens.lock().unwrap();
        match guard.as_ref() {
            Some(tokens) => Ok(tokens.access_token.clone()),
            None => Err(TideCloakError::Token("No tokens available".to_string())),
        }
    }

    /// Try to refresh the token. Fails silently if no refresh token is available.
    pub async fn try_refresh(&self, dpop_proof: Option<&str>) -> Result<()> {
        let refresh_token = {
            let guard = self.tokens.lock().unwrap();
            match guard.as_ref().and_then(|t| t.refresh_token.clone()) {
                Some(rt) => rt,
                None => {
                    return Err(TideCloakError::Token(
                        "No refresh token available".to_string(),
                    ))
                }
            }
        };

        let new_tokens =
            auth::refresh_token(&self.config, &self.endpoints, &refresh_token, dpop_proof).await?;
        self.set_tokens(new_tokens);
        Ok(())
    }

    /// Get the access token string (without refresh). Returns None if not available.
    pub fn access_token(&self) -> Option<String> {
        self.tokens
            .lock()
            .unwrap()
            .as_ref()
            .map(|t| t.access_token.clone())
    }

    /// Get the ID token string. Returns None if not available.
    pub fn id_token(&self) -> Option<String> {
        self.tokens
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|t| t.id_token.clone())
    }

    /// Get the refresh token string. Returns None if not available.
    pub fn refresh_token_str(&self) -> Option<String> {
        self.tokens
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|t| t.refresh_token.clone())
    }

    /// Get the doken (Tide encryption token). Returns None if not available.
    pub fn doken(&self) -> Option<String> {
        self.tokens
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|t| t.doken.clone())
    }

    /// Decode the access token and return the claims
    pub fn decode_access_token(&self) -> Result<JwtClaims> {
        let guard = self.tokens.lock().unwrap();
        match guard.as_ref() {
            Some(tokens) => jwt::decode_jwt(&tokens.access_token),
            None => Err(TideCloakError::Token("No access token".to_string())),
        }
    }

    /// Extract user info from the current access token
    pub fn user_info(&self) -> Result<UserInfo> {
        let claims = self.decode_access_token()?;
        Ok(UserInfo {
            sub: claims.sub.unwrap_or_default(),
            preferred_username: claims.preferred_username,
            email: claims.email,
            name: claims.name,
            realm_roles: claims
                .realm_access
                .map(|ra| ra.roles)
                .unwrap_or_default(),
        })
    }

    /// Check if the user has a realm role
    pub fn has_realm_role(&self, role: &str) -> bool {
        self.decode_access_token()
            .ok()
            .and_then(|c| c.realm_access)
            .map(|ra| ra.roles.contains(&role.to_string()))
            .unwrap_or(false)
    }

    /// Check if the user has a client role
    pub fn has_client_role(&self, role: &str, client: Option<&str>) -> bool {
        let client_id = client.unwrap_or(&self.config.resource);
        self.decode_access_token()
            .ok()
            .and_then(|c| c.resource_access)
            .and_then(|ra| ra.get(client_id).cloned())
            .and_then(|v| v.get("roles").cloned())
            .and_then(|roles| roles.as_array().cloned())
            .map(|roles| roles.iter().any(|r| r.as_str() == Some(role)))
            .unwrap_or(false)
    }

    /// Get a custom claim from the access token
    pub fn get_claim(&self, key: &str) -> Option<serde_json::Value> {
        let guard = self.tokens.lock().unwrap();
        guard
            .as_ref()
            .and_then(|t| jwt::get_claim(&t.access_token, key).ok().flatten())
    }

    /// Seconds until access token expires
    pub fn expires_in_secs(&self) -> i64 {
        let guard = self.tokens.lock().unwrap();
        match guard.as_ref() {
            Some(tokens) => {
                let now = now_ms();
                (tokens.expires_at as i64 - now as i64) / 1000
            }
            None => 0,
        }
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
