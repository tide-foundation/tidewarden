use serde::{Deserialize, Serialize};

/// Raw TideCloak config as loaded from tidecloak.json
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TideCloakConfig {
    #[serde(rename = "auth-server-url")]
    pub auth_server_url: String,
    pub realm: String,
    pub resource: String,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(rename = "vendorId", default)]
    pub vendor_id: Option<String>,
    #[serde(rename = "homeOrkUrl", default)]
    pub home_ork_url: Option<String>,
    /// Auth mode: "frontchannel", "native", or "hybrid"
    #[serde(rename = "authMode", default = "default_auth_mode")]
    pub auth_mode: String,
    /// Whether to use DPoP
    #[serde(rename = "useDPoP", default)]
    pub use_dpop: Option<DPoPConfig>,
}

fn default_auth_mode() -> String {
    "native".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DPoPConfig {
    #[serde(default = "default_dpop_alg")]
    pub alg: String,
    #[serde(default = "default_dpop_mode")]
    pub mode: String,
}

fn default_dpop_alg() -> String {
    "ES256".to_string()
}

fn default_dpop_mode() -> String {
    "auto".to_string()
}

/// OIDC endpoints discovered from the well-known configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcEndpoints {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub end_session_endpoint: String,
    pub userinfo_endpoint: String,
    pub issuer: String,
    #[serde(default)]
    pub jwks_uri: Option<String>,
}

/// Token set received from the token endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenSet {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub id_token: Option<String>,
    /// Tide-specific doken for encryption/decryption
    #[serde(default)]
    pub doken: Option<String>,
    /// Absolute timestamp (ms since epoch) when the access token expires
    pub expires_at: u64,
}

/// Parsed JWT claims (subset relevant to TideCloak)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    #[serde(default)]
    pub sub: Option<String>,
    #[serde(default)]
    pub exp: Option<u64>,
    #[serde(default)]
    pub iat: Option<u64>,
    #[serde(default)]
    pub preferred_username: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub realm_access: Option<RealmAccess>,
    #[serde(default)]
    pub resource_access: Option<serde_json::Value>,
    /// All raw claims as a JSON value for custom claim extraction
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealmAccess {
    #[serde(default)]
    pub roles: Vec<String>,
}

/// User info extracted from JWT claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub sub: String,
    pub preferred_username: Option<String>,
    pub email: Option<String>,
    pub name: Option<String>,
    pub realm_roles: Vec<String>,
}

/// PKCE challenge/verifier pair
#[derive(Debug, Clone)]
pub struct PkceChallenge {
    pub verifier: String,
    pub challenge: String,
    pub method: String,
}

/// Token endpoint response (raw from server)
#[derive(Debug, Deserialize)]
pub(crate) struct TokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub id_token: Option<String>,
    #[serde(default)]
    pub expires_in: Option<u64>,
    #[serde(default)]
    #[allow(dead_code)]
    pub token_type: Option<String>,
    #[serde(default)]
    pub doken: Option<String>,
}
