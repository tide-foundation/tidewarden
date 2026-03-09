pub mod error;
pub mod types;
pub mod config;
pub mod jwt;
pub mod pkce;
pub mod auth;
pub mod token;
pub mod dpop;
pub mod admin;
#[cfg(feature = "ffi")]
pub mod ffi;

// Re-export primary types for convenience
pub use error::{Result, TideCloakError};
pub use types::{
    TideCloakConfig, OidcEndpoints, TokenSet, JwtClaims, UserInfo, PkceChallenge,
};
pub use config::{load_config, discover_oidc, realm_url};
pub use jwt::{decode_jwt, is_expired, expires_within};
pub use pkce::make_pkce;
pub use auth::{build_auth_url, exchange_code, refresh_token, build_logout_url};
pub use token::TokenManager;
pub use dpop::DPoPProvider;
pub use admin::AdminClient;
