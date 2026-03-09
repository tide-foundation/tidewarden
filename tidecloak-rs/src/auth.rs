use url::Url;

use crate::config::{effective_scope, realm_url};
use crate::error::{Result, TideCloakError};
use crate::types::{OidcEndpoints, PkceChallenge, TideCloakConfig, TokenResponse, TokenSet};

/// Build the authorization URL for the OIDC login flow.
///
/// The caller should open this URL in a browser (CEF popup or system browser).
/// After the user authenticates, the IdP redirects to `redirect_uri` with an auth code.
pub fn build_auth_url(
    config: &TideCloakConfig,
    endpoints: &OidcEndpoints,
    pkce: &PkceChallenge,
    redirect_uri: &str,
) -> Result<String> {
    let mut url = Url::parse(&endpoints.authorization_endpoint)?;

    url.query_pairs_mut()
        .append_pair("client_id", &config.resource)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("response_type", "code")
        .append_pair("scope", &effective_scope(config))
        .append_pair("code_challenge", &pkce.challenge)
        .append_pair("code_challenge_method", &pkce.method)
        .append_pair("prompt", "login");

    Ok(url.to_string())
}

/// Exchange an authorization code for tokens at the token endpoint.
///
/// This performs the standard OIDC code exchange with PKCE verification.
/// Optionally includes a DPoP proof header.
pub async fn exchange_code(
    config: &TideCloakConfig,
    endpoints: &OidcEndpoints,
    code: &str,
    pkce_verifier: &str,
    redirect_uri: &str,
    dpop_proof: Option<&str>,
) -> Result<TokenSet> {
    let client = reqwest::Client::new();

    let params = [
        ("grant_type", "authorization_code"),
        ("client_id", &config.resource),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("code_verifier", pkce_verifier),
    ];

    let mut req = client
        .post(&endpoints.token_endpoint)
        .form(&params);

    if let Some(proof) = dpop_proof {
        req = req.header("DPoP", proof);
    }

    let resp = req.send().await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(TideCloakError::Auth(format!(
            "Token exchange failed ({status}): {body}"
        )));
    }

    let token_resp: TokenResponse = resp.json().await?;
    Ok(token_response_to_set(token_resp))
}

/// Refresh an access token using a refresh token.
pub async fn refresh_token(
    config: &TideCloakConfig,
    endpoints: &OidcEndpoints,
    refresh_token: &str,
    dpop_proof: Option<&str>,
) -> Result<TokenSet> {
    let client = reqwest::Client::new();

    let params = [
        ("grant_type", "refresh_token"),
        ("client_id", &config.resource),
        ("refresh_token", refresh_token),
    ];

    let mut req = client
        .post(&endpoints.token_endpoint)
        .form(&params);

    if let Some(proof) = dpop_proof {
        req = req.header("DPoP", proof);
    }

    let resp = req.send().await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(TideCloakError::Auth(format!(
            "Token refresh failed ({status}): {body}"
        )));
    }

    let token_resp: TokenResponse = resp.json().await?;
    Ok(token_response_to_set(token_resp))
}

/// Build the logout URL. The caller should navigate to this URL to end the session.
pub fn build_logout_url(
    config: &TideCloakConfig,
    endpoints: &OidcEndpoints,
    id_token_hint: Option<&str>,
    post_logout_redirect_uri: Option<&str>,
) -> Result<String> {
    let mut url = Url::parse(&endpoints.end_session_endpoint)?;

    {
        let mut q = url.query_pairs_mut();
        q.append_pair("client_id", &config.resource);
        if let Some(hint) = id_token_hint {
            q.append_pair("id_token_hint", hint);
        }
        if let Some(redirect) = post_logout_redirect_uri {
            q.append_pair("post_logout_redirect_uri", redirect);
        }
    }

    Ok(url.to_string())
}

/// Build the token endpoint URL from config (fallback if OIDC discovery not done)
pub fn token_endpoint_url(config: &TideCloakConfig) -> String {
    format!(
        "{}/protocol/openid-connect/token",
        realm_url(config)
    )
}

fn token_response_to_set(resp: TokenResponse) -> TokenSet {
    let expires_at = resp.expires_in.map_or_else(
        || {
            // Default to 5 minutes if not provided
            now_ms() + 300_000
        },
        |secs| now_ms() + secs * 1000,
    );

    TokenSet {
        access_token: resp.access_token,
        refresh_token: resp.refresh_token,
        id_token: resp.id_token,
        doken: resp.doken,
        expires_at,
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pkce::make_pkce;

    fn test_config() -> TideCloakConfig {
        TideCloakConfig {
            auth_server_url: "https://auth.example.com".to_string(),
            realm: "myrealm".to_string(),
            resource: "myclient".to_string(),
            scope: None,
            vendor_id: None,
            home_ork_url: None,
            auth_mode: "native".to_string(),
            use_dpop: None,
        }
    }

    fn test_endpoints() -> OidcEndpoints {
        OidcEndpoints {
            authorization_endpoint: "https://auth.example.com/realms/myrealm/protocol/openid-connect/auth".to_string(),
            token_endpoint: "https://auth.example.com/realms/myrealm/protocol/openid-connect/token".to_string(),
            end_session_endpoint: "https://auth.example.com/realms/myrealm/protocol/openid-connect/logout".to_string(),
            userinfo_endpoint: "https://auth.example.com/realms/myrealm/protocol/openid-connect/userinfo".to_string(),
            issuer: "https://auth.example.com/realms/myrealm".to_string(),
            jwks_uri: None,
        }
    }

    #[test]
    fn test_build_auth_url() {
        let config = test_config();
        let endpoints = test_endpoints();
        let pkce = make_pkce();
        let redirect_uri = "http://localhost:8080/callback";

        let url = build_auth_url(&config, &endpoints, &pkce, redirect_uri).unwrap();
        assert!(url.contains("client_id=myclient"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("code_challenge="));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("prompt=login"));
        assert!(url.contains("scope=openid+profile+email"));
    }

    #[test]
    fn test_build_logout_url() {
        let config = test_config();
        let endpoints = test_endpoints();

        let url = build_logout_url(&config, &endpoints, Some("id-tok"), Some("http://localhost:8080")).unwrap();
        assert!(url.contains("client_id=myclient"));
        assert!(url.contains("id_token_hint=id-tok"));
        assert!(url.contains("post_logout_redirect_uri="));
    }

    #[test]
    fn test_token_endpoint_url() {
        let config = test_config();
        assert_eq!(
            token_endpoint_url(&config),
            "https://auth.example.com/realms/myrealm/protocol/openid-connect/token"
        );
    }
}
