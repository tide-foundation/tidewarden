use crate::error::{Result, TideCloakError};
use crate::types::{OidcEndpoints, TideCloakConfig};
use std::path::Path;

/// Load TideCloak config from a JSON file
pub fn load_config(path: &Path) -> Result<TideCloakConfig> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| TideCloakError::Config(format!("Failed to read config file: {e}")))?;
    let config: TideCloakConfig = serde_json::from_str(&contents)?;

    if config.auth_server_url.is_empty() {
        return Err(TideCloakError::Config(
            "auth-server-url is required".to_string(),
        ));
    }
    if config.realm.is_empty() {
        return Err(TideCloakError::Config("realm is required".to_string()));
    }
    if config.resource.is_empty() {
        return Err(TideCloakError::Config("resource is required".to_string()));
    }

    Ok(config)
}

/// Discover OIDC endpoints from the well-known configuration URL
pub async fn discover_oidc(config: &TideCloakConfig) -> Result<OidcEndpoints> {
    let base = config.auth_server_url.trim_end_matches('/');
    let realm = &config.realm;
    let well_known_url = format!(
        "{base}/realms/{realm}/.well-known/openid-configuration"
    );

    let client = reqwest::Client::new();
    let resp = client.get(&well_known_url).send().await?;

    if !resp.status().is_success() {
        return Err(TideCloakError::Config(format!(
            "OIDC discovery failed with status {}: {}",
            resp.status(),
            well_known_url
        )));
    }

    let endpoints: OidcEndpoints = resp.json().await?;
    Ok(endpoints)
}

/// Build the realm base URL (no trailing slash)
pub fn realm_url(config: &TideCloakConfig) -> String {
    let base = config.auth_server_url.trim_end_matches('/');
    format!("{base}/realms/{}", config.realm)
}

/// Get the effective scope string
pub fn effective_scope(config: &TideCloakConfig) -> String {
    config
        .scope
        .clone()
        .unwrap_or_else(|| "openid profile email".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_realm_url() {
        let config = TideCloakConfig {
            auth_server_url: "https://auth.example.com".to_string(),
            realm: "myrealm".to_string(),
            resource: "myclient".to_string(),
            scope: None,
            vendor_id: None,
            home_ork_url: None,
            auth_mode: "native".to_string(),
            use_dpop: None,
        };
        assert_eq!(
            realm_url(&config),
            "https://auth.example.com/realms/myrealm"
        );
    }

    #[test]
    fn test_effective_scope_default() {
        let config = TideCloakConfig {
            auth_server_url: "https://auth.example.com".to_string(),
            realm: "myrealm".to_string(),
            resource: "myclient".to_string(),
            scope: None,
            vendor_id: None,
            home_ork_url: None,
            auth_mode: "native".to_string(),
            use_dpop: None,
        };
        assert_eq!(effective_scope(&config), "openid profile email");
    }

    #[test]
    fn test_effective_scope_custom() {
        let config = TideCloakConfig {
            auth_server_url: "https://auth.example.com".to_string(),
            realm: "myrealm".to_string(),
            resource: "myclient".to_string(),
            scope: Some("openid custom".to_string()),
            vendor_id: None,
            home_ork_url: None,
            auth_mode: "native".to_string(),
            use_dpop: None,
        };
        assert_eq!(effective_scope(&config), "openid custom");
    }
}
