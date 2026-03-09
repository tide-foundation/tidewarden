use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use crate::error::{Result, TideCloakError};
use crate::types::JwtClaims;

/// Decode a JWT payload without verifying the signature.
/// TideCloak server handles verification — the client only needs to read claims.
pub fn decode_jwt(token: &str) -> Result<JwtClaims> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(TideCloakError::Token(format!(
            "Invalid JWT: expected 3 parts, got {}",
            parts.len()
        )));
    }

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .or_else(|_| {
            // Try with standard base64 padding variants
            let padded = match parts[1].len() % 4 {
                2 => format!("{}==", parts[1]),
                3 => format!("{}=", parts[1]),
                _ => parts[1].to_string(),
            };
            URL_SAFE_NO_PAD.decode(&padded)
        })
        .map_err(|e| TideCloakError::Token(format!("Invalid JWT base64: {e}")))?;

    let claims: JwtClaims = serde_json::from_slice(&payload_bytes)?;
    Ok(claims)
}

/// Check if a JWT is expired. Returns true if expired.
pub fn is_expired(token: &str) -> bool {
    match decode_jwt(token) {
        Ok(claims) => {
            if let Some(exp) = claims.exp {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                exp <= now
            } else {
                // No exp claim — treat as not expired
                false
            }
        }
        Err(_) => true,
    }
}

/// Check if a JWT will expire within the given number of seconds.
pub fn expires_within(token: &str, seconds: u64) -> bool {
    match decode_jwt(token) {
        Ok(claims) => {
            if let Some(exp) = claims.exp {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                exp <= now + seconds
            } else {
                false
            }
        }
        Err(_) => true,
    }
}

/// Extract a specific claim value from a JWT
pub fn get_claim(token: &str, key: &str) -> Result<Option<serde_json::Value>> {
    let claims = decode_jwt(token)?;
    Ok(claims.extra.get(key).cloned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_jwt(payload: &serde_json::Value) -> String {
        let header = serde_json::json!({"alg": "RS256", "typ": "JWT"});
        let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).unwrap());
        format!("{h}.{p}.fakesignature")
    }

    #[test]
    fn test_decode_jwt() {
        let jwt = make_test_jwt(&serde_json::json!({
            "sub": "user123",
            "preferred_username": "john",
            "exp": 9999999999u64,
            "realm_access": { "roles": ["admin", "user"] }
        }));

        let claims = decode_jwt(&jwt).unwrap();
        assert_eq!(claims.sub.as_deref(), Some("user123"));
        assert_eq!(claims.preferred_username.as_deref(), Some("john"));
        assert_eq!(claims.exp, Some(9999999999));
        assert_eq!(
            claims.realm_access.as_ref().unwrap().roles,
            vec!["admin", "user"]
        );
    }

    #[test]
    fn test_is_expired() {
        let expired_jwt = make_test_jwt(&serde_json::json!({
            "sub": "user123",
            "exp": 1000000000u64
        }));
        assert!(is_expired(&expired_jwt));

        let valid_jwt = make_test_jwt(&serde_json::json!({
            "sub": "user123",
            "exp": 9999999999u64
        }));
        assert!(!is_expired(&valid_jwt));
    }

    #[test]
    fn test_invalid_jwt() {
        assert!(decode_jwt("not.a.valid.jwt.at.all").is_err());
        assert!(decode_jwt("only-one-part").is_err());
    }
}
