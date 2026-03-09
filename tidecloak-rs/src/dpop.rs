use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::EncodedPoint;
use sha2::{Digest, Sha256};
use url::Url;

use crate::error::Result;

/// DPoP (Demonstration of Proof-of-Possession) provider.
///
/// Generates DPoP proofs per RFC 9449 using ECDSA P-256 (ES256).
/// The keypair is ephemeral — generated once per session.
pub struct DPoPProvider {
    signing_key: SigningKey,
    jwk_thumbprint: String,
    /// JWK public key components for the JWT header
    jwk_crv: String,
    jwk_kty: String,
    jwk_x: String,
    jwk_y: String,
    /// Authorization server nonce (from DPoP-Nonce header)
    auth_server_nonce: std::sync::Mutex<Option<String>>,
}

impl DPoPProvider {
    /// Create a new DPoP provider with a fresh ECDSA P-256 keypair
    pub fn new() -> Result<Self> {
        let signing_key = SigningKey::random(&mut rand::thread_rng());
        let verifying_key = signing_key.verifying_key();

        // Export public key coordinates as base64url
        let point = EncodedPoint::from(verifying_key);
        let jwk_crv = "P-256".to_string();
        let jwk_kty = "EC".to_string();
        let jwk_x = URL_SAFE_NO_PAD.encode(point.x().expect("valid x coordinate"));
        let jwk_y = URL_SAFE_NO_PAD.encode(point.y().expect("valid y coordinate"));

        // Compute JWK thumbprint (used for `ath` claim)
        let thumbprint_input = format!(
            r#"{{"crv":"{}","kty":"{}","x":"{}","y":"{}"}}"#,
            jwk_crv, jwk_kty, jwk_x, jwk_y
        );
        let thumbprint_hash = Sha256::digest(thumbprint_input.as_bytes());
        let jwk_thumbprint = URL_SAFE_NO_PAD.encode(thumbprint_hash);

        Ok(Self {
            signing_key,
            jwk_thumbprint,
            jwk_crv,
            jwk_kty,
            jwk_x,
            jwk_y,
            auth_server_nonce: std::sync::Mutex::new(None),
        })
    }

    /// Generate a DPoP proof JWT for a request
    ///
    /// # Arguments
    /// * `http_method` - HTTP method (GET, POST, etc.)
    /// * `url` - The target URL
    /// * `access_token` - Optional access token (included as `ath` claim when calling resource servers)
    /// * `nonce` - Optional server-provided nonce
    pub fn generate_proof(
        &self,
        http_method: &str,
        url: &str,
        access_token: Option<&str>,
        nonce: Option<&str>,
    ) -> Result<String> {
        let parsed_url = Url::parse(url)?;
        // htu = scheme + host + path (no query, no fragment)
        let htu = format!(
            "{}://{}{}",
            parsed_url.scheme(),
            parsed_url.host_str().unwrap_or(""),
            parsed_url.path()
        );

        let jti = uuid::Uuid::new_v4().to_string();
        let iat = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Build header
        let header = serde_json::json!({
            "alg": "ES256",
            "typ": "dpop+jwt",
            "jwk": {
                "crv": self.jwk_crv,
                "kty": self.jwk_kty,
                "x": self.jwk_x,
                "y": self.jwk_y,
            }
        });

        // Build payload
        let mut payload = serde_json::json!({
            "jti": jti,
            "htm": http_method.to_uppercase(),
            "htu": htu,
            "iat": iat,
        });

        // Add `ath` (access token hash) if token provided
        if let Some(token) = access_token {
            let hash = Sha256::digest(token.as_bytes());
            let ath = URL_SAFE_NO_PAD.encode(hash);
            payload["ath"] = serde_json::Value::String(ath);
        }

        // Add nonce if provided
        if let Some(n) = nonce {
            payload["nonce"] = serde_json::Value::String(n.to_string());
        }

        // Encode header and payload
        let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes());
        let unsigned_token = format!("{header_b64}.{payload_b64}");

        // Sign with ECDSA P-256
        let signature: Signature = self.signing_key.sign(unsigned_token.as_bytes());
        let sig_bytes = signature.to_bytes();
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig_bytes);

        Ok(format!("{unsigned_token}.{sig_b64}"))
    }

    /// Get the current authorization server nonce
    pub fn get_auth_server_nonce(&self) -> Option<String> {
        self.auth_server_nonce.lock().unwrap().clone()
    }

    /// Update the authorization server nonce (called after receiving DPoP-Nonce header)
    pub fn update_auth_server_nonce(&self, nonce: String) {
        *self.auth_server_nonce.lock().unwrap() = Some(nonce);
    }

    /// Get the JWK thumbprint
    pub fn thumbprint(&self) -> &str {
        &self.jwk_thumbprint
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_proof() {
        let provider = DPoPProvider::new().unwrap();
        let proof = provider
            .generate_proof("POST", "https://auth.example.com/token", None, None)
            .unwrap();

        // Should be a valid JWT with 3 parts
        let parts: Vec<&str> = proof.split('.').collect();
        assert_eq!(parts.len(), 3);

        // Decode and verify header
        let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["typ"], "dpop+jwt");
        assert!(header["jwk"]["crv"].is_string());

        // Decode and verify payload
        let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(payload["htm"], "POST");
        assert_eq!(payload["htu"], "https://auth.example.com/token");
        assert!(payload["jti"].is_string());
        assert!(payload["iat"].is_number());
    }

    #[test]
    fn test_generate_proof_with_access_token() {
        let provider = DPoPProvider::new().unwrap();
        let proof = provider
            .generate_proof(
                "GET",
                "https://api.example.com/data?page=1",
                Some("fake-access-token"),
                None,
            )
            .unwrap();

        let parts: Vec<&str> = proof.split('.').collect();
        let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

        // Should have ath claim
        assert!(payload["ath"].is_string());
        // htu should NOT include query params
        assert_eq!(payload["htu"], "https://api.example.com/data");
    }

    #[test]
    fn test_generate_proof_with_nonce() {
        let provider = DPoPProvider::new().unwrap();
        let proof = provider
            .generate_proof("POST", "https://auth.example.com/token", None, Some("server-nonce-123"))
            .unwrap();

        let parts: Vec<&str> = proof.split('.').collect();
        let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

        assert_eq!(payload["nonce"], "server-nonce-123");
    }

    #[test]
    fn test_nonce_management() {
        let provider = DPoPProvider::new().unwrap();
        assert!(provider.get_auth_server_nonce().is_none());

        provider.update_auth_server_nonce("nonce1".to_string());
        assert_eq!(provider.get_auth_server_nonce().unwrap(), "nonce1");

        provider.update_auth_server_nonce("nonce2".to_string());
        assert_eq!(provider.get_auth_server_nonce().unwrap(), "nonce2");
    }

    #[test]
    fn test_unique_proofs() {
        let provider = DPoPProvider::new().unwrap();
        let proof1 = provider
            .generate_proof("GET", "https://api.example.com", None, None)
            .unwrap();
        let proof2 = provider
            .generate_proof("GET", "https://api.example.com", None, None)
            .unwrap();
        // Different jti values → different proofs
        assert_ne!(proof1, proof2);
    }
}
