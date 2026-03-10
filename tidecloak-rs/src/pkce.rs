use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::Rng;
use sha2::{Digest, Sha256};

use crate::types::PkceChallenge;

const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
const VERIFIER_LENGTH: usize = 96;

/// Generate a random PKCE verifier string
fn random_verifier(len: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// Generate a PKCE challenge/verifier pair using S256 method
pub fn make_pkce() -> PkceChallenge {
    let verifier = random_verifier(VERIFIER_LENGTH);
    let digest = Sha256::digest(verifier.as_bytes());
    let challenge = URL_SAFE_NO_PAD.encode(digest);

    PkceChallenge {
        verifier,
        challenge,
        method: "S256".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_make_pkce() {
        let pkce = make_pkce();
        assert_eq!(pkce.verifier.len(), VERIFIER_LENGTH);
        assert_eq!(pkce.method, "S256");
        // Challenge should be base64url-encoded SHA-256 (43 chars without padding)
        assert_eq!(pkce.challenge.len(), 43);

        // Verify the challenge matches the verifier
        let digest = Sha256::digest(pkce.verifier.as_bytes());
        let expected = URL_SAFE_NO_PAD.encode(digest);
        assert_eq!(pkce.challenge, expected);
    }

    #[test]
    fn test_verifier_characters() {
        let verifier = random_verifier(1000);
        for ch in verifier.chars() {
            assert!(
                ch.is_ascii_alphanumeric() || ch == '-' || ch == '.' || ch == '_' || ch == '~',
                "Invalid character in verifier: {ch}"
            );
        }
    }

    #[test]
    fn test_uniqueness() {
        let p1 = make_pkce();
        let p2 = make_pkce();
        assert_ne!(p1.verifier, p2.verifier);
        assert_ne!(p1.challenge, p2.challenge);
    }
}
