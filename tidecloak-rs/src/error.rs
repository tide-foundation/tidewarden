use thiserror::Error;

#[derive(Error, Debug)]
pub enum TideCloakError {
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),

    #[error("JSON parse error: {0}")]
    Parse(#[from] serde_json::Error),

    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),

    #[error("Config error: {0}")]
    Config(String),

    #[error("Auth error: {0}")]
    Auth(String),

    #[error("Token error: {0}")]
    Token(String),

    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Crypto error: {0}")]
    Crypto(String),
}

pub type Result<T> = std::result::Result<T, TideCloakError>;
