use thiserror::Error;

#[derive(Debug, Error)]
pub enum DataLedgerError {
    #[error("signature verification failed")]
    VerificationFailed,

    #[error("invalid base64url encoding: {0}")]
    Base64Error(#[from] base64::DecodeError),

    #[error("invalid ed25519 key or signature: {0}")]
    CryptoError(String),

    #[error("JSON serialisation error: {0}")]
    SerdeError(#[from] serde_json::Error),

    #[error("canonicalisation error: {0}")]
    CanonError(String),

    #[error("missing required field: {0}")]
    MissingField(&'static str),

    #[error("invalid field value for '{field}': {reason}")]
    InvalidField { field: &'static str, reason: String },
}
