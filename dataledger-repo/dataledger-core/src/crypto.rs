use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier, Signature};
use rand::rngs::OsRng;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use crate::error::DataLedgerError;

/// An ed25519 keypair used for signing dataset manifests.
pub struct Keypair {
    pub(crate) signing_key: SigningKey,
}

impl Keypair {
    /// Generate a new random keypair using the OS random number generator.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Load a signing key from raw bytes (32 bytes).
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self { signing_key: SigningKey::from_bytes(bytes) }
    }

    /// Return the public key as a base64url-encoded string (no padding).
    pub fn public_key_base64url(&self) -> String {
        let vk: VerifyingKey = self.signing_key.verifying_key();
        URL_SAFE_NO_PAD.encode(vk.as_bytes())
    }

    /// Sign arbitrary bytes and return the signature as base64url (no padding).
    pub fn sign_bytes(&self, data: &[u8]) -> String {
        let sig: Signature = self.signing_key.sign(data);
        URL_SAFE_NO_PAD.encode(sig.to_bytes())
    }
}

/// Verify an ed25519 signature.
///
/// # Arguments
/// * `public_key_b64` - base64url-encoded 32-byte public key (no padding)
/// * `signature_b64`  - base64url-encoded 64-byte signature (no padding)
/// * `message`        - the signed byte sequence
pub fn verify(
    public_key_b64: &str,
    signature_b64: &str,
    message: &[u8],
) -> Result<(), DataLedgerError> {
    let key_bytes = URL_SAFE_NO_PAD.decode(public_key_b64)?;
    let key_array: [u8; 32] = key_bytes.try_into()
        .map_err(|_| DataLedgerError::CryptoError("public key must be 32 bytes".into()))?;
    let vk = VerifyingKey::from_bytes(&key_array)
        .map_err(|e| DataLedgerError::CryptoError(e.to_string()))?;

    let sig_bytes = URL_SAFE_NO_PAD.decode(signature_b64)?;
    let sig_array: [u8; 64] = sig_bytes.try_into()
        .map_err(|_| DataLedgerError::CryptoError("signature must be 64 bytes".into()))?;
    let sig = Signature::from_bytes(&sig_array);

    vk.verify(message, &sig)
        .map_err(|_| DataLedgerError::VerificationFailed)
}

/// Compute a SHA-256 digest and return as lowercase hex string.
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}
