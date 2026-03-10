use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::Utc;
use crate::crypto::{sha256_hex, verify, Keypair};
use crate::error::DataLedgerError;

/// A split descriptor within a dataset manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Split {
    pub name: String,
    pub file_count: u64,
    pub row_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
}

/// A signed DataLedger dataset manifest.
///
/// See SPEC.md Section 4 for the full format definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub id: String,
    pub version: String,
    pub name: String,
    pub source_uri: String,
    pub licence: String,
    pub content_hash: String,
    pub created_at: String,
    pub publisher_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub splits: Option<Vec<Split>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub homepage: Option<String>,
    pub signature: String,
}

impl Manifest {
    /// Verify the manifest's signature.
    ///
    /// Returns `Ok(())` if the signature is valid, or a `DataLedgerError` if not.
    pub fn verify(&self) -> Result<(), DataLedgerError> {
        // Reconstruct the unsigned manifest (signature field set to empty string)
        let mut unsigned = self.clone();
        unsigned.signature = String::new();

        // Serialise to canonical JSON (RFC 8785 JCS)
        let json_value = serde_json::to_value(&unsigned)?;
        let canonical = jcs::to_string(&json_value)
            .map_err(|e| DataLedgerError::CanonError(e.to_string()))?;

        verify(&self.publisher_key, &self.signature, canonical.as_bytes())
    }

    /// Serialise the manifest to a pretty-printed JSON string.
    pub fn to_json_pretty(&self) -> Result<String, DataLedgerError> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Deserialise a manifest from a JSON string.
    pub fn from_json(json: &str) -> Result<Self, DataLedgerError> {
        Ok(serde_json::from_str(json)?)
    }
}

/// Builder for constructing and signing a [`Manifest`].
#[derive(Default)]
pub struct ManifestBuilder {
    version: Option<String>,
    name: Option<String>,
    source_uri: Option<String>,
    licence: Option<String>,
    content_hash: Option<String>,
    splits: Option<Vec<Split>>,
    description: Option<String>,
    homepage: Option<String>,
}

impl ManifestBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn version(mut self, v: impl Into<String>) -> Self {
        self.version = Some(v.into()); self
    }

    pub fn name(mut self, n: impl Into<String>) -> Self {
        self.name = Some(n.into()); self
    }

    pub fn source_uri(mut self, u: impl Into<String>) -> Self {
        self.source_uri = Some(u.into()); self
    }

    pub fn licence(mut self, l: impl Into<String>) -> Self {
        self.licence = Some(l.into()); self
    }

    /// Set the content hash from a pre-computed hex string.
    pub fn content_hash(mut self, h: impl Into<String>) -> Self {
        self.content_hash = Some(h.into()); self
    }

    /// Compute the content hash from raw bytes.
    pub fn content_hash_from_bytes(mut self, data: &[u8]) -> Self {
        self.content_hash = Some(sha256_hex(data)); self
    }

    pub fn splits(mut self, splits: Vec<Split>) -> Self {
        self.splits = Some(splits); self
    }

    pub fn description(mut self, d: impl Into<String>) -> Self {
        self.description = Some(d.into()); self
    }

    pub fn homepage(mut self, h: impl Into<String>) -> Self {
        self.homepage = Some(h.into()); self
    }

    /// Build and sign the manifest.
    pub fn build_and_sign(self, keypair: &Keypair) -> Result<Manifest, DataLedgerError> {
        let version   = self.version.ok_or(DataLedgerError::MissingField("version"))?;
        let name      = self.name.ok_or(DataLedgerError::MissingField("name"))?;
        let source_uri = self.source_uri.ok_or(DataLedgerError::MissingField("source_uri"))?;
        let licence   = self.licence.ok_or(DataLedgerError::MissingField("licence"))?;
        let content_hash = self.content_hash.ok_or(DataLedgerError::MissingField("content_hash"))?;

        let mut manifest = Manifest {
            id: Uuid::new_v4().to_string(),
            version,
            name,
            source_uri,
            licence,
            content_hash,
            created_at: Utc::now().to_rfc3339(),
            publisher_key: keypair.public_key_base64url(),
            splits: self.splits,
            description: self.description,
            homepage: self.homepage,
            signature: String::new(),
        };

        // Sign over the canonicalised unsigned manifest
        let json_value = serde_json::to_value(&manifest)?;
        let canonical = jcs::to_string(&json_value)
            .map_err(|e| DataLedgerError::CanonError(e.to_string()))?;

        manifest.signature = keypair.sign_bytes(canonical.as_bytes());
        Ok(manifest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_sign_and_verify() {
        let keypair = Keypair::generate();
        let manifest = ManifestBuilder::new()
            .name("Test Dataset")
            .version("1.0.0")
            .source_uri("https://example.org/test.tar.gz")
            .licence("CC-BY-4.0")
            .content_hash_from_bytes(b"fake dataset content")
            .build_and_sign(&keypair)
            .expect("sign failed");

        assert!(manifest.verify().is_ok(), "verification should pass");
    }

    #[test]
    fn tampered_manifest_fails_verification() {
        let keypair = Keypair::generate();
        let mut manifest = ManifestBuilder::new()
            .name("Test Dataset")
            .version("1.0.0")
            .source_uri("https://example.org/test.tar.gz")
            .licence("CC-BY-4.0")
            .content_hash_from_bytes(b"original content")
            .build_and_sign(&keypair)
            .expect("sign failed");

        // Tamper with the name after signing
        manifest.name = "Tampered Dataset".into();

        assert!(manifest.verify().is_err(), "tampered manifest should fail verification");
    }

    #[test]
    fn json_roundtrip() {
        let keypair = Keypair::generate();
        let manifest = ManifestBuilder::new()
            .name("JSON Test")
            .version("0.1.0")
            .source_uri("https://example.org/json-test.tar.gz")
            .licence("MIT")
            .content_hash_from_bytes(b"json test content")
            .build_and_sign(&keypair)
            .expect("sign failed");

        let json = manifest.to_json_pretty().expect("serialise failed");
        let recovered = Manifest::from_json(&json).expect("deserialise failed");
        assert!(recovered.verify().is_ok(), "recovered manifest should verify");
    }
}
