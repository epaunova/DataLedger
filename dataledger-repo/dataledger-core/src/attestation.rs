use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::Utc;
use crate::crypto::sha256_hex;
use crate::error::DataLedgerError;

/// A record of one manifest consumed during a training run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsumedManifest {
    pub manifest_id: String,
    pub version: String,
    pub content_hash: String,
    /// Fraction of training data from this dataset, between 0.0 and 1.0.
    pub proportion: f64,
}

/// A DataLedger training run attestation.
///
/// Produced by a training pipeline at the end of a run.
/// See SPEC.md Section 5 for the full format definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    pub run_id: String,
    pub model_id: String,
    pub started_at: String,
    pub completed_at: String,
    pub manifests_consumed: Vec<ConsumedManifest>,
    pub pipeline_tool: String,
    /// SHA-256 of the RFC 8785 canonicalisation of this document (with this field set to "").
    pub attestation_hash: String,
}

impl Attestation {
    /// Return the attestation hash for embedding in model metadata.
    pub fn hash(&self) -> &str {
        &self.attestation_hash
    }

    /// Verify that the attestation_hash field matches the document content.
    pub fn verify_hash(&self) -> Result<(), DataLedgerError> {
        let mut copy = self.clone();
        copy.attestation_hash = String::new();

        let json_value = serde_json::to_value(&copy)?;
        let canonical = jcs::to_string(&json_value)
            .map_err(|e| DataLedgerError::CanonError(e.to_string()))?;

        let expected = sha256_hex(canonical.as_bytes());
        if expected == self.attestation_hash {
            Ok(())
        } else {
            Err(DataLedgerError::VerificationFailed)
        }
    }

    pub fn to_json_pretty(&self) -> Result<String, DataLedgerError> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    pub fn from_json(json: &str) -> Result<Self, DataLedgerError> {
        Ok(serde_json::from_str(json)?)
    }
}

/// Builder for constructing a [`Attestation`].
#[derive(Default)]
pub struct AttestationBuilder {
    model_id: Option<String>,
    started_at: Option<String>,
    manifests_consumed: Vec<ConsumedManifest>,
    pipeline_tool: Option<String>,
}

impl AttestationBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn model_id(mut self, id: impl Into<String>) -> Self {
        self.model_id = Some(id.into()); self
    }

    pub fn started_at(mut self, t: impl Into<String>) -> Self {
        self.started_at = Some(t.into()); self
    }

    pub fn pipeline_tool(mut self, t: impl Into<String>) -> Self {
        self.pipeline_tool = Some(t.into()); self
    }

    pub fn add_manifest(mut self, m: ConsumedManifest) -> Self {
        self.manifests_consumed.push(m); self
    }

    /// Build the attestation and compute the attestation_hash.
    pub fn build(self) -> Result<Attestation, DataLedgerError> {
        let model_id      = self.model_id.ok_or(DataLedgerError::MissingField("model_id"))?;
        let started_at    = self.started_at.ok_or(DataLedgerError::MissingField("started_at"))?;
        let pipeline_tool = self.pipeline_tool.ok_or(DataLedgerError::MissingField("pipeline_tool"))?;
        let completed_at  = Utc::now().to_rfc3339();

        let mut attestation = Attestation {
            run_id: Uuid::new_v4().to_string(),
            model_id,
            started_at,
            completed_at,
            manifests_consumed: self.manifests_consumed,
            pipeline_tool,
            attestation_hash: String::new(),
        };

        let json_value = serde_json::to_value(&attestation)?;
        let canonical = jcs::to_string(&json_value)
            .map_err(|e| DataLedgerError::CanonError(e.to_string()))?;

        attestation.attestation_hash = sha256_hex(canonical.as_bytes());
        Ok(attestation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attestation_hash_verifies() {
        let attestation = AttestationBuilder::new()
            .model_id("my-model-v1")
            .started_at("2026-04-01T08:00:00Z")
            .pipeline_tool("PyTorch 2.2.0")
            .add_manifest(ConsumedManifest {
                manifest_id: "f47ac10b-58cc-4372-a567-0e02b2c3d479".into(),
                version: "1.0.0".into(),
                content_hash: "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3".into(),
                proportion: 1.0,
            })
            .build()
            .expect("build failed");

        assert!(attestation.verify_hash().is_ok(), "attestation hash should verify");
    }
}
