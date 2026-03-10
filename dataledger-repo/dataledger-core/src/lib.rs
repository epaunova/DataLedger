//! DataLedger Core
//!
//! Reference implementation of the DataLedger AI training data provenance standard.
//!
//! # Quick Start
//!
//! ```rust
//! use dataledger_core::{Manifest, ManifestBuilder, Keypair};
//!
//! // Generate a keypair (store the private key securely)
//! let keypair = Keypair::generate();
//!
//! // Build and sign a manifest
//! let manifest = ManifestBuilder::new()
//!     .name("My Dataset")
//!     .version("1.0.0")
//!     .source_uri("https://example.org/dataset-v1.tar.gz")
//!     .licence("CC-BY-4.0")
//!     .content_hash_from_bytes(b"...dataset bytes...")
//!     .build_and_sign(&keypair)
//!     .expect("failed to sign manifest");
//!
//! // Verify the manifest
//! manifest.verify().expect("manifest verification failed");
//! ```

pub mod manifest;
pub mod attestation;
pub mod crypto;
pub mod error;

pub use manifest::{Manifest, ManifestBuilder, Split};
pub use attestation::{Attestation, AttestationBuilder, ConsumedManifest};
pub use crypto::Keypair;
pub use error::DataLedgerError;
