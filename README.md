# DataLedger

**Open Standard for Verifiable AI Training Data Provenance**

DataLedger defines a cryptographic provenance standard for AI training datasets. A dataset publisher signs a manifest document with an ed25519 key. A training pipeline records which manifests it consumed. An auditor or regulator can verify the full chain without trusting any intermediary.

This repository contains:

- `dataledger-spec/` — the manifest and attestation format specification
- `dataledger-core/` — reference implementation in Rust
- `dataledger-py/` — Python bindings (PyO3)
- `cli/` — command-line tool
- `test-vectors/` — conformance test vectors
- `docs/` — developer documentation

## Design Goals

DataLedger is designed to be minimal and composable. It defines two JSON formats and one verification algorithm. It does not require a centralised registry, a network service, or a blockchain. Any tool can implement the standard using only the specification and the test vectors.

DataLedger is composable with the Croissant ML dataset metadata format and with Hugging Face dataset cards.

## Cryptographic Primitives

- Signatures: ed25519 (RFC 8032)
- Content hashing: SHA-256
- Serialisation for signing: RFC 8785 JSON Canonicalisation Scheme (JCS)

## Licence

Code: MIT or Apache 2.0, at your choice.
Specification and documentation: CC-BY 4.0.

## Contact

Eva Paunova 
Codeberg: https://codeberg.org/dataledger/dataledger
