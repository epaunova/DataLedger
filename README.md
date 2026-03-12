# DataLedger

**Open Standard for Verifiable AI Training Data Provenance**

DataLedger defines a cryptographic provenance standard for AI training datasets. A dataset publisher signs a manifest document with an ed25519 key. A training pipeline records which manifests it consumed. Any researcher, auditor, or downstream user can verify the full chain without trusting any intermediary.

This repository contains:

- `dataledger-spec/` the manifest and attestation format specification
- `dataledger-core/` reference implementation in Rust
- `dataledger-py/` Python bindings (PyO3)
- `cli/` command-line tool
- `test-vectors/` conformance test vectors
- `docs/` developer documentation

## Status

This project is under active development as part of an NGI Zero Commons Fund application (April 2026). The specification is at draft stage. No stable release exists yet.

## Design Goals

DataLedger is designed to be minimal and composable. It defines two JSON formats and one verification algorithm. It does not require a centralised registry, a network service, or a blockchain. Any tool can implement the standard using only the specification and the test vectors.

DataLedger is composable with the Croissant ML dataset metadata format and with Hugging Face dataset cards.

## Cryptographic Primitives

- Signatures: ed25519 (RFC 8032)
- Content hashing: SHA-256
- Serialisation for signing: RFC 8785 JSON Canonicalisation Scheme (JCS)

# dataledger-core

Rust implementation of the DataLedger specification.

## Status

**Current:** Python proof-of-concept (`dataledger_poc.py`) fully working, 12 passing tests.  
**In progress:** Rust library — architecture complete, implementation in progress.

The Python PoC validates the full protocol:
- ed25519 signing over RFC 8785 canonical JSON
- Manifest verification and tamper detection
- Training run attestation with proportional consumption
- Croissant metadata composability

Run the PoC:

```bash
pip install cryptography
python3 dataledger_poc.py
```

Run the tests:

```bash
pip install pytest cryptography
python3 -m pytest dataledger_poc.py -v
```

Expected output: `12 passed in 0.14s`

## Rust Library

The Rust implementation (`src/`) targets the same API as the Python PoC.
Primary crates: `ed25519-dalek 2.x`, `sha2`, `serde_json`, `jcs`.

```bash
cargo test
```

## Why Both?

The Python PoC was written first to validate the protocol design before
committing to a Rust implementation. The signing procedure, canonical JSON
behaviour, and attestation format are all proven correct in Python.
The Rust library provides the production-grade implementation for
infrastructure tooling that requires performance and memory safety.

## Licence

Code: MIT or Apache 2.0, at your choice.
Specification and documentation: CC-BY 4.0.

## Contact

Eva Paunova 
