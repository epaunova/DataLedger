# dataledger-py

Python bindings for the DataLedger reference implementation.

Built with [PyO3](https://pyo3.rs). Wraps `dataledger-core` (Rust).

## Status

Under development. Not yet published to PyPI.

## Planned API

```python
import dataledger

# Generate a keypair
keypair = dataledger.Keypair.generate()
print(keypair.public_key_base64url())

# Build and sign a manifest
manifest = (
    dataledger.ManifestBuilder()
    .name("My Dataset")
    .version("1.0.0")
    .source_uri("https://example.org/dataset-v1.tar.gz")
    .licence("CC-BY-4.0")
    .content_hash_from_bytes(b"...dataset bytes...")
    .build_and_sign(keypair)
)

# Verify
manifest.verify()  # raises DataLedgerError on failure

# Serialise
print(manifest.to_json_pretty())

# Attestation
attestation = (
    dataledger.AttestationBuilder()
    .model_id("my-model-v1")
    .started_at("2026-04-01T08:00:00Z")
    .pipeline_tool("PyTorch 2.2.0")
    .add_manifest(dataledger.ConsumedManifest(
        manifest_id=manifest.id,
        version=manifest.version,
        content_hash=manifest.content_hash,
        proportion=1.0,
    ))
    .build()
)

print(attestation.hash())  # embed in model card
```

## Build

Requires Rust and [maturin](https://www.maturin.rs).

```bash
pip install maturin
maturin develop
```
