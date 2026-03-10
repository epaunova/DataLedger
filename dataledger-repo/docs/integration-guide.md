# DataLedger Integration Guide

This guide explains how to integrate DataLedger into a dataset publishing or training pipeline workflow.

## For Dataset Publishers

A dataset publisher is any person or organisation that creates and distributes a dataset. To sign a manifest:

1. Generate an ed25519 keypair once. Store the private key securely. Publish the public key at a stable URI (e.g. `https://yourorganisation.org/.well-known/dataledger-key.json`).

2. For each dataset release, create a manifest describing the dataset. The `content_hash` field must be the SHA-256 digest of the canonical dataset archive that consumers will download.

3. Sign the manifest using the DataLedger CLI or the Python library.

4. Publish the signed manifest alongside the dataset. A conventional location is `dataledger-manifest.json` at the root of the dataset repository.

## For Training Pipeline Developers

A training pipeline that consumes DataLedger-signed datasets should:

1. Before using a dataset, call `dataledger manifest verify` (CLI) or `manifest.verify()` (Python) to confirm the manifest is authentic and the content hash matches the downloaded file.

2. At the start of training, record the manifest IDs and versions of all datasets to be consumed.

3. At the end of training, call `dataledger attest create` or `AttestationBuilder.build()` to produce a training run attestation.

4. Embed the `attestation_hash` value in the model card or config file using `dataledger attest embed` or manually adding it to the YAML front matter.

## For Auditors and Regulators

To verify a model's training data provenance:

1. Obtain the `attestation_hash` from the model card YAML front matter (`dataledger.attestation_hash`).

2. Obtain the attestation document (from `dataledger.attestation_uri` if present, or from the model developer).

3. Verify that SHA-256 of the RFC 8785 canonicalisation of the attestation document (with `attestation_hash` set to empty string) equals the value embedded in the model card.

4. For each manifest listed in `manifests_consumed`, obtain the manifest document from the dataset publisher's repository and call `dataledger manifest verify` to confirm authenticity.

## Hugging Face Model Card Example

```yaml
---
license: apache-2.0
dataledger:
  attestation_hash: "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
  attestation_uri: "https://example.org/attestations/run-20260401.json"
---
```

## EU AI Act Relevance

For high-risk AI systems subject to EU AI Act Article 10 and Annex IV, DataLedger manifests and attestations provide verifiable technical documentation of training data sources. The attestation_hash embedded in model metadata creates an auditable link that can be presented to a conformity assessment body.

DataLedger is not a compliance certification tool. It provides the cryptographic provenance substrate on which compliance documentation can be built.
