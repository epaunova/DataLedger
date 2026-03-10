# DataLedger Specification

**Version:** 0.1-draft
**Date:** April 2026
**Status:** Draft — open for public review
**Licence:** CC-BY 4.0

---

## 1. Introduction

DataLedger defines two JSON document formats and one cryptographic verification algorithm:

1. The **dataset manifest** — a signed document created by a dataset publisher that records the identity, version, content hash, and licence of a dataset.
2. The **training run attestation** — an unsigned document created by a training pipeline that records which manifests were consumed and in what proportions.

The goal is to allow any downstream consumer — a pipeline, an auditor, or a regulator — to verify that a dataset manifest is authentic and unmodified, and to confirm which datasets entered a training run, without trusting any intermediary.

---

## 2. Definitions

| Term | Definition |
|------|------------|
| Publisher | The entity that creates and signs a dataset manifest |
| Consumer | Any entity that downloads or uses a published dataset |
| Manifest | A signed JSON document describing one version of a dataset |
| Attestation | An unsigned JSON document recording manifests consumed during a training run |
| Content hash | SHA-256 hex digest of the canonical dataset archive |
| Signing key | An ed25519 private key held by the publisher |
| Verification key | The corresponding ed25519 public key, distributed by the publisher |

---

## 3. Cryptographic Primitives

DataLedger uses only well-established, publicly audited primitives.

**Signature scheme:** ed25519 as defined in RFC 8032. Signatures are 64 bytes. Public keys are 32 bytes. Both are encoded as base64url (no padding) when stored in JSON.

**Content hashing:** SHA-256. The digest is encoded as a lowercase hex string of 64 characters.

**Serialisation for signing:** RFC 8785 JSON Canonicalisation Scheme (JCS). Before signing, the manifest document is canonicalised according to RFC 8785. This ensures that two JSON documents with identical semantic content but different key ordering or whitespace produce identical byte sequences and therefore identical signatures.

---

## 4. Dataset Manifest Format

A dataset manifest is a JSON object with the following fields.

### 4.1 Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string (UUID v4) | Unique identifier assigned by the publisher at manifest creation time |
| `version` | string (semver) | Version of the dataset, e.g. `"1.0.0"` |
| `name` | string | Human-readable name of the dataset |
| `source_uri` | string (URI) | Canonical URI where the dataset can be obtained |
| `licence` | string (SPDX) | SPDX licence identifier, e.g. `"CC-BY-4.0"` or `"Apache-2.0"` |
| `content_hash` | string (hex) | SHA-256 hex digest of the canonical dataset archive |
| `created_at` | string (ISO 8601) | Timestamp of manifest creation in UTC, e.g. `"2026-04-01T12:00:00Z"` |
| `publisher_key` | string (base64url) | ed25519 public key of the publisher, base64url-encoded without padding |
| `signature` | string (base64url) | ed25519 signature over the canonicalised manifest, base64url-encoded without padding |

### 4.2 Optional Fields

| Field | Type | Description |
|-------|------|-------------|
| `splits` | array | Array of split descriptors (see Section 4.3) |
| `description` | string | Free-text description of the dataset |
| `homepage` | string (URI) | Project homepage URI |
| `croissant` | object | Embedded Croissant 1.0 metadata object |

### 4.3 Split Descriptor

Each object in the `splits` array has the following fields:

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Split name, e.g. `"train"`, `"validation"`, `"test"` |
| `file_count` | integer | Number of files in the split |
| `row_count` | integer | Number of rows or examples in the split |
| `content_hash` | string (hex) | SHA-256 digest of the split archive, if applicable |

### 4.4 Signing Procedure

1. Construct the manifest JSON object with all required fields, setting `signature` to the empty string `""`.
2. Canonicalise the object using RFC 8785 JCS to produce a deterministic byte sequence.
3. Sign the byte sequence with the publisher's ed25519 private key to produce a 64-byte signature.
4. Encode the signature as base64url without padding.
5. Set the `signature` field to the encoded value.

### 4.5 Verification Procedure

1. Extract the `signature` field value and decode it from base64url to 64 bytes.
2. Set the `signature` field to the empty string `""` in the manifest object.
3. Canonicalise the modified object using RFC 8785 JCS to produce a deterministic byte sequence.
4. Decode the `publisher_key` field from base64url to 32 bytes.
5. Verify the signature over the byte sequence using the ed25519 public key.
6. If verification succeeds, the manifest is authentic and unmodified.

### 4.6 Example Manifest

```json
{
  "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "version": "1.0.0",
  "name": "Example NLP Dataset",
  "source_uri": "https://example.org/datasets/example-nlp-v1.0.0.tar.gz",
  "licence": "CC-BY-4.0",
  "content_hash": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
  "created_at": "2026-04-01T12:00:00Z",
  "publisher_key": "MCowBQYDK2VdAyEA...",
  "splits": [
    { "name": "train",      "file_count": 10, "row_count": 100000 },
    { "name": "validation", "file_count": 1,  "row_count": 5000   },
    { "name": "test",       "file_count": 1,  "row_count": 5000   }
  ],
  "signature": "base64url-encoded-64-byte-signature"
}
```

---

## 5. Training Run Attestation Format

A training run attestation is a JSON object produced by a training pipeline at the end of a training run.

### 5.1 Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `run_id` | string (UUID v4) | Unique identifier for this training run |
| `model_id` | string | Identifier of the resulting model |
| `started_at` | string (ISO 8601) | Training run start time in UTC |
| `completed_at` | string (ISO 8601) | Training run completion time in UTC |
| `manifests_consumed` | array | Array of consumed manifest records (see Section 5.2) |
| `pipeline_tool` | string | Name and version of the training framework, e.g. `"PyTorch 2.2.0"` |
| `attestation_hash` | string (hex) | SHA-256 of the RFC 8785 canonicalisation of this attestation document (excluding this field, set to `""` during hashing) |

### 5.2 Consumed Manifest Record

Each object in `manifests_consumed` has:

| Field | Type | Description |
|-------|------|-------------|
| `manifest_id` | string (UUID v4) | The `id` field of the consumed manifest |
| `version` | string | The `version` field of the consumed manifest |
| `content_hash` | string (hex) | The `content_hash` field of the consumed manifest, for cross-verification |
| `proportion` | number | Fraction of training data contributed by this dataset, between 0.0 and 1.0 inclusive |

### 5.3 Attestation Hash Procedure

1. Construct the attestation JSON object with all required fields, setting `attestation_hash` to `""`.
2. Canonicalise the object using RFC 8785 JCS.
3. Compute the SHA-256 digest of the byte sequence.
4. Encode as a lowercase hex string.
5. Set the `attestation_hash` field to the encoded value.
6. Embed this value in model metadata (e.g. the `dataledger_attestation_hash` field of a Hugging Face model card YAML front matter).

---

## 6. Hugging Face Integration

To embed a DataLedger attestation hash in a Hugging Face model card, add the following to the YAML front matter of the `README.md` file in the model repository:

```yaml
dataledger:
  attestation_hash: "sha256-hex-digest-of-attestation"
  attestation_uri: "https://example.org/attestations/run-f47ac10b.json"
```

The `attestation_uri` field is optional and points to the full attestation document for download and verification.

---

## 7. Croissant Composability

A Croissant 1.0 metadata object may be embedded in the `croissant` field of a DataLedger manifest. The presence of this field does not alter the signing or verification procedure. The signature covers the full manifest including any embedded Croissant metadata.

---

## 8. What DataLedger Does Not Provide

DataLedger does not provide:

- Automated licence enforcement or access control
- Data quality assessment or bias detection
- Key distribution infrastructure
- Revocation of previously issued manifests
- Compliance certification for any regulatory framework

These are important problems that may be addressed by tooling built on top of DataLedger.

---

## 9. Changelog

| Version | Date | Changes |
|---------|------|---------|
| 0.1-draft | April 2026 | Initial draft for public review |
