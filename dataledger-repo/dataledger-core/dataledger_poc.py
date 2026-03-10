#!/usr/bin/env python3
"""
DataLedger — Proof of Concept
==============================
Demonstrates:
  1. Dataset manifest signing with ed25519 + RFC 8785-style canonical JSON
  2. Manifest verification
  3. Tamper detection (licence change, content hash change, name change)
  4. Training run attestation with proportional consumption records
  5. Attestation hash verification

WHY NOT in-toto ITE-6 / SLSA Provenance v1
-------------------------------------------
See comments throughout. Short answer:

  in-toto materials[] = { uri, digest }
  DataLedger splits[]  = { name, file_count, row_count, content_hash }

  in-toto has no:
    - licence field (SPDX)
    - split-level granularity (train/val/test with row counts)
    - proportional consumption (proportion: 0.7, 0.2, 0.1)
    - Croissant composability (embedded JSON-LD metadata)
    - self-contained publisher_key (in-toto requires Sigstore Fulcio CA)

WHY NOT Croissant extension
----------------------------
  Croissant describes dataset structure (fields, splits, transformations).
  It has no signing, no content hash commitment, no publisher key,
  no verification algorithm. It is a metadata vocabulary, not a
  provenance protocol. DataLedger is composable WITH Croissant —
  a Croissant object can be embedded in the manifest's croissant field.

Run:   python3 dataledger_poc.py
Test:  python3 -m pytest dataledger_poc.py -v
"""

import hashlib
import json
import base64
import uuid
import copy
from datetime import datetime, timezone
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption
)
from cryptography.exceptions import InvalidSignature


# ──────────────────────────────────────────────────────────────────────────────
# CANONICAL JSON  (RFC 8785 subset)
#
# in-toto uses a different canonicalization (canonical JSON per
# https://gibson042.github.io/canonicaljson-spec/) which does NOT
# sort object keys recursively in the same way RFC 8785 requires.
# DataLedger requires RFC 8785 for Croissant composability —
# Croissant metadata contains nested JSON-LD @context objects
# where deterministic key ordering is critical for hash stability.
# ──────────────────────────────────────────────────────────────────────────────
def canonical_json(obj) -> bytes:
    """
    RFC 8785-style canonical JSON serialisation.
    Keys sorted lexicographically by Unicode code point, recursively.
    No whitespace. Deterministic for any JSON-compatible Python object.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


# ──────────────────────────────────────────────────────────────────────────────
# KEYPAIR
# ──────────────────────────────────────────────────────────────────────────────
class Keypair:
    def __init__(self, private_key: Ed25519PrivateKey):
        self._private_key = private_key

    @classmethod
    def generate(cls) -> "Keypair":
        return cls(Ed25519PrivateKey.generate())

    def public_key_b64url(self) -> str:
        raw = self._private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return b64url_encode(raw)

    def sign(self, data: bytes) -> str:
        return b64url_encode(self._private_key.sign(data))


# ──────────────────────────────────────────────────────────────────────────────
# MANIFEST
#
# Differences from in-toto ITE-6 subject:
#
#   1. licence (SPDX identifier) — in-toto has no licence semantics.
#      EU AI Act Annex IV para 2(c) requires disclosure of applicable
#      licence terms. There is no field for this in any in-toto predicate.
#
#   2. splits[] — in-toto tracks a single subject with one digest.
#      ML datasets have named splits (train/validation/test) with
#      different statistical properties. An auditor verifying EU AI Act
#      compliance needs split-level granularity, not just a tarball hash.
#
#   3. publisher_key (self-contained) — in-toto verification requires
#      Sigstore Fulcio CA or an external key distribution service.
#      DataLedger embeds the publisher key in the manifest itself,
#      enabling offline verification without any trusted third party.
#      This is essential for air-gapped compliance audits.
#
#   4. croissant field — in-toto predicates have no path for structured
#      ML dataset metadata. DataLedger allows embedding a Croissant 1.0
#      metadata object so a single signed document carries both
#      verifiable provenance and structured dataset description.
# ──────────────────────────────────────────────────────────────────────────────
def sign_manifest(
    name: str,
    version: str,
    source_uri: str,
    licence: str,
    dataset_bytes: bytes,
    keypair: Keypair,
    splits: Optional[list] = None,
    description: Optional[str] = None,
    croissant: Optional[dict] = None,
) -> dict:
    """
    Build and sign a DataLedger dataset manifest.

    Signing procedure (SPEC.md Section 4.4):
      1. Construct manifest with signature = ""
      2. Canonicalise with RFC 8785 canonical JSON
      3. Sign canonical bytes with ed25519 private key
      4. Store base64url-encoded signature in manifest.signature
    """
    manifest = {
        "id": str(uuid.uuid4()),
        "version": version,
        "name": name,
        "source_uri": source_uri,
        "licence": licence,
        "content_hash": sha256_hex(dataset_bytes),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "publisher_key": keypair.public_key_b64url(),
        "signature": "",
    }
    if splits:
        manifest["splits"] = splits
    if description:
        manifest["description"] = description
    if croissant:
        # Croissant metadata embedded directly — the signature covers
        # this field too, so any modification to Croissant metadata
        # invalidates the manifest signature.
        manifest["croissant"] = croissant

    canonical = canonical_json(manifest)
    manifest["signature"] = keypair.sign(canonical)
    return manifest


def verify_manifest(manifest: dict) -> tuple[bool, str]:
    """
    Verify a DataLedger manifest signature.

    Returns (True, "valid") or (False, reason).

    Verification procedure (SPEC.md Section 4.5):
      1. Extract and decode signature
      2. Set signature field to ""
      3. Canonicalise with RFC 8785 canonical JSON
      4. Verify ed25519 signature over canonical bytes
    """
    try:
        sig_bytes = b64url_decode(manifest["signature"])
        key_bytes = b64url_decode(manifest["publisher_key"])

        # Reconstruct unsigned manifest
        unsigned = copy.deepcopy(manifest)
        unsigned["signature"] = ""
        canonical = canonical_json(unsigned)

        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        pub_key = Ed25519PublicKey.from_public_bytes(key_bytes)
        pub_key.verify(sig_bytes, canonical)
        return True, "valid"

    except InvalidSignature:
        return False, "signature verification failed"
    except Exception as e:
        return False, f"error: {e}"


# ──────────────────────────────────────────────────────────────────────────────
# TRAINING RUN ATTESTATION
#
# The critical differentiator from in-toto ITE-6 / SLSA Provenance v1:
#
# in-toto materials[] entry: { "uri": "...", "digest": { "sha256": "..." } }
# DataLedger consumed entry: { "manifest_id", "version", "content_hash",
#                              "proportion": 0.85 }
#
# `proportion` records the fractional contribution of each dataset
# to the training run. This is required by EU AI Act Annex IV para 2(d):
# "the origin, scope and main characteristics of the training, validation
# and testing data sets, including a description of how the data was
# obtained and selected."
#
# "Scope and main characteristics" implies proportional weighting —
# a model trained 95% on one corpus and 5% on another has fundamentally
# different bias characteristics than one trained 50/50. No existing
# in-toto predicate captures this. Adding it would require defining
# a new predicate type — at which point you are defining DataLedger.
# ──────────────────────────────────────────────────────────────────────────────
def build_attestation(
    model_id: str,
    manifests_consumed: list,
    pipeline_tool: str,
) -> dict:
    """
    Build a training run attestation and compute its hash.

    The attestation_hash is computed over the RFC 8785 canonicalisation
    of the attestation with attestation_hash set to "". This hash is
    embedded in the model card YAML front matter as:

        dataledger:
          attestation_hash: "<hex>"
          attestation_uri: "<uri>"
    """
    attestation = {
        "run_id": str(uuid.uuid4()),
        "model_id": model_id,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "manifests_consumed": manifests_consumed,
        "pipeline_tool": pipeline_tool,
        "attestation_hash": "",
    }
    canonical = canonical_json(attestation)
    attestation["attestation_hash"] = sha256_hex(canonical)
    return attestation


def verify_attestation_hash(attestation: dict) -> tuple[bool, str]:
    copy_ = copy.deepcopy(attestation)
    stored_hash = copy_.pop("attestation_hash")
    copy_["attestation_hash"] = ""
    canonical = canonical_json(copy_)
    computed = sha256_hex(canonical)
    if computed == stored_hash:
        return True, "valid"
    return False, f"hash mismatch: stored={stored_hash[:16]}... computed={computed[:16]}..."


# ──────────────────────────────────────────────────────────────────────────────
# DEMO
# ──────────────────────────────────────────────────────────────────────────────
def main():
    print("=" * 60)
    print("DataLedger — Proof of Concept")
    print("=" * 60)

    # Generate publisher keypair
    keypair = Keypair.generate()
    print(f"\nPublisher key: {keypair.public_key_b64url()[:24]}...")

    # Dataset with splits
    # NOTE: split granularity is absent from in-toto ITE-6.
    # A Hugging Face dataset typically has train/validation/test splits
    # with different statistical properties. EU AI Act compliance
    # requires split-level documentation.
    dataset_bytes = b"[simulated 50GB NLP dataset archive]"
    splits = [
        {"name": "train",      "file_count": 100, "row_count": 1_000_000},
        {"name": "validation", "file_count": 5,   "row_count": 10_000},
        {"name": "test",       "file_count": 5,   "row_count": 10_000},
    ]

    # Optional: embed Croissant metadata
    # This demonstrates composability — Croissant describes structure,
    # DataLedger adds cryptographic integrity over the whole document.
    croissant_meta = {
        "@context": "https://schema.org/",
        "@type": "Dataset",
        "name": "Example NLP Dataset",
        "description": "Example dataset for DataLedger PoC",
        "licence": "https://creativecommons.org/licenses/by/4.0/",
    }

    # 1. Sign manifest
    manifest = sign_manifest(
        name="Example NLP Dataset",
        version="1.0.0",
        source_uri="https://example.org/datasets/nlp-v1.tar.gz",
        licence="CC-BY-4.0",
        dataset_bytes=dataset_bytes,
        keypair=keypair,
        splits=splits,
        croissant=croissant_meta,
    )
    print(f"\n[1] Manifest signed")
    print(f"    id:           {manifest['id']}")
    print(f"    content_hash: {manifest['content_hash'][:24]}...")
    print(f"    signature:    {manifest['signature'][:24]}...")

    # 2. Verify — should pass
    ok, reason = verify_manifest(manifest)
    print(f"\n[2] Verification: {'VALID' if ok else 'FAILED'} ({reason})")
    assert ok, "verification should pass"

    # 3. Tamper: change licence
    tampered = copy.deepcopy(manifest)
    tampered["licence"] = "MIT"
    ok, reason = verify_manifest(tampered)
    print(f"\n[3] Tamper (licence change): {'CAUGHT' if not ok else 'MISSED — BUG'} ({reason})")
    assert not ok

    # 4. Tamper: change content hash
    tampered2 = copy.deepcopy(manifest)
    tampered2["content_hash"] = sha256_hex(b"different content")
    ok, reason = verify_manifest(tampered2)
    print(f"[4] Tamper (content_hash):   {'CAUGHT' if not ok else 'MISSED — BUG'} ({reason})")
    assert not ok

    # 5. Tamper: modify embedded Croissant metadata
    tampered3 = copy.deepcopy(manifest)
    tampered3["croissant"]["name"] = "Injected Dataset Name"
    ok, reason = verify_manifest(tampered3)
    print(f"[5] Tamper (croissant meta): {'CAUGHT' if not ok else 'MISSED — BUG'} ({reason})")
    assert not ok

    # 6. Build training attestation with proportional consumption
    # Two datasets: 85% primary corpus, 15% supplementary
    # proportion is the field with no equivalent in in-toto ITE-6
    attestation = build_attestation(
        model_id="my-model-v1.0",
        manifests_consumed=[
            {
                "manifest_id": manifest["id"],
                "version": manifest["version"],
                "content_hash": manifest["content_hash"],
                "proportion": 0.85,   # 85% of training data
            },
            {
                "manifest_id": str(uuid.uuid4()),
                "version": "2.1.0",
                "content_hash": sha256_hex(b"supplementary corpus"),
                "proportion": 0.15,   # 15% of training data
            },
        ],
        pipeline_tool="PyTorch 2.2.0",
    )
    print(f"\n[6] Attestation built")
    print(f"    run_id:           {attestation['run_id']}")
    print(f"    attestation_hash: {attestation['attestation_hash'][:24]}...")
    print(f"    (embed this hash in model card YAML front matter)")

    # 7. Verify attestation hash
    ok, reason = verify_attestation_hash(attestation)
    print(f"\n[7] Attestation hash: {'VALID' if ok else 'FAILED'} ({reason})")
    assert ok

    # 8. Tamper: change proportion after attestation is built
    tampered_att = copy.deepcopy(attestation)
    tampered_att["manifests_consumed"][0]["proportion"] = 0.5
    ok, reason = verify_attestation_hash(tampered_att)
    print(f"[8] Tamper (proportion):     {'CAUGHT' if not ok else 'MISSED — BUG'} ({reason})")
    assert not ok

    print(f"\n{'=' * 60}")
    print("All checks passed.")
    print(f"{'=' * 60}")

    print("\n--- Signed manifest JSON ---")
    print(json.dumps(manifest, indent=2))

    print("\n--- Attestation JSON ---")
    print(json.dumps(attestation, indent=2))

    print("\n--- Hugging Face model card YAML snippet ---")
    print("dataledger:")
    print(f"  attestation_hash: \"{attestation['attestation_hash']}\"")
    print(f"  attestation_uri: \"https://example.org/attestations/{attestation['run_id']}.json\"")


if __name__ == "__main__":
    main()


# ──────────────────────────────────────────────────────────────────────────────
# PYTEST TESTS
# ──────────────────────────────────────────────────────────────────────────────
def _sample():
    kp = Keypair.generate()
    m = sign_manifest("T", "1.0", "https://x.org/t.tar.gz", "MIT", b"data", kp)
    return m, kp

def test_valid_manifest_verifies():
    m, _ = _sample()
    ok, _ = verify_manifest(m)
    assert ok

def test_tampered_name_fails():
    m, _ = _sample()
    m["name"] = "Tampered"
    ok, _ = verify_manifest(m)
    assert not ok

def test_tampered_licence_fails():
    m, _ = _sample()
    m["licence"] = "GPL-3.0"
    ok, _ = verify_manifest(m)
    assert not ok

def test_tampered_content_hash_fails():
    m, _ = _sample()
    m["content_hash"] = sha256_hex(b"other")
    ok, _ = verify_manifest(m)
    assert not ok

def test_tampered_version_fails():
    m, _ = _sample()
    m["version"] = "9.9.9"
    ok, _ = verify_manifest(m)
    assert not ok

def test_wrong_key_fails():
    m, _ = _sample()
    other = Keypair.generate()
    m["publisher_key"] = other.public_key_b64url()
    ok, _ = verify_manifest(m)
    assert not ok

def test_json_roundtrip():
    m, _ = _sample()
    m2 = json.loads(json.dumps(m))
    ok, _ = verify_manifest(m2)
    assert ok

def test_croissant_tamper_fails():
    kp = Keypair.generate()
    m = sign_manifest("T", "1.0", "https://x.org/t.tar.gz", "MIT", b"data", kp,
                      croissant={"@type": "Dataset", "name": "original"})
    m["croissant"]["name"] = "injected"
    ok, _ = verify_manifest(m)
    assert not ok

def test_attestation_hash_verifies():
    m, _ = _sample()
    att = build_attestation("model-v1",
        [{"manifest_id": m["id"], "version": m["version"],
          "content_hash": m["content_hash"], "proportion": 1.0}],
        "PyTorch 2.2.0")
    ok, _ = verify_attestation_hash(att)
    assert ok

def test_tampered_proportion_fails():
    m, _ = _sample()
    att = build_attestation("model-v1",
        [{"manifest_id": m["id"], "version": m["version"],
          "content_hash": m["content_hash"], "proportion": 0.8}],
        "PyTorch 2.2.0")
    att["manifests_consumed"][0]["proportion"] = 0.5
    ok, _ = verify_attestation_hash(att)
    assert not ok

def test_canonical_json_sorts_keys():
    obj = {"z": 1, "a": 2, "m": 3}
    result = canonical_json(obj).decode()
    assert result == '{"a":2,"m":3,"z":1}'

def test_canonical_json_nested():
    obj = {"outer": {"z": 1, "a": 2}}
    result = canonical_json(obj).decode()
    assert result == '{"outer":{"a":2,"z":1}}'
