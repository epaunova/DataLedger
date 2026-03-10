# Contributing to DataLedger

DataLedger is an open standard developed in public. Contributions, questions, and criticism are welcome.

## What Needs Review

The most valuable contribution right now is review of the specification. Specifically:

- Is the signing and verification procedure in SPEC.md Section 4 unambiguous?
- Is the use of RFC 8785 JCS the right canonicalisation approach, or is there a better option?
- Are there attack scenarios not covered in the threat model?
- Are there composability requirements with existing standards that are not addressed?

Please open an issue on Codeberg or start a thread on the SocialHub ActivityPub forum if you have thoughts.

## Code Contributions

The project is at an early stage. Before submitting code, please open an issue to discuss the change.

All code must pass `cargo test` and `cargo clippy -- -D warnings`.

## Specification Changes

Changes to SPEC.md require a rationale comment in the pull request explaining why the change is necessary and what alternatives were considered.

## Licence

By contributing you agree that your contributions are licensed under the same terms as the project: MIT or Apache 2.0 for code, CC-BY 4.0 for specification and documentation.
