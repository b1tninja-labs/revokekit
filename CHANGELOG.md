# Changelog

The format follows Keep a Changelog, and this project adheres to Semantic Versioning.

## Unreleased

### Added

- `request.build` and `request.certid`: one unsigned OCSPRequest with a SHA-256 CertID (SHA-1 only on request),
  optional nonce extension; reproduces RFC 9919 appendix B.4.
- `nonce.generate`, `encode_extension`, `decode_extension`, `check` (RFC 9654 sec. 2.1, RFC 9919 sec. 5).
- `freshest.is_fresh` with an injected clock (RFC 9919 sec. 5).
- `asn1core` as the one runtime dependency, resolved from the sibling checkout.

### Changed

- Signatures of `request.build`, `nonce.check` and `freshest.is_fresh` are now concrete; the stub placeholders are gone.
- The `request.build` citation is RFC 6960 sec. 4.1.1, not sec. 4.1.
- ROADMAP rows split and added for response, CRL, HTTP and policy work; RFC 10007, RFC 9608 and RFC 5754 join the spine.

The remaining public functions are still typed stubs that raise `NotImplementedError`; [ROADMAP.md](ROADMAP.md) lists what has to happen first.

## 0.0.0 - 2026-11-05

### Added

- Package skeleton, obligation matrix and CI gates for revokekit.
- `revokekit.apps` namespace reserved for composition that is not protocol behaviour.
