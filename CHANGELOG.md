# Changelog

The format follows Keep a Changelog, and this project adheres to Semantic Versioning.

## Unreleased

### Added

- `request.build` and `request.certid`: one unsigned OCSPRequest with a SHA-256 CertID (SHA-1 only on request),
  optional nonce extension; reproduces RFC 9919 appendix B.4.
- `nonce.generate`, `encode_extension`, `decode_extension`, `check` (RFC 9654 sec. 2.1, RFC 9919 sec. 5).
- `freshest.is_fresh` with an injected clock (RFC 9919 sec. 5).
- `asn1core` as a runtime dependency, resolved from the sibling checkout.
- `response.parse`, `match`, `authorize_signer`, `verify_signature` and `parse_and_verify`: OCSP response parsing that keeps the signed bytes, status and CertID matching, delegated responder rules (RFC 6960 sec. 4.2.2.2), signature through `sigwire[verify]`, nonce and freshness.
- `crl.parse_and_verify` and `crl.status_of`: CRL verification, delta CRL combination (RFC 5280 sec. 5.2.4, 6.3.3), the RFC 10007 cRLSign check; `crl.revocation_required` and `norevavail_problems` for RFC 9608.
- `sigwire[verify]` and `pkix` as runtime dependencies (sibling checkouts).

### Changed

- `crl.status_of` decides through `pkix.revocation.CrlChecker` (RFC 5280 sec. 6.3.3 in full) and `crl.parse_and_verify` reads the issuing distribution point, CRL number and delta CRL indicator with asn1core: one implementation (rows `rk.crl-decide-via-pkix`, `rk.crl-extensions-asn1core`). Indirect CRLs, `onlySomeReasons` partitions and relative distribution point names now work (`rk.crl-indirect`, `rk.crl-reasons`, `rk.crl-dp-relative-name`). `status_of` gains `issuer`, `certificates`, `anchor`, `more_crls` and `policy`; `CrlStatus` gains `answer`; `VerifiedCrl` gains `issuer` and its `idp` is asn1core's `IssuingDistributionPoint` (revokekit's own class is gone). Failing closed is unchanged: UNDETERMINED raises `CrlError`.
- Behaviour changes: an encoded DEFAULT FALSE in the issuing distribution point is now refused (X.690 sec. 11.5; it was accepted); a CRLNumber or BaseCRLNumber over 20 octets is now accepted (RFC 5280 sec. 5.2.3 binds issuers, "CRL issuers MUST NOT"; it was refused); a critical certificateIssuer entry extension is processed (sec. 5.3.3); the `CrlError` messages for a foreign issuer, scope mismatches and `onlySomeReasons` are pkix's wording (sec. 6.3.3 (b), (d)); a delta CRL that pkix would not read (no FreshestCRL, sec. 6.3.3 (h)) and that names the certificate is refused rather than ignored.

- Signatures of `request.build`, `nonce.check` and `freshest.is_fresh` are now concrete; the stub placeholders are gone.
- The `request.build` citation is RFC 6960 sec. 4.1.1, not sec. 4.1.
- ROADMAP rows split and added for response, CRL, HTTP and policy work; RFC 10007, RFC 9608 and RFC 5754 join the spine.

The remaining public functions are still typed stubs that raise `NotImplementedError`; [ROADMAP.md](ROADMAP.md) lists what has to happen first.

## 0.0.0 - 2026-11-05

### Added

- Package skeleton, obligation matrix and CI gates for revokekit.
- `revokekit.apps` namespace reserved for composition that is not protocol behaviour.
