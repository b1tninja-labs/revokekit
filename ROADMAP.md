# Specification completeness -- and the roadmap it implies

This is the project's north star: every protocol obligation revokekit could plausibly take on,
with an honest status against the code at `HEAD`. It is blunt about gaps on purpose. A
roadmap that overstates its coverage is not a plan, it is marketing.

**The honesty rule:** a row may read `[ok]` only when a named test would fail if the
behaviour regressed. Reading the code and agreeing with it is not enough. That is how
"decoded but never sent" quietly becomes "implemented".

Legend: `[ok]` implemented and pinned by a named test -- `[part]` partial, with what is
missing stated -- `[ ]` not implemented -- `[no]` deliberate non-goal.

A Where cell marked `(to be written)` names the test that will pin the row once it exists; no
such test has been written yet, and the row cannot leave `[ ]` until it has. The Milestone
column places the row on the ladder in section 2, and `-` means it is not placed yet.

Update the affected row in the same commit that changes the behaviour. A row and its test
drift apart within one release, and the document becomes useless exactly when it is needed.

## 1. Obligations

| Obligation | Spec | Status | Where | Milestone |
|---|---|---|---|---|
| `request.build()` | RFC 6960 sec. 4.1.1, RFC 9919 sec. 3.1.1 | `[ok]` | `tests/test_request.py::test_request_matches_rfc9919_appendix_b4` | M1 |
| `request.certid()` | RFC 6960 sec. 4.1.1, RFC 9919 sec. 3.1.1 | `[ok]` | `tests/test_request.py::test_certid_hashes_are_over_the_issuer_name_der_and_key_bits` | M1 |
| `rk.request-asn1core-builder` | swap the private `_tlv` helper for the asn1core DER builder once it exists | `[ ]` | `tests/test_request.py::test_request_matches_rfc9919_appendix_b4` (to be written) | M1 |
| `rk.request-serial-limits` | RFC 5280 sec. 4.1.2.2 (users MUST handle 20 octets; zero and negative serials SHOULD be handled gracefully) | `[ ]` | `tests/test_request.py::test_oversized_serial_policy_is_stated` (to be written) | M1 |
| `rk.response-parse` | RFC 6960 sec. 4.2.1, RFC 9919 sec. 3.2 | `[ok]` | `tests/test_response.py::test_basic_response_keeps_tbs_response_data_bytes` | M1 |
| `rk.response-status` | RFC 6960 sec. 4.2.1, 2.3 | `[ok]` | `tests/test_response.py::test_unsuccessful_status_carries_no_response_bytes` | M1 |
| `rk.response-match-certid` | RFC 6960 sec. 4.2.2.3 (the response MUST hold a SingleResponse per requested certificate; sec. 4.2.2.1 is Time, not matching), RFC 9919 sec. 3.2.1 | `[ok]` | `tests/test_response.py::test_every_single_response_certid_is_compared` | M1 |
| `rk.response-extended-revoked` | RFC 6960 sec. 4.4.8 (read before citing) | `[ok]` | `tests/test_response.py::test_extended_revoked_is_not_good` | M1 |
| `rk.limits-check` | design (maximum body, certs, SingleResponse count, depth); needs an owner sentence (D6) | `[ ]` | `tests/test_limits.py::test_hostile_response_is_bounded` (to be written) | M1 |
| `rk.response-verify-signature` | RFC 6960 sec. 4.2.1 (signature over the stored tbsResponseData, through `sigwire[verify]`) | `[ok]` | `tests/test_response.py::test_signature_is_over_stored_tbs_bytes` | M2 |
| `rk.response-delegated-responder` | RFC 6960 sec. 4.2.2.2 (read in full 2026-11-13: id-kp-OCSPSigning, issued directly by the CA, same signing key; 4.2.2.2.1 nocheck; through `pkix.check_signature` and `check_validity`) | `[ok]` | `tests/test_response.py::test_delegate_must_be_issued_by_the_ca_with_ocspsigning` | M2 |
| `response.parse_and_verify()` | RFC 6960 | `[ok]` | `tests/test_obligations.py::test_parse_and_verify` | M2 |
| `rk.crl-indirect` | RFC 5280 sec. 5.2.5, 5.3.3, 6.3.3 step (b)(1) (indirectCRL, certificateIssuer entries; refused today with a named error) | `[ok]` | `tests/test_crl.py::test_indirect_crl_entries_are_attributed_by_certificate_issuer` | M5 |
| `rk.crl-reasons` | RFC 5280 sec. 6.3.3 steps (d), (e), (l) (onlySomeReasons and reasons_mask across several CRLs; refused today) | `[ok]` | `tests/test_crl.py::test_reasons_mask_accumulates_across_partitioned_crls` | M5 |
| `rk.crl-dp-relative-name` | RFC 5280 sec. 4.2.1.13, 5.2.5 (nameRelativeToCRLIssuer; only fullName is matched today, by identical GeneralName encoding) | `[ok]` | `tests/test_crl.py::test_relative_distribution_point_name_is_matched` | M5 |
| `rk.crl-decide-via-pkix` | RFC 5280 sec. 6.3.3 in full (proposal, 2026-11-13): `crl.status_of` keeps its own delta merge and refuses indirect CRLs, onlySomeReasons and relative DP names, while `pkix.revocation.CrlChecker` now implements every step (IDP scope, reasons_mask, indirect CRLs with certificateIssuer, separate CRL signers validated from the trust anchor, delta CRLs; PKITS 1.0.1 247/0/0). Proposal: revokekit keeps fetching, caching and freshness (`cache`, `freshest`, `http`) and hands the CRLs it holds to `CrlChecker(crls, certificates=..., policy=...)` for the decision, so `rk.crl-indirect`, `rk.crl-reasons` and `rk.crl-dp-relative-name` close by consumption rather than by a second implementation. Needs an owner nod: it makes `crl.status_of`'s result type a wrapper over `pkix.revocation.RevocationAnswer` | `[ok]` | `tests/test_crl.py::test_status_of_agrees_with_pkix_crl_checker` | M5 |
| `rk.crl-extensions-asn1core` | PORTFOLIO.md section 9 item 15 (one DER reader): `crl._idp` and `crl._integer_extension` duplicate `asn1core.extensions.parse_issuing_distribution_point`, `parse_crl_number` and `parse_delta_crl_indicator` (row `dk.ext-crl`, 2026-11-13). Two differences to settle when switching: `_flag` accepts an encoded FALSE in the IDP, which DER forbids for a DEFAULT (X.690 11.5) and asn1core refuses; and `_integer_extension` refuses a CRLNumber over 20 octets, while RFC 5280 sec. 5.2.3 puts that bound on issuers ("MUST NOT use") and asn1core decodes it | `[ok]` | `tests/test_crl.py::test_crl_extensions_are_read_by_asn1core` | M5 |
| `rk.crl-explicit-delta` | RFC 5280 sec. 6.3.3 step (h) (proposal for pkix): `CrlChecker` reads a delta only when the CRL or certificate carries FreshestCRL, so a delta the caller holds is left unread. `crl.status_of` refuses (`CrlError`) when that delta names the certificate; pkix could take an explicit-delta mode | `[ ]` | `tests/test_crl.py::test_explicit_delta_that_pkix_leaves_unread_is_refused` (refusal only) | M5 |
| `rk.crl-answer-details` | `pkix.revocation.RevocationAnswer` carries status and a sentence only; `crl.status_of` reads the reason code, date and delta origin back from the entries itself and leaves them None when a serial is ambiguous (indirect CRL). Proposal for pkix: structured `reason_code`, `revocation_date`, `on_delta` fields | `[ ]` | `tests/test_crl.py::test_status_of_agrees_with_pkix_crl_checker` (state only) | M5 |
| `rk.crl-keyusage-via-pkix` | `crl.check_issuer_key_usage` duplicates `pkix.revocation.check_crl_issuer_key_usage` (RFC 10007 sec. 4); switch when parse_and_verify can take pkix's `CrlIssuerCheck` | `[ ]` | `tests/test_crl.py::test_crl_signer_without_crlsign_is_refused` | M5 |
| `rk.crl-fetch-delta` | RFC 5280 sec. 5.2.6, 6.3.3 step (a) (choose and fetch the delta through FreshestCRL; needs the extension decoders of asn1core `dk.ext-structure`) | `[ ]` | `tests/test_crl.py::test_freshest_crl_names_the_delta_location` (to be written) | M5 |
| `rk.response-delegate-revocation` | RFC 6960 sec. 4.2.2.2.1 (a delegate without id-pkix-ocsp-nocheck is reported as `nocheck=False`; the caller must check its status, to be wired to `crl.status_of`) | `[ ]` | `tests/test_response.py::test_delegate_without_nocheck_is_reported` (to be written) | M2 |
| `rk.response-same-key` | RFC 6960 sec. 4.2.2.2 (the same signing key: holds by construction from the issuer the caller names; also verify the target certificate's own signature under it, once pkix offers that for a bare issuer) | `[ ]` | `tests/test_response.py::test_target_signed_by_a_different_key_of_the_ca_is_refused` (to be written) | M2 |
| `rk.response-sigalg-coverage` | RFC 4055 sec. 3.1 (RSASSA-PSS) and RFC 8410 sec. 3 (Ed25519) signatures on OCSP responses (RFC 6960 sec. 4.2.1) and on CRLs (RFC 5280 sec. 5.1.1.2) take the same path as ECDSA and RSA PKCS#1 | `[ok]` | `tests/test_sigalgs.py::test_pss_and_ed25519_response_signatures_verify`; `tests/test_sigalgs.py::test_pss_and_ed25519_crl_signatures_verify` | M2 |
| `rk.response-lenient-read` | the response and its certs are read strictly (`der=True`, strict certificates); real responders send certificates that a lenient asn1core read (`lenient_values`, `Certificate.defects`) would carry; decide what is refused | `[ ]` | `tests/test_response.py::test_nonconforming_responder_certificate_is_read_with_defects` (to be written) | M2 |
| `rk.verify-seam-public` | `revokekit/_verify.py` verifies through pkix's public `validity.check_signed_data` and no longer imports `pkix._algorithms`; a CRL's tbsCertList.signature is now compared with its signatureAlgorithm (RFC 5280 sec. 5.1.1.2, which pkix enforces) | `[ok]` | `tests/test_sigalgs.py::test_revokekit_no_longer_imports_pkix_private_algorithms`; `tests/test_response.py::test_signature_is_over_stored_tbs_bytes` | M2 |
| `rk.response-spec-vector` | a response from a specification or an independent implementation (RFC 9919 appendix B stops at the request; RFC 6960 has no binary example) instead of one generated by `cryptography` | `[ ]` | `tests/test_response.py::test_independent_response_vector_verifies` (to be written) | M2 |
| `nonce.generate()` | RFC 9654 sec. 2.1 | `[ok]` | `tests/test_nonce.py::test_generate_refuses_below_32_and_above_128` | M3 |
| `nonce.encode_extension()` | RFC 9654 sec. 2.1 | `[ok]` | `tests/test_nonce.py::test_extension_encoding_matches_the_rfc9654_example` | M3 |
| `nonce.decode_extension()` | RFC 9654 sec. 2.1 | `[ok]` | `tests/test_nonce.py::test_extension_with_trailing_bytes_refused` | M3 |
| `nonce.check()` | RFC 9654 sec. 2.1, RFC 9919 sec. 5 | `[ok]` | `tests/test_nonce.py::test_check_match_mismatch_absent` | M3 |
| `freshest.is_fresh()` | RFC 9919 sec. 5, RFC 6960 sec. 2.4 | `[ok]` | `tests/test_freshness.py::test_missing_nextupdate_is_rejected` | M4 |
| `rk.freshness-of-response` | feed a parsed SingleResponse (thisUpdate, nextUpdate) to `is_fresh`; producedAt plays no part | `[ok]` | `tests/test_freshness.py::test_single_response_times_feed_is_fresh` | M4 |
| `rk.clock-skew-policy` | RFC 9919 sec. 5 names no number; any default is a project convention, labelled as one | `[ ]` | `tests/test_freshness.py::test_documented_default_skew_is_labelled_convention` (to be written) | M4 |
| `http.query()` | RFC 6960 appendix A | `[ ]` | `tests/test_obligations.py::test_query` (to be written) | M4 |
| `rk.http-request-for` | RFC 6960 appendix A.1, RFC 9919 sec. 6 (pure: the HTTP request fields for a DER request) | `[ ]` | `tests/test_http.py::test_get_and_post_forms_match_rfc9919_sec6` (to be written) | M4 |
| `rk.http-response-from` | RFC 6960 appendix A.2 (pure: status, content-type, size cap) | `[ ]` | `tests/test_http.py::test_oversized_body_is_refused` (to be written) | M4 |
| `crl.fetch()` | RFC 5280 sec. 4.2.1.13 | `[ ]` | `tests/test_obligations.py::test_fetch` (to be written) | M5 |
| `rk.crl-parse-and-verify` | RFC 5280 sec. 5, 6.3 (asn1core `parse_crl` exists; verification over the stored tbsCertList) | `[ok]` | `tests/test_crl.py::test_signature_is_over_stored_tbs_cert_list` | M5 |
| `rk.crl-delta` | RFC 5280 sec. 5.2.4, 6.3.3 steps (c), (h), (i) to (k) (sec. 5.2.6 FreshestCRL, the fetch side, is `rk.crl-fetch-delta`) | `[ok]` | `tests/test_crl.py::test_delta_crl_is_applied_to_its_base` | M5 |
| `rk.crl-issuer-keyusage` | RFC 10007 (updates RFC 5280 sec. 6.3 with the cRLSign check; read before citing) | `[ok]` | `tests/test_crl.py::test_crl_signer_without_crlsign_is_refused` | M5 |
| `rk.norevavail` | RFC 9608 (read before citing) | `[ok]` | `tests/test_crl.py::test_norevavail_skips_revocation_checking` | M5 |
| `rk.soft-fail-policy` | PORTFOLIO.md section 9 item 15: fail closed. `decide.decide` returns "unknown", never "good", when the CRL cannot answer; OCSP is consulted only with `Fallback.OCSP`. pkix's `revocation.CrlChecker` keeps the same rule (UNDETERMINED fails the path) | `[ok]` | `tests/test_policy.py::test_failed_fetch_is_not_good`; `tests/test_policy.py::test_ocsp_fallback_is_used_only_when_asked` | M5 |
| `stapling.verify_stapled()` | RFC 7633 sec. 4.3.3 | `[ ]` | `tests/test_obligations.py::test_verify_stapled` (to be written) | M5 |
| `rk.stapled-in-cms` | RFC 5940 (OCSP responses in CMS RevocationInfoChoices; shared with signeddata) | `[ ]` | `tests/test_stapling.py::test_ocsp_response_choice_in_cms_is_read` (to be written) | M5 |

## 2. Milestones

- M1 request and response codec against RFC 6960 vectors (request side done: RFC 9919 appendix B.4 is reproduced byte for byte)
- M2 signature and delegated responder verification (done for ECDSA and RSA PKCS#1; PSS, Ed25519 and the delegate's own revocation are rows)
- M3 nonce rules per RFC 9654 with explicit missing-nonce policy (done)
- M4 freshness, caching and clock skew, then the bounded HTTP client
- M5 CRL and delta CRL, and the stapling check (verification, delta combination, cRLSign and noRevAvail done; fetching, indirect CRLs and reason partitions are rows)
- M6 publication: 0.1.0, wired as the revocation provider for pkix

Every milestone is accepted by its rows above flipping to `[ok]` with a named test, not by
the code existing. Coverage in `pyproject.toml` ratchets in the same commit.

## 3. Errata watch

- RFC 6960 carries 6 verified errata and is updated by RFC 8954 and RFC 9654: read 9654 before implementing Nonce, because it supersedes the older constraint.
- RFC 9654 and RFC 9919 report no errata as of 2026-11-07 (rfclib), and both are new enough that implementations are the open question rather than corrections.
- RFC 5280 carries 6 verified errata and is updated by nine later RFCs (6818, 8398, 8399, 9549, 9598, 9608, 9618, 9925, 10007) as of 2026-11-07 (rfclib). RFC 8954 is obsoleted by RFC 9654 and is not a document to implement.
- RFC 9919 obsoletes RFC 5019. Recipes copied from 5019 describe the superseded profile.
- RFC 10007 (2026-06) updates RFC 5280 sec. 6.3 with a cRLSign key usage check on CRL validation, and RFC 9608 (2024-06) defines noRevAvail, which changes whether revocation checking applies. Both were missing from the spine and now have rows.
- RFC 6960 errata 6165, 6166 and 6167 (verified) say a KeyHash is over the BIT STRING value without tag, length and unused-bits octet. Sec. 4.1.1 words the CertID issuerKeyHash less plainly ("value (excluding tag and length)"); the RFC 9919 appendix B.4 example is reproduced only without the unused-bits octet, and a test says so.
- The RFC 9654 sec. 2.1 example is 49 octets, not 47: the SEQUENCE length printed in the RFC is 47, after a two octet header. The first-pass review's "47 bytes" was the content length.
- RFC 5280 sec. 4.1.2.2 says a serial MUST be positive, then says non-conforming CAs issue zero and negative ones and users SHOULD handle them gracefully. `request` encodes such serials rather than refusing them, contrary to the first-pass brief.
- RFC 9919 sec. 5: the nonce-fallback sentence applies to a client that sent a nonce and got none back; a client that sent none MUST ignore a nonce in the response. The first-pass review merged the two, and `nonce.check` keeps them apart.
- The `request.build` citation was RFC 6960 sec. 4.1, a heading only; the ASN.1 and the CertID rules are sec. 4.1.1. Fixed in the row, the docstring and the surface test.
- RFC 6960 sec. 4.2.2.1 is Time (thisUpdate and nextUpdate); the first-pass row cited it for CertID matching. The rule that a response MUST hold a SingleResponse for each requested certificate is sec. 4.2.2.3, and RFC 9919 sec. 3.2.1 allows extra ones (a SHA-1 and a SHA-256 CertID for one certificate), so every CertID is compared and matching ones that disagree are refused.
- `ResponseData.version` is `[0] EXPLICIT Version DEFAULT v1`: RFC 6960 sec. 4.2.2.3 says it MUST be v1, which is the default, so a DER response never encodes it and a `[0]` there is refused whatever its value.
- RFC 10007 sec. 4 replaces step (f) of RFC 5280 sec. 6.3.3: keyUsage must be present with cRLSign for a v3 issuer certificate, where RFC 5280 only checked it "if present". `crl.check_issuer_key_usage` implements the new text; RFC 10007 reports no errata.
- RFC 9608 sec. 4 skips step (a)(3) for noRevAvail or id-pkix-ocsp-nocheck. Its sec. 3 lists what makes a noRevAvail certificate invalid (a CA, CRLDP, FreshestCRL, an id-ad-ocsp access method); `crl.norevavail_problems` reports them and `crl.revocation_required` raises `NoRevAvailViolation`. Criticality (sec. 2, "MUST be FALSE") is an obligation on CAs and is not reported.
- RFC 5280 errata for the sections read here (5.2.x, 5.3.3, 6.3): none verified. RFC 6960 errata 5891, 7961 and 7962 are ASN.1 module editorial points; none affects the structures parsed here.
- The `cryptography` OCSP builder emits exactly one SingleResponse, so the test helper `ocsp_response_multi` hand-assembles multi-response DER. The generated test PKI is not a specification vector and the tests say so; RFC 9919 appendix B has no response example, so no response vector from a specification is in the repository yet (row `rk.response-spec-vector`).

## 4. Deliberate non-goals

| Non-goal | Status | Revisit when |
|---|---|---|
| being an OCSP responder, which is a deployment product | `[no]` | a named document requires it |
| path validation, which is pkix and consumes this library | `[no]` | a named document requires it |
| CRL generation for CA operators | `[no]` | a named document requires it |

## 5. Open questions

- `response.parse_and_verify()` is split into the `rk.response-*` rows above, by the portfolio rule that bytes are retained and then verified; the umbrella row stays on M2 and closes when they do
- M2 landed 2026-11-13 on `sigwire[verify]` (sigprim is merged into it and retired) and pkix `check_signature` and `check_validity`, which exist now; `revokekit/_verify.py` still reaches into `pkix._algorithms`, which is row `rk.verify-seam-public`
- `rk.limits-check` needs the acceptance sentence the owner has not given (D6)
- `crl.status_of` on a CRL that cannot establish a status (UNDETERMINED or unsupported by `pkix.revocation.CrlChecker`: a name mismatch, uncovered reasons, a CRL signer without a trust anchor) raises `CrlError`; whether the caller then falls back to OCSP or fails closed is `rk.soft-fail-policy`
- Round 3 (2026-11-13): that decision is made. `revokekit.decide` fails closed by default and falls back to OCSP only on the caller's `Fallback.OCSP` (`rk.soft-fail-policy`). The verification seam is pkix's public `validity.check_signed_data`, so `_verify.py` no longer reaches into `pkix._algorithms`, and PSS and Ed25519 are pinned on both responses and CRLs. `cryptography`'s OCSP builder signs RSA only with PKCS #1 v1.5, so the PSS response in `tests/test_sigalgs.py` is re-signed over the stored tbsResponseData

## 6. Publication checklist

- [ ] every `[ ]` row above either `[ok]` or moved to a named later milestone
- [ ] `docs/research.md` claims re-verified and the dated ones either promoted or deleted
- [ ] interoperability evidence recorded in `docs/` against a non-Python implementation
- [ ] `tools/check_dist.py` proves the wheel ships the fixtures the README promises
- [ ] version 0.1.0 tagged, trusted publisher configured, README badges uncommented
