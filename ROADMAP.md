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
| `rk.response-parse` | RFC 6960 sec. 4.2.1, RFC 9919 sec. 3.2 | `[ ]` | `tests/test_response.py::test_basic_response_keeps_tbs_response_data_bytes` (to be written) | M1 |
| `rk.response-status` | RFC 6960 sec. 4.2.1, 2.3 | `[ ]` | `tests/test_response.py::test_unsuccessful_status_carries_no_response_bytes` (to be written) | M1 |
| `rk.response-match-certid` | RFC 6960 sec. 4.2.2.1 (read before citing), RFC 9919 sec. 3.2 | `[ ]` | `tests/test_response.py::test_every_single_response_certid_is_compared` (to be written) | M1 |
| `rk.response-extended-revoked` | RFC 6960 sec. 4.4.8 (read before citing) | `[ ]` | `tests/test_response.py::test_extended_revoked_is_not_good` (to be written) | M1 |
| `rk.limits-check` | design (maximum body, certs, SingleResponse count, depth); needs an owner sentence (D6) | `[ ]` | `tests/test_limits.py::test_hostile_response_is_bounded` (to be written) | M1 |
| `rk.response-verify-signature` | RFC 6960 sec. 4.2.1 (signature over the stored tbsResponseData; needs sigprim) | `[ ]` | `tests/test_response.py::test_signature_is_over_stored_tbs_bytes` (to be written) | M2 |
| `rk.response-delegated-responder` | RFC 6960 sec. 4.2.2.2 (read in full 2026-11-13: id-kp-OCSPSigning, issued directly by the CA, same signing key; 4.2.2.2.1 nocheck; needs pkix) | `[ ]` | `tests/test_response.py::test_delegate_must_be_issued_by_the_ca_with_ocspsigning` (to be written) | M2 |
| `response.parse_and_verify()` | RFC 6960 | `[ ]` | `tests/test_obligations.py::test_parse_and_verify` (to be written) | M2 |
| `nonce.generate()` | RFC 9654 sec. 2.1 | `[ok]` | `tests/test_nonce.py::test_generate_refuses_below_32_and_above_128` | M3 |
| `nonce.encode_extension()` | RFC 9654 sec. 2.1 | `[ok]` | `tests/test_nonce.py::test_extension_encoding_matches_the_rfc9654_example` | M3 |
| `nonce.decode_extension()` | RFC 9654 sec. 2.1 | `[ok]` | `tests/test_nonce.py::test_extension_with_trailing_bytes_refused` | M3 |
| `nonce.check()` | RFC 9654 sec. 2.1, RFC 9919 sec. 5 | `[ok]` | `tests/test_nonce.py::test_check_match_mismatch_absent` | M3 |
| `freshest.is_fresh()` | RFC 9919 sec. 5, RFC 6960 sec. 2.4 | `[ok]` | `tests/test_freshness.py::test_missing_nextupdate_is_rejected` | M4 |
| `rk.freshness-of-response` | feed a parsed SingleResponse (thisUpdate, nextUpdate) to `is_fresh`; producedAt plays no part | `[ ]` | `tests/test_freshness.py::test_single_response_times_feed_is_fresh` (to be written) | M4 |
| `rk.clock-skew-policy` | RFC 9919 sec. 5 names no number; any default is a project convention, labelled as one | `[ ]` | `tests/test_freshness.py::test_documented_default_skew_is_labelled_convention` (to be written) | M4 |
| `http.query()` | RFC 6960 appendix A | `[ ]` | `tests/test_obligations.py::test_query` (to be written) | M4 |
| `rk.http-request-for` | RFC 6960 appendix A.1, RFC 9919 sec. 6 (pure: the HTTP request fields for a DER request) | `[ ]` | `tests/test_http.py::test_get_and_post_forms_match_rfc9919_sec6` (to be written) | M4 |
| `rk.http-response-from` | RFC 6960 appendix A.2 (pure: status, content-type, size cap) | `[ ]` | `tests/test_http.py::test_oversized_body_is_refused` (to be written) | M4 |
| `crl.fetch()` | RFC 5280 sec. 4.2.1.13 | `[ ]` | `tests/test_obligations.py::test_fetch` (to be written) | M5 |
| `rk.crl-parse-and-verify` | RFC 5280 sec. 5, 6.3 (asn1core `parse_crl` exists; verification over the stored tbsCertList) | `[ ]` | `tests/test_crl.py::test_signature_is_over_stored_tbs_cert_list` (to be written) | M5 |
| `rk.crl-delta` | RFC 5280 sec. 5.2.4, 5.2.6, 6.3.3 | `[ ]` | `tests/test_crl.py::test_delta_crl_is_applied_to_its_base` (to be written) | M5 |
| `rk.crl-issuer-keyusage` | RFC 10007 (updates RFC 5280 sec. 6.3 with the cRLSign check; read before citing) | `[ ]` | `tests/test_crl.py::test_crl_signer_without_crlsign_is_refused` (to be written) | M5 |
| `rk.norevavail` | RFC 9608 (read before citing) | `[ ]` | `tests/test_crl.py::test_norevavail_skips_revocation_checking` (to be written) | M5 |
| `rk.soft-fail-policy` | the contract with pkix `revocation.status_of`: what a failed fetch means; written once, in both projects | `[ ]` | `tests/test_policy.py::test_failed_fetch_is_not_good` (to be written) | M5 |
| `stapling.verify_stapled()` | RFC 7633 sec. 4.3.3 | `[ ]` | `tests/test_obligations.py::test_verify_stapled` (to be written) | M5 |
| `rk.stapled-in-cms` | RFC 5940 (OCSP responses in CMS RevocationInfoChoices; shared with signeddata) | `[ ]` | `tests/test_stapling.py::test_ocsp_response_choice_in_cms_is_read` (to be written) | M5 |

## 2. Milestones

- M1 request and response codec against RFC 6960 vectors (request side done: RFC 9919 appendix B.4 is reproduced byte for byte)
- M2 signature and delegated responder verification
- M3 nonce rules per RFC 9654 with explicit missing-nonce policy (done)
- M4 freshness, caching and clock skew, then the bounded HTTP client
- M5 CRL and delta CRL, and the stapling check
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

## 4. Deliberate non-goals

| Non-goal | Status | Revisit when |
|---|---|---|
| being an OCSP responder, which is a deployment product | `[no]` | a named document requires it |
| path validation, which is pkix and consumes this library | `[no]` | a named document requires it |
| CRL generation for CA operators | `[no]` | a named document requires it |

## 5. Open questions

- `response.parse_and_verify()` is split into the `rk.response-*` rows above, by the portfolio rule that bytes are retained and then verified; the umbrella row stays on M2 and closes when they do
- M2 needs sigprim for the signature arithmetic and pkix for the delegated responder's chain; sigprim is unpublished and pkix `validity.check_signature` is `[ ]`, so M2 waits
- `rk.limits-check` needs the acceptance sentence the owner has not given (D6)

## 6. Publication checklist

- [ ] every `[ ]` row above either `[ok]` or moved to a named later milestone
- [ ] `docs/research.md` claims re-verified and the dated ones either promoted or deleted
- [ ] interoperability evidence recorded in `docs/` against a non-Python implementation
- [ ] `tools/check_dist.py` proves the wheel ships the fixtures the README promises
- [ ] version 0.1.0 tagged, trusted publisher configured, README badges uncommented
