# Where every claim in this repository comes from

| Document | Status | Published | Verified against the publisher record on |
|---|---|---|---|
| RFC 6960 | Proposed Standard | 2013-06 | 2026-11-05 |
| RFC 9654 | Proposed Standard | 2024-08 | 2026-11-05 |
| RFC 9919 | Proposed Standard | 2026-07 | 2026-11-05 |
| RFC 7633 | Proposed Standard | 2015-10 | 2026-11-05 |
| RFC 5940 | Proposed Standard | 2010-08 | 2026-11-05 |
| RFC 5280 | Proposed Standard | 2008-05 | 2026-11-05 |
| RFC 10007 | Proposed Standard | 2026-06 | 2026-11-13 |
| RFC 9608 | Proposed Standard | 2024-06 | 2026-11-13 |
| RFC 5754 | Proposed Standard | 2010-01 | 2026-11-13 |

Status detail, read with rfclib on 2026-11-13:

| Document | Obsoletes, obsoleted by, updates | Errata | Notes |
|---|---|---|---|
| RFC 6960 | updated by RFC 8954 (obsolete) and RFC 9654 | 6 verified | the ASN.1 of OCSPRequest and CertID is sec. 4.1.1, not sec. 4.1; errata 6165-6167 say a KeyHash excludes tag, length and unused-bits octet |
| RFC 9654 | obsoletes RFC 8954, updates RFC 6960 | none | Nonce is 1..128 octets, a requester uses 32 or more, a responder accepts 16..32 (sec. 2.1) |
| RFC 9919 | obsoletes RFC 5019 | none | one Request, SHA-256 CertID, no singleRequestExtensions (sec. 3.1.1); nextUpdate required and time checked (sec. 5); appendix B.1, B.2, B.4 are test vectors |
| RFC 7633 | none | none verified (1 on file) | sec. 4.3.3 is the client |
| RFC 5940 | none | not rechecked | OCSP responses in CMS; row `rk.stapled-in-cms` |
| RFC 5280 | updated by nine RFCs, among them 9608 and 10007 | 6 verified | sec. 4.1.2.2 on serial numbers is cited by `request` |
| RFC 10007 | updates RFC 5280 | none | cRLSign check in CRL validation (sec. 6.3); row `rk.crl-issuer-keyusage` |
| RFC 9608 | updates RFC 5280 | 0 verified (1 on file) | noRevAvail; row `rk.norevavail` |
| RFC 5754 | updates RFC 3370 | 2 verified | defines SHA-256 as RFC 9919 sec. 3.1.1 uses it (sec. 2.2 of RFC 5754) |
| RFC 5019, RFC 8954 | obsolete (by RFC 9919, RFC 9654) | n/a | not documents to implement |

Sections read in full on 2026-11-13 for M2 and M5: RFC 6960 sec. 2.2, 4.2.1, 4.2.2 (4.2.2.1 to 4.2.2.3) and 4.4.8; RFC 9919 sec. 3.2 and 4; RFC 5280 sec. 5.2, 5.2.3, 5.2.4, 5.2.5, 5.3.3 and 6.3; RFC 10007 sec. 3 and 4; RFC 9608 sec. 2 to 5. Errata were read for RFC 6960 and RFC 5280: none touches those sections.

Test vectors: `tests/fixtures/rfc9919/` holds RFC 9919 appendix B.1, B.2 and B.4 (see its `SOURCES.txt`); the nonce extension example is RFC 9654 sec. 2.1.

Citation rules, in the order they most often get broken:

1. Cite the document. A secondary write-up is a lead, not a source.
2. A section number is cited only if that section was read in full.
3. Errata are checked at each milestone freeze, not once at the start.
4. Where a claim came from a body outside the RFC series, that body is named here.

Re-verify with the RFC library rather than memory: `info('RFCnnnn')` for current status, `errata('RFCnnnn')` for corrections, and `read('RFCnnnn', view='normative')` for the MUST and SHOULD statements that become obligation rows.
