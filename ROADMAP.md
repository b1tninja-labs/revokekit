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
| `request.build()` | RFC 6960 sec. 4.1, RFC 9919 sec. 3.1.1 | `[ ]` | `tests/test_obligations.py::test_build` (to be written) | M1 |
| `response.parse_and_verify()` | RFC 6960 | `[ ]` | `tests/test_obligations.py::test_parse_and_verify` (to be written) | M2 |
| `nonce.generate()` | RFC 9654 sec. 2.1 | `[ ]` | `tests/test_obligations.py::test_generate` (to be written) | M3 |
| `nonce.check()` | RFC 9654 sec. 2.1 | `[ ]` | `tests/test_obligations.py::test_check` (to be written) | M3 |
| `freshest.is_fresh()` | RFC 9919 sec. 5 | `[ ]` | `tests/test_obligations.py::test_is_fresh` (to be written) | M4 |
| `http.query()` | RFC 6960 appendix A | `[ ]` | `tests/test_obligations.py::test_query` (to be written) | M4 |
| `crl.fetch()` | RFC 5280 sec. 4.2.1.13 | `[ ]` | `tests/test_obligations.py::test_fetch` (to be written) | M5 |
| `stapling.verify_stapled()` | RFC 7633 sec. 4.3.3 | `[ ]` | `tests/test_obligations.py::test_verify_stapled` (to be written) | M5 |

## 2. Milestones

- M1 request and response codec against RFC 6960 vectors
- M2 signature and delegated responder verification
- M3 nonce rules per RFC 9654 with explicit missing-nonce policy
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

## 4. Deliberate non-goals

| Non-goal | Status | Revisit when |
|---|---|---|
| being an OCSP responder, which is a deployment product | `[no]` | a named document requires it |
| path validation, which is pkix and consumes this library | `[no]` | a named document requires it |
| CRL generation for CA operators | `[no]` | a named document requires it |

## 5. Open questions

- whether `response.parse_and_verify()` splits into a parse row (M1, the codec) and a verify row (M2, signature and delegated responder); it stays one row on M2 until decided (D24)

## 6. Publication checklist

- [ ] every `[ ]` row above either `[ok]` or moved to a named later milestone
- [ ] `docs/research.md` claims re-verified and the dated ones either promoted or deleted
- [ ] interoperability evidence recorded in `docs/` against a non-Python implementation
- [ ] `tools/check_dist.py` proves the wheel ships the fixtures the README promises
- [ ] version 0.1.0 tagged, trusted publisher configured, README badges uncommented
