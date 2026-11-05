# Specification completeness -- and the roadmap it implies

This is the project's north star: every protocol obligation revokekit could plausibly take on,
with an honest status against the code at `HEAD`. It is blunt about gaps on purpose. A
roadmap that overstates its coverage is not a plan, it is marketing.

**The honesty rule:** a row may read `[ok]` only when a named test would fail if the
behaviour regressed. Reading the code and agreeing with it is not enough. That is how
"decoded but never sent" quietly becomes "implemented".

Legend: `[ok]` implemented and pinned by a named test -- `[part]` partial, with what is
missing stated -- `[ ]` not implemented -- `[no]` deliberate non-goal.

Update the affected row in the same commit that changes the behaviour. A row and its test
drift apart within one release, and the document becomes useless exactly when it is needed.

## 1. Obligations

| Obligation | Spec | Status | Where |
|---|---|---|---|
| `request.build()` | RFC 6960, RFC 9919 | `[ ]` | `tests/test_obligations.py::build` |
| `response.parse_and_verify()` | RFC 6960 | `[ ]` | `tests/test_obligations.py::parse_and_verify` |
| `nonce.generate()` | RFC 9654 | `[ ]` | `tests/test_obligations.py::generate` |
| `nonce.check()` | RFC 9654 | `[ ]` | `tests/test_obligations.py::check` |
| `freshest.is_fresh()` | RFC 9919 | `[ ]` | `tests/test_obligations.py::is_fresh` |
| `http.query()` | RFC 6960 | `[ ]` | `tests/test_obligations.py::query` |
| `crl.fetch()` | RFC 5280 | `[ ]` | `tests/test_obligations.py::fetch` |
| `stapling.verify_stapled()` | RFC 7633 | `[ ]` | `tests/test_obligations.py::verify_stapled` |

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
- RFC 9654 and RFC 9919 report no errata as of 2026-10-29, and both are new enough that implementations are the open question rather than corrections.
- RFC 9919 obsoletes RFC 5019. Recipes copied from 5019 describe the superseded profile.

## 4. Deliberate non-goals

| Non-goal | Status | Revisit when |
|---|---|---|
| being an OCSP responder, which is a deployment product | `[no]` | a named document requires it |
| path validation, which is pkix and consumes this library | `[no]` | a named document requires it |
| CRL generation for CA operators | `[no]` | a named document requires it |

## 5. Open questions

- none recorded yet

## 6. Publication checklist

- [ ] every `[ ]` row above either `[ok]` or moved to a named later milestone
- [ ] `docs/research.md` claims re-verified and the dated ones either promoted or deleted
- [ ] interoperability evidence recorded in `docs/` against a non-Python implementation
- [ ] `tools/check_dist.py` proves the wheel ships the fixtures the README promises
- [ ] version 0.1.0 tagged, trusted publisher configured, README badges uncommented
