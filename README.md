# revokekit

<!-- PyPI badges go live with the first release. Until then a version badge renders
     "no version" on the landing page, which reads as a defect rather than a date, so
     the badges stay commented out until the tag exists.
-->

**Pre-alpha shell.** The package surface, the obligation matrix and the CI gates exist.
No protocol behaviour is implemented: every public function raises `NotImplementedError`,
and the test suite records that rather than hiding it. Read
[ROADMAP.md](ROADMAP.md) before depending on any of it.

revokekit -- OCSP and CRL clients that know the current specification

OCSP is being rewritten while we watch. RFC 9654 obsoleted RFC 8954 in 2024-08 and redefined the Nonce extension, and RFC 9919 obsoleted RFC 5019 in July 2026 with a lightweight high volume profile that recommends SHA-256. cryptography can build and parse an OCSP request but ships no client, no caching, no responder chain rules and no nonce policy, and the only library that ever did revocation end to end died in 2016. Meanwhile the deployments that matter check stapled responses whose must-staple extension comes from RFC 7633. revokekit is the client and the policy, written against the documents as they now stand, and it is the revocation provider pkix consumes.

## The gap, with a date

PyPI was queried on 2026-11-05 for this name and for every neighbouring project. Landscape
claims rot quickly: two projects in this portfolio shipped within five days of the survey,
which is why the table below carries dates instead of adjectives.

| Project | Version | Last release | Why it is not this project |
|---|---|---|---|
| cryptography.x509.ocsp | 50.0.2 | 2026-09-30 | request and response types, no client, no cache, no responder policy |
| certvalidator | 0.11.1 | 2016-07-29 | did OCSP and CRL checking; unmaintained for ten years |
| x509kit | 0.10.0 | 2026-10-11 | OCSP structures and signing, not a network client or a policy |

What this project intends to add:

- an HTTP client with bounds: timeouts, response size caps, no redirect chasing, per-responder circuit breaking
- nonce handling that actually follows RFC 9654, including what to do when the responder omits it
- responder validation: delegated signing certificate, key purpose and OCSP no-check
- thisUpdate, nextUpdate and maxAge discipline with clock skew tolerance stated explicitly
- CRL and delta CRL fetching with issuer matching, and stapled response verification for TLS servers

## Specification spine

Status and publication dates below were read from the RFC Editor record on 2026-11-05. A
section number is cited only where that section was read in full; everything else cites the
document, which is the honest grain size for a plan. See [docs/rfc-map.md](docs/rfc-map.md).

| Document | Status | Published | What it gives this project |
|---|---|---|---|
| RFC 6960 | Proposed Standard | 2013-06 | OCSP request, response and the basic confirmation types |
| RFC 9654 | Proposed Standard | 2024-08 | the Nonce extension, obsoleting RFC 8954 and updating RFC 6960 |
| RFC 9919 | Proposed Standard | 2026-07 | the lightweight high volume profile, obsoleting RFC 5019 |
| RFC 7633 | Proposed Standard | 2015-10 | the TLS Feature extension behind OCSP must-staple |
| RFC 5940 | Proposed Standard | 2010-08 | revocation choices carried inside CMS, the signed document case |
| RFC 5280 | Proposed Standard | 2008-05 | the CRL and delta CRL profile and CRL validation the crl module follows |

### Errata watch

- RFC 6960 carries 6 verified errata and is updated by RFC 8954 and RFC 9654: read 9654 before implementing Nonce, because it supersedes the older constraint.
- RFC 9654 and RFC 9919 report no errata as of 2026-11-07 (rfclib), and both are new enough that implementations are the open question rather than corrections.
- RFC 5280 carries 6 verified errata and is updated by nine later RFCs (6818, 8398, 8399, 9549, 9598, 9608, 9618, 9925, 10007) as of 2026-11-07 (rfclib). RFC 8954 is obsoleted by RFC 9654 and is not a document to implement.
- RFC 9919 obsoletes RFC 5019. Recipes copied from 5019 describe the superseded profile.

## Module layout

| Module | Responsibility |
|---|---|
| `request` | build and sign requests, single and batch (RFC 6960, RFC 9919) |
| `response` | parse and verify signatures, including delegated responders (RFC 6960) |
| `nonce` | generation, echo verification and the missing nonce policy (RFC 9654) |
| `freshest` | thisUpdate, nextUpdate, maxAge and skew tolerance (RFC 6960, RFC 9919) |
| `http` | bounded transport with retries, budgets and circuit breaking |
| `crl` | CRL and delta CRL fetch, matching and cache (RFC 5280) |
| `stapling` | verify a TLS server's stapled response against the connection (RFC 7633) |
| `cache` | storage with explicit staleness decisions |

## What it does not do

- being an OCSP responder, which is a deployment product
- path validation, which is pkix and consumes this library
- CRL generation for CA operators


## Install

```bash
git clone https://github.com/b1tninja/revokekit.git
cd revokekit
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\\Scripts\\Activate.ps1
pip install -e ".[dev]"
```

Not published to PyPI yet. The name is reserved for this repository's trusted publisher at
the moment of the first release.

## Development

All four gates must pass, on Linux and Windows alike:

```bash
ruff check . && ruff format --check .
mypy revokekit
pytest -q --cov
python -O -m pytest -q
```

The last line is the one that matters most in a protocol library. `-O` strips `assert`, and a
parser whose bounds checks were asserts stops being a parser under production flags. Wire
paths raise named exceptions; asserts belong in tests and nowhere else.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
