# Instructions for coding agents

Revocation in practice: OCSP request and response handling to RFC 9654 and RFC 9919, CRL and delta CRL processing, stapled response checks and caching.

Primary documents are listed in `docs/rfc-map.md` with statuses and known errata.
The obligation table in `ROADMAP.md` records what is owed, and `README.md` explains
what the library is for. Read those three before changing anything.

## Finding work

If the person gave you a task, do that task.

If you arrived with nothing to do, run this from this directory:

    python -m projecthub pickup --who <your name> --project revokekit

Its output is your assignment: one row, already claimed for you, with what to build, the commands that prove
it and the ways to end it. The board decides the order of work, so the row it gives you is the row to work,
even if it is in another project. `NO WORK` is a real answer: ask the person what to work on.

Without the workspace beside this repository, read `.projecthub/packet.md` if it exists. If it does not, ask what
to work on.

## Commands

    python -m pip install -e ".[dev]"
    python -m pytest -q
    python -m pytest -q tests/test_roadmap_rows.py
    python -m pytest -q tests/test_public_api.py::test_stubs_are_loud
    python -m ruff check .
    python -m ruff format --check .
    python -m mypy revokekit tests

The first line installs the dev extras. The six commands after it are the gates,
and all six must pass before a change is finished. CI runs the same set on Linux
and Windows, plus the suite under `python -O`.

## Invariants

These are the points where a plausible-looking change makes the project wrong
rather than merely incomplete.

1. **Roadmap honesty.** Never change a `ROADMAP.md` row from `[ ]` to `[ok]` unless
   the test named in its `Where` cell exists, passes, and would fail if the behaviour
   regressed. A Where cell marked `(to be written)` names a test nobody has written:
   write it, then drop the marker in the same commit that flips the row.
   `tests/test_roadmap_rows.py` checks only that every row names a callable the
   package defines; it cannot tell a passing test from a missing one, so this rule
   is the check. Do not weaken that test, skip it, or delete it to get a green run.
2. **No silent stubs.** Code that is not implemented raises `NotImplementedError`.
   Never return an empty value, an empty collection, or a result object that reports
   success. A protocol library that answers nothing is worse than one that refuses
   to answer, and `tests/test_public_api.py` enforces that every stub is loud.
3. **Normative text is never paraphrased from memory.** Fetch it with the `rfc_*`
   tools and cite the section. If the text you fetch does not say what the obligation claims,
   the obligation is wrong: fix the roadmap row and say so in the commit.
4. **Dependencies.** `pyproject.toml` declares `asn1core` (this workspace's own codec), `sigwire[verify]`
   (signature verification; `sigprim` was merged into it) and `pkix` (the delegated responder's signature and
   validity), resolved from sibling checkouts (`pythonpath` and `mypy_path` point at `../asn1core`,
   `../sigwire`, `../pkix`) because none is on an index yet. No `asn1crypto` or `pyasn1`, and package code
   never imports `cryptography`: it arrives only through `sigwire.verify`. The tests import it to generate a
   test PKI (`tests/pki_helpers.py`); that is a test convenience, not a specification vector. Adding another runtime dependency
   needs a paragraph of justification in `docs/strategy.md` explaining why the standard library is not
   enough. Until asn1core has a DER builder, `request.py` assembles its few TLVs with a private `_tlv`
   (row `rk.request-asn1core-builder`).
5. **Scope.** What is deliberately absent is listed under Non-goals in `README.md`.
   An agent that "helpfully" implements a non-goal has expanded the API surface that
   has to be supported forever.

## Read before implementing

- RFC 6960 carries 6 verified errata and is updated by RFC 8954 and RFC 9654: read 9654 before implementing Nonce, because it supersedes the older constraint.
- RFC 9654 and RFC 9919 report no errata as of 2026-11-07 (rfclib), and both are new enough that implementations are the open question rather than corrections.
- RFC 5280 carries 6 verified errata and is updated by nine later RFCs (6818, 8398, 8399, 9549, 9598, 9608, 9618, 9925, 10007) as of 2026-11-07 (rfclib). RFC 8954 is obsoleted by RFC 9654 and is not a document to implement.
- RFC 9919 obsoletes RFC 5019. Recipes copied from 5019 describe the superseded profile.

## Protocol work

`.clinerules/10-rfclib.md` describes the `rfc_*` tool calls to make for each obligation
and lists the section refs for this project. If you are not running in Cline, the
same procedure applies: confirm the document, read its errata, pull the normative
statements, then write code.
