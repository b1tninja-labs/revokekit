"""The soft-fail contract (row `rk.soft-fail-policy`, PORTFOLIO.md section 9 item 15).

revokekit fails closed: a CRL that cannot establish a status gives "unknown", never "good". Falling
back to OCSP happens only when the caller passes `Fallback.OCSP`.
"""

from __future__ import annotations

import pytest
from pki_helpers import NOW, crl_der, make_ca, make_leaf, ocsp_response, single_response

from revokekit import crl as crl_module
from revokekit import response
from revokekit.decide import Decision, Fallback, decide
from revokekit.errors import CrlError

CA = make_ca()
LEAF = make_leaf(CA)


def _broken_fetch() -> crl_module.CrlStatus:
    raise OSError("connection refused")


def _ocsp_good() -> response.VerifiedResponse:
    raw = ocsp_response(CA, [single_response(LEAF, CA)])
    return response.parse_and_verify(raw, LEAF.parsed, CA.parsed, at=NOW)


def _crl_good() -> crl_module.CrlStatus:
    verified = crl_module.parse_and_verify(crl_der(CA), CA.parsed, at=NOW)
    return crl_module.status_of(LEAF.parsed, verified, at=NOW)


def test_failed_fetch_is_not_good():
    decision = decide(_broken_fetch, _ocsp_good)
    assert decision == Decision("unknown", None, decision.reasons)
    assert not decision.acceptable
    assert any("connection refused" in r for r in decision.reasons)
    # The OCSP source was offered but not asked: the fallback is the caller's explicit choice.
    assert any("no fallback" in r for r in decision.reasons)


def test_a_crl_that_cannot_answer_is_unknown_without_a_fallback():
    def other_issuer() -> crl_module.CrlStatus:
        other = make_ca("Other CA")
        verified = crl_module.parse_and_verify(crl_der(other), other.parsed, at=NOW)
        return crl_module.status_of(LEAF.parsed, verified, at=NOW)

    with pytest.raises(CrlError):
        other_issuer()
    assert decide(other_issuer).state == "unknown"


def test_ocsp_fallback_is_used_only_when_asked():
    decision = decide(_broken_fetch, _ocsp_good, fallback=Fallback.OCSP)
    assert (decision.state, decision.source) == ("good", "ocsp")
    assert decide(_broken_fetch, None, fallback=Fallback.OCSP).state == "unknown"


def test_a_working_crl_answers_by_itself():
    decision = decide(_crl_good)
    assert (decision.state, decision.source) == ("good", "crl")
