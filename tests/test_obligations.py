"""End to end: the public ``response.parse_and_verify`` behind the ROADMAP row of that name."""

from __future__ import annotations

import pytest
from cryptography import x509
from cryptography.x509 import ocsp
from pki_helpers import DAY, NOW, make_ca, make_delegate, make_leaf, ocsp_response, single_response

import revokekit
from revokekit import nonce, request, response
from revokekit.errors import ResponderNotAuthorized, ResponseError


def test_parse_and_verify():
    ca = make_ca()
    leaf = make_leaf(ca)
    delegate = make_delegate(ca)
    challenge = nonce.generate()
    # The request that would have been sent, and a response to it signed by a delegate.
    assert request.build(leaf.parsed.raw, ca.parsed.raw, challenge)
    revoked = single_response(
        leaf,
        ca,
        status=ocsp.OCSPCertStatus.REVOKED,
        revocation_time=NOW - DAY,
        reason=x509.ReasonFlags.superseded,
    )
    raw = ocsp_response(delegate, [revoked], include_certs=[delegate], nonce=challenge)
    verified = revokekit.parse_and_verify(
        raw, leaf.parsed, ca.parsed, at=NOW, request_nonce=challenge
    )
    assert verified.status == "revoked"
    assert verified.single.revocation_reason == 4
    assert verified.signer.kind == "delegate"
    assert verified.freshness
    # The same response about another certificate: nothing to say, so it is refused, not "good".
    other = make_leaf(ca, serial=555)
    with pytest.raises(ResponseError, match="no SingleResponse"):
        revokekit.parse_and_verify(raw, other.parsed, ca.parsed, at=NOW)
    # And a response signed by a stranger's key is refused before its status is looked at.
    rogue = make_ca("Rogue")
    forged = ocsp_response(rogue, [single_response(leaf, ca)], by_key=False)
    with pytest.raises(ResponderNotAuthorized):
        response.parse_and_verify(forged, leaf.parsed, ca.parsed, at=NOW)
