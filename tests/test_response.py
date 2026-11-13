"""OCSP response parsing, CertID matching, signer authorization and signature (RFC 6960 sec. 4.2)."""

from __future__ import annotations

import datetime

import asn1core
import pytest
import sigwire.verify
from cryptography import x509
from cryptography.x509 import ocsp
from pki_helpers import (
    DAY,
    GOOD_STATUS,
    HOUR,
    NOW,
    make_ca,
    make_delegate,
    make_leaf,
    ocsp_response,
    ocsp_response_multi,
    revoked_status,
    single_response,
)

from revokekit import nonce as nonce_module
from revokekit import response
from revokekit.errors import (
    ResponderNotAuthorized,
    ResponseError,
    ResponseStatusError,
    SignatureInvalid,
    SignaturePolicyRefused,
)
from revokekit.request import certid

CA = make_ca()
LEAF = make_leaf(CA)
OTHER = make_leaf(CA, serial=1002, common_name="other.example")
DELEGATE = make_delegate(CA)


def _good(leaf=LEAF, **kw):
    return single_response(leaf, CA, **kw)


def _verify(raw, **kw):
    kw.setdefault("at", NOW)
    return response.parse_and_verify(raw, LEAF.parsed, CA.parsed, **kw)


def test_basic_response_keeps_tbs_response_data_bytes():
    raw = ocsp_response(CA, [_good()])
    parsed = response.parse(raw)
    assert parsed.status_name == "successful"
    basic = parsed.basic
    assert basic is not None
    # The signed region is the slice of the input, byte for byte, not a re-encoding.
    assert basic.tbs_response_data in raw
    top, _ = asn1core.decode(raw, der=True)
    inner, _ = asn1core.decode(top.children[1].children[0].children[1].content(), der=True)
    assert basic.tbs_response_data == inner.children[0].raw
    assert basic.responder.by_key is not None
    assert basic.produced_at.tzinfo is not None
    (single,) = basic.responses
    assert single.status == "good"
    assert single.cert_id.serial == LEAF.parsed.serial
    assert single.next_update is not None


def test_unsuccessful_status_carries_no_response_bytes():
    parsed = response.parse(bytes.fromhex("30030a0106"))
    assert parsed.status_name == "unauthorized"
    assert parsed.basic is None
    with pytest.raises(ResponseStatusError) as caught:
        response.parse_and_verify(bytes.fromhex("30030a0103"), LEAF.parsed, CA.parsed, at=NOW)
    assert caught.value.status == 3
    # RFC 6960 sec. 4.2.1: an error status leaves responseBytes unset; successful needs them;
    # status 4 is "not used".
    good = ocsp_response(CA, [_good()])
    with_bytes = bytearray(good)
    with_bytes[with_bytes.index(0x0A) + 2] = 6  # ENUMERATED successful(0) -> unauthorized(6)
    with pytest.raises(ResponseError, match="must not carry responseBytes"):
        response.parse(bytes(with_bytes))
    with pytest.raises(ResponseError, match="carries responseBytes"):
        response.parse(bytes.fromhex("30030a0100"))
    with pytest.raises(ResponseError, match="not defined"):
        response.parse(bytes.fromhex("30030a0104"))
    with pytest.raises(ResponseError, match="trailing"):
        response.parse(bytes.fromhex("30030a010600"))


def test_every_single_response_certid_is_compared():
    # RFC 9919 sec. 3.2.1: one SingleResponse per CertID hash; the wanted one is not first.
    raw = ocsp_response_multi(
        CA,
        [
            (certid(OTHER.parsed, CA.parsed), GOOD_STATUS, None),
            (certid(LEAF.parsed, CA.parsed, hash_name="sha1"), GOOD_STATUS, None),
            (certid(LEAF.parsed, CA.parsed), GOOD_STATUS, None),
        ],
    )
    basic = response.parse(raw).basic
    assert basic is not None
    assert len(basic.responses) == 3
    assert response.match(basic, LEAF.parsed, CA.parsed).cert_id.serial == LEAF.parsed.serial
    # The other serial is found too, and an unlisted certificate is not.
    assert response.match(basic, OTHER.parsed, CA.parsed).cert_id.serial == 1002
    stranger = make_leaf(CA, serial=4242)
    with pytest.raises(ResponseError, match="no SingleResponse"):
        response.match(basic, stranger.parsed, CA.parsed)
    # Same serial under another issuer is not a match: the name and key hashes differ.
    other_ca = make_ca("Another CA")
    twin = make_leaf(other_ca, serial=LEAF.parsed.serial)
    with pytest.raises(ResponseError, match="no SingleResponse"):
        response.match(basic, twin.parsed, other_ca.parsed)


def test_matching_singles_that_disagree_are_refused():
    raw = ocsp_response_multi(
        CA,
        [
            (certid(LEAF.parsed, CA.parsed), GOOD_STATUS, None),
            (
                certid(LEAF.parsed, CA.parsed, hash_name="sha1"),
                revoked_status(NOW - DAY),
                None,
            ),
        ],
    )
    basic = response.parse(raw).basic
    assert basic is not None
    with pytest.raises(ResponseError, match="disagree"):
        response.match(basic, LEAF.parsed, CA.parsed)


def test_revoked_carries_time_and_reason():
    raw = ocsp_response(
        CA,
        [
            _good(
                status=ocsp.OCSPCertStatus.REVOKED,
                revocation_time=NOW - DAY,
                reason=x509.ReasonFlags.key_compromise,
            )
        ],
    )
    verified = _verify(raw)
    assert verified.status == "revoked"
    assert verified.single.revocation_reason == 1
    assert verified.single.revocation_time == NOW - DAY


def test_extended_revoked_is_not_good():
    # RFC 6960 sec. 2.2 and 4.4.8: "revoked" for a non-issued certificate is hold + 1970-01-01.
    epoch = datetime.datetime(1970, 1, 1, tzinfo=datetime.UTC)
    raw = ocsp_response(
        CA,
        [
            _good(
                status=ocsp.OCSPCertStatus.REVOKED,
                revocation_time=epoch,
                reason=x509.ReasonFlags.certificate_hold,
            )
        ],
        extended_revoke=True,
    )
    verified = _verify(raw)
    assert verified.response.basic is not None
    assert verified.response.basic.extended_revoke
    assert verified.single.is_non_issued_signal
    assert verified.status == "revoked"
    assert verified.status != "good"
    plain = ocsp_response(CA, [_good()])
    assert not response.parse(plain).basic.extended_revoke


def test_signature_is_over_stored_tbs_bytes():
    raw = ocsp_response(CA, [_good()])
    verified = _verify(raw)
    assert verified.signature.scheme == "ecdsa"
    assert verified.signer.kind == "ca"
    # Flip one bit inside tbsResponseData: the stored bytes change and the signature fails.
    basic = response.parse(raw).basic
    assert basic is not None
    at = raw.index(basic.tbs_response_data) + len(basic.tbs_response_data) - 5
    tampered = bytearray(raw)
    tampered[at] ^= 0x01
    with pytest.raises(SignatureInvalid):
        _verify(bytes(tampered))
    # A signature made by some other key under the CA's name does not verify either.
    forger = make_ca("Test CA")
    with pytest.raises((SignatureInvalid, ResponderNotAuthorized)):
        _verify(ocsp_response(forger, [_good()], by_key=False))


def test_rsa_signed_response_verifies_and_a_policy_can_refuse_it():
    rsa_ca = make_ca("RSA CA", kind="rsa")
    rsa_leaf = make_leaf(rsa_ca, kind="rsa")
    single = single_response(rsa_leaf, rsa_ca)
    raw = ocsp_response(rsa_ca, [single])
    verified = response.parse_and_verify(raw, rsa_leaf.parsed, rsa_ca.parsed, at=NOW)
    assert verified.signature.scheme == "rsa-pkcs1v15"
    with pytest.raises(SignaturePolicyRefused):
        response.parse_and_verify(
            raw, rsa_leaf.parsed, rsa_ca.parsed, at=NOW, policy=sigwire.verify.Policy("nothing")
        )


def test_by_name_responder_is_identified_by_name():
    raw = ocsp_response(CA, [_good()], by_key=False)
    basic = response.parse(raw).basic
    assert basic is not None
    assert basic.responder.by_name is not None
    assert _verify(raw).signer.kind == "ca"


def test_delegate_must_be_issued_by_the_ca_with_ocspsigning():
    single = [_good()]
    ok = ocsp_response(DELEGATE, single, include_certs=[DELEGATE])
    verified = _verify(ok)
    assert verified.signer.kind == "delegate"
    assert verified.signer.nocheck

    # A delegate whose certificate was not shipped cannot be found.
    with pytest.raises(ResponderNotAuthorized, match="no certificate"):
        _verify(ocsp_response(DELEGATE, single))
    # ...unless the caller supplies it out of band.
    assert _verify(
        ocsp_response(DELEGATE, single), responder_certs=[DELEGATE.parsed]
    ).signer.kind == ("delegate")

    # No id-kp-OCSPSigning: a certificate from the CA is not thereby a responder.
    no_eku = make_delegate(CA, ocsp_signing=False, serial=2002)
    with pytest.raises(ResponderNotAuthorized, match="OCSPSigning"):
        _verify(ocsp_response(no_eku, single, include_certs=[no_eku]))

    # Issued by someone else: a different CA's delegate, same EKU, signed by the wrong key.
    rogue = make_ca("Rogue CA")
    foreign = make_delegate(rogue, serial=2003, issuer_name=CA.cert.subject)
    with pytest.raises(ResponderNotAuthorized, match="does not verify"):
        _verify(ocsp_response(foreign, single, include_certs=[foreign]))
    foreign_name = make_delegate(rogue, serial=2004)
    with pytest.raises(ResponderNotAuthorized, match="not issued by the CA"):
        _verify(ocsp_response(foreign_name, single, include_certs=[foreign_name]))

    # Expired delegate.
    expired = make_delegate(CA, serial=2005, not_after=NOW - HOUR)
    with pytest.raises(ResponderNotAuthorized, match="not valid"):
        _verify(ocsp_response(expired, single, include_certs=[expired]))

    # A locally configured authority is accepted without the EKU (RFC 6960 sec. 4.2.2.2 item 1).
    configured = _verify(
        ocsp_response(no_eku, single, include_certs=[no_eku]),
        configured_signers=[no_eku.parsed],
    )
    assert configured.signer.kind == "configured"


def test_delegate_without_nocheck_is_reported():
    plain = make_delegate(CA, nocheck=False, serial=2006)
    verified = _verify(ocsp_response(plain, [_good()], include_certs=[plain]))
    assert verified.signer.kind == "delegate"
    assert not verified.signer.nocheck


def test_nonce_is_checked_when_one_was_sent():
    sent = bytes(range(32))
    raw = ocsp_response(CA, [_good()], nonce=sent)
    assert _verify(raw, request_nonce=sent).nonce is nonce_module.NonceVerdict.MATCH
    with pytest.raises(ResponseError, match="mismatch"):
        _verify(raw, request_nonce=bytes(32))
    plain = ocsp_response(CA, [_good()])
    assert _verify(plain, request_nonce=sent).nonce is nonce_module.NonceVerdict.ABSENT_ALLOWED
    with pytest.raises(ResponseError, match="nonce"):
        _verify(plain, request_nonce=sent, require_nonce=True)


def test_stale_or_future_response_is_rejected():
    stale = ocsp_response(CA, [_good(this_update=NOW - 3 * DAY, next_update=NOW - DAY)])
    with pytest.raises(ResponseError, match="stale"):
        _verify(stale)
    future = ocsp_response(CA, [_good(this_update=NOW + DAY, next_update=NOW + 2 * DAY)])
    with pytest.raises(ResponseError, match="not_yet_valid"):
        _verify(future)


def test_malformed_response_is_refused():
    raw = ocsp_response(CA, [_good()])
    for bad in (b"", b"\x30\x80\x00\x00", raw[:-1], raw + b"\x00"):
        with pytest.raises(ResponseError):
            response.parse(bad)
