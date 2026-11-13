"""CRL verification, delta CRLs, the RFC 10007 cRLSign check and RFC 9608 noRevAvail."""

from __future__ import annotations

import asn1core
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import AuthorityInformationAccessOID, ObjectIdentifier
from pki_helpers import DAY, HOUR, NOW, _builder, crl_der, key_usage, make_ca, make_leaf, name

from revokekit import crl as crl_module
from revokekit.errors import CrlError, NoRevAvailViolation, SignatureInvalid

CA = make_ca()
LEAF = make_leaf(CA, serial=1001)
REVOKED = make_leaf(CA, serial=1002)
HELD = make_leaf(CA, serial=1003)


def _verify(raw, issuer=CA, **kw):
    kw.setdefault("at", NOW)
    return crl_module.parse_and_verify(raw, issuer.parsed, **kw)


def test_signature_is_over_stored_tbs_cert_list():
    raw = crl_der(CA, [(1002, NOW - DAY, x509.ReasonFlags.key_compromise)])
    verified = _verify(raw)
    assert verified.signature.scheme == "ecdsa"
    assert verified.number == 1
    assert not verified.is_delta
    status = crl_module.status_of(REVOKED.parsed, verified, at=NOW)
    assert (status.state, status.reason) == ("revoked", 1)
    assert crl_module.status_of(LEAF.parsed, verified, at=NOW).state == "good"
    # One flipped bit in the stored tbsCertList breaks the signature, whatever the bit is.
    parsed = asn1core.parse_crl(raw)
    at = raw.index(parsed.tbs_cert_list) + len(parsed.tbs_cert_list) - 3
    broken = bytearray(raw)
    broken[at] ^= 0x01
    with pytest.raises(SignatureInvalid):
        _verify(bytes(broken))
    # A CRL signed by another key under the same name is refused too.
    impostor = make_ca("Test CA")
    with pytest.raises(SignatureInvalid):
        _verify(crl_der(impostor))


def test_crl_issuer_name_and_time_are_checked():
    other = make_ca("Elsewhere")
    with pytest.raises(CrlError, match="issuer"):
        _verify(crl_der(CA), issuer=other)
    with pytest.raises(CrlError, match="nextUpdate"):
        _verify(crl_der(CA, this_update=NOW - 3 * DAY, next_update=NOW - DAY))
    with pytest.raises(CrlError, match="future"):
        _verify(crl_der(CA, this_update=NOW + HOUR, next_update=NOW + DAY))


def test_status_requires_the_crl_issuer_to_be_the_certificate_issuer():
    verified = _verify(crl_der(CA))
    stranger = make_leaf(make_ca("Elsewhere"))
    with pytest.raises(CrlError, match="not issued by the CRL issuer"):
        crl_module.status_of(stranger.parsed, verified, at=NOW)


def test_unprocessed_critical_extension_makes_the_crl_unusable():
    odd = (x509.UnrecognizedExtension(ObjectIdentifier("1.2.3.4"), b"\x05\x00"), True)
    with pytest.raises(CrlError, match="unprocessed critical"):
        _verify(crl_der(CA, extra_extensions=[odd]))
    quiet = (x509.UnrecognizedExtension(ObjectIdentifier("1.2.3.4"), b"\x05\x00"), False)
    _verify(crl_der(CA, extra_extensions=[quiet]))


def test_crl_signer_without_crlsign_is_refused():
    # RFC 10007 sec. 4: a v3 issuer certificate must have keyUsage *and* cRLSign.
    without_extension = make_ca("No KU CA", key_usage=False)
    with pytest.raises(CrlError, match="no keyUsage"):
        _verify(crl_der(without_extension), issuer=without_extension)
    signing_only = make_ca("Cert Sign CA", key_usage=key_usage(key_cert_sign=True))
    with pytest.raises(CrlError, match="cRLSign"):
        _verify(crl_der(signing_only), issuer=signing_only)
    crl_only = make_ca("CRL CA", key_usage=key_usage(crl_sign=True))
    _verify(crl_der(crl_only), issuer=crl_only)
    # cRLSign is bit 6, and the neighbouring bits do not stand in for it.
    for neighbour in ("key_cert_sign", "digital_signature", "key_agreement"):
        decoy = make_ca("Decoy CA", key_usage=key_usage(**{neighbour: True}))
        with pytest.raises(CrlError, match="cRLSign"):
            crl_module.check_issuer_key_usage(decoy.parsed)


def _delta_pair(complete_revoked=(), delta_revoked=(), **delta_kw):
    complete = _verify(crl_der(CA, complete_revoked, number=5))
    delta = _verify(crl_der(CA, delta_revoked, number=7, delta_base=5, **delta_kw))
    return complete, delta


def test_delta_crl_is_applied_to_its_base():
    held_then_released = [(1003, NOW - DAY, x509.ReasonFlags.certificate_hold)]
    complete, delta = _delta_pair(
        complete_revoked=[(1002, NOW - 2 * DAY, x509.ReasonFlags.superseded), *held_then_released],
        delta_revoked=[
            (1001, NOW - HOUR, x509.ReasonFlags.key_compromise),
            (1003, NOW - HOUR, x509.ReasonFlags.remove_from_crl),
        ],
    )
    assert delta.is_delta
    assert delta.base_number == 5
    # Newly revoked on the delta only.
    new = crl_module.status_of(LEAF.parsed, complete, delta, at=NOW)
    assert (new.state, new.reason, new.from_delta) == ("revoked", 1, True)
    # On the base, untouched by the delta.
    old = crl_module.status_of(REVOKED.parsed, complete, delta, at=NOW)
    assert (old.state, old.reason, old.from_delta) == ("revoked", 4, False)
    # On hold in the base, released by removeFromCRL in the delta (step (k)).
    released = crl_module.status_of(HELD.parsed, complete, delta, at=NOW)
    assert released.state == "good"
    # Without the delta the same certificate is still on hold: the delta is what changes it.
    held = crl_module.status_of(HELD.parsed, complete, at=NOW)
    assert (held.state, held.on_hold) == ("revoked", True)
    # A certificate on neither CRL is good.
    assert (
        crl_module.status_of(make_leaf(CA, serial=9).parsed, complete, delta, at=NOW).state
        == "good"
    )


def test_delta_crl_that_cannot_combine_is_refused():
    complete = _verify(crl_der(CA, number=5))
    # RFC 5280 sec. 5.2.4 (c): the base number may not exceed the complete CRL's number.
    newer_base = _verify(crl_der(CA, number=9, delta_base=6))
    with pytest.raises(CrlError, match="older than the delta's base"):
        crl_module.status_of(LEAF.parsed, complete, newer_base, at=NOW)
    # (d): the delta must follow the complete CRL.
    behind = _verify(crl_der(CA, number=5, delta_base=4))
    with pytest.raises(CrlError, match="does not follow"):
        crl_module.status_of(LEAF.parsed, complete, behind, at=NOW)
    # A complete CRL standing where the delta should be.
    with pytest.raises(CrlError, match="no delta CRL indicator"):
        crl_module.status_of(LEAF.parsed, complete, _verify(crl_der(CA, number=8)), at=NOW)
    # Differing authority key identifiers (sec. 6.3.3 (c)(3)).
    no_aki = _verify(crl_der(CA, number=8, delta_base=5, aki=False))
    with pytest.raises(CrlError, match="authority key identifier"):
        crl_module.status_of(LEAF.parsed, complete, no_aki, at=NOW)
    # A delta indicator with a base at or above its own number is nonsense.
    with pytest.raises(CrlError, match="BaseCRLNumber"):
        _verify(crl_der(CA, number=5, delta_base=5))
    # A delta CRL cannot stand alone.
    with pytest.raises(CrlError, match="complete CRL first"):
        crl_module.status_of(LEAF.parsed, _verify(crl_der(CA, number=8, delta_base=5)), at=NOW)


def test_delta_crl_must_be_current():
    complete = _verify(crl_der(CA, number=5))
    delta = _verify(crl_der(CA, number=7, delta_base=5, next_update=NOW + HOUR))
    late = NOW + 2 * HOUR
    with pytest.raises(CrlError, match="not current"):
        crl_module.status_of(LEAF.parsed, complete, delta, at=late)


def test_idp_scope_is_applied():
    users_only = x509.IssuingDistributionPoint(
        full_name=None,
        relative_name=None,
        only_contains_user_certs=True,
        only_contains_ca_certs=False,
        only_some_reasons=None,
        indirect_crl=False,
        only_contains_attribute_certs=False,
    )
    verified = _verify(crl_der(CA, idp=users_only))
    assert crl_module.status_of(LEAF.parsed, verified, at=NOW).state == "good"
    sub_ca = make_leaf(CA, serial=77)
    ca_cert = (
        _builder(name("Sub"), CA.cert.subject, sub_ca.key, 77)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(CA.key, hashes.SHA256())
    )
    ca_parsed = asn1core.parse_certificate(ca_cert.public_bytes(serialization.Encoding.DER))
    with pytest.raises(CrlError, match="only user certificates"):
        crl_module.status_of(ca_parsed, verified, at=NOW)
    unsupported = x509.IssuingDistributionPoint(
        full_name=None,
        relative_name=None,
        only_contains_user_certs=False,
        only_contains_ca_certs=False,
        only_some_reasons=frozenset({x509.ReasonFlags.key_compromise}),
        indirect_crl=False,
        only_contains_attribute_certs=False,
    )
    with pytest.raises(CrlError, match="onlySomeReasons"):
        crl_module.status_of(LEAF.parsed, _verify(crl_der(CA, idp=unsupported)), at=NOW)


def test_idp_distribution_point_name_must_match_the_certificate():
    uri = x509.UniformResourceIdentifier("http://crl.example/ca.crl")
    idp = x509.IssuingDistributionPoint(
        full_name=[uri],
        relative_name=None,
        only_contains_user_certs=False,
        only_contains_ca_certs=False,
        only_some_reasons=None,
        indirect_crl=False,
        only_contains_attribute_certs=False,
    )
    verified = _verify(crl_der(CA, idp=idp))

    def leaf_with(dp_uri):
        key = make_leaf(CA).key
        builder = _builder(name("dp.example"), CA.cert.subject, key, 1500)
        if dp_uri is not None:
            builder = builder.add_extension(
                x509.CRLDistributionPoints([x509.DistributionPoint([dp_uri], None, None, None)]),
                critical=False,
            )
        cert = builder.sign(CA.key, hashes.SHA256())
        return asn1core.parse_certificate(cert.public_bytes(serialization.Encoding.DER))

    assert crl_module.status_of(leaf_with(uri), verified, at=NOW).state == "good"
    other = x509.UniformResourceIdentifier("http://other.example/x.crl")
    with pytest.raises(CrlError, match="distribution point"):
        crl_module.status_of(leaf_with(other), verified, at=NOW)
    with pytest.raises(CrlError, match="distribution point"):
        crl_module.status_of(leaf_with(None), verified, at=NOW)


def _cert_with(*extensions, ca=CA, serial=3000, is_ca=False):
    key = make_leaf(CA).key
    builder = _builder(name("nrv.example"), ca.cert.subject, key, serial)
    if is_ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
    for ext, critical in extensions:
        builder = builder.add_extension(ext, critical=critical)
    cert = builder.sign(ca.key, hashes.SHA256())
    return asn1core.parse_certificate(cert.public_bytes(serialization.Encoding.DER))


NO_REV_AVAIL = (x509.UnrecognizedExtension(ObjectIdentifier("2.5.29.56"), b"\x05\x00"), False)


def test_norevavail_skips_revocation_checking():
    # RFC 9608 sec. 4: noRevAvail or id-pkix-ocsp-nocheck present -> step (a)(3) is skipped.
    assert crl_module.revocation_required(LEAF.parsed) is True
    assert crl_module.revocation_required(_cert_with(NO_REV_AVAIL)) is False
    assert crl_module.revocation_required(_cert_with((x509.OCSPNoCheck(), False))) is False


def test_norevavail_with_forbidden_companions_is_invalid():
    # RFC 9608 sec. 3: a CA, a CRLDP, a Freshest CRL or an OCSP access method next to noRevAvail.
    crldp = (
        x509.CRLDistributionPoints(
            [
                x509.DistributionPoint(
                    [x509.UniformResourceIdentifier("http://crl.example/x")], None, None, None
                )
            ]
        ),
        False,
    )
    ocsp_aia = (
        x509.AuthorityInformationAccess(
            [
                x509.AccessDescription(
                    AuthorityInformationAccessOID.OCSP,
                    x509.UniformResourceIdentifier("http://ocsp.example"),
                )
            ]
        ),
        False,
    )
    ca_issuers_only = (
        x509.AuthorityInformationAccess(
            [
                x509.AccessDescription(
                    AuthorityInformationAccessOID.CA_ISSUERS,
                    x509.UniformResourceIdentifier("http://ca.example/ca.cer"),
                )
            ]
        ),
        False,
    )
    freshest = (
        x509.FreshestCRL(
            [
                x509.DistributionPoint(
                    [x509.UniformResourceIdentifier("http://crl.example/d")], None, None, None
                )
            ]
        ),
        False,
    )
    for companion, fragment in (
        (crldp, "CRL Distribution"),
        (ocsp_aia, "id-ad-ocsp"),
        (freshest, "Freshest"),
    ):
        with pytest.raises(NoRevAvailViolation, match=fragment):
            crl_module.revocation_required(_cert_with(NO_REV_AVAIL, companion))
    with pytest.raises(NoRevAvailViolation, match="cA TRUE"):
        crl_module.revocation_required(_cert_with(NO_REV_AVAIL, is_ca=True))
    # caIssuers is not an OCSP method and is allowed.
    assert crl_module.revocation_required(_cert_with(NO_REV_AVAIL, ca_issuers_only)) is False
    bad_value = (x509.UnrecognizedExtension(ObjectIdentifier("2.5.29.56"), b"\x04\x00"), False)
    with pytest.raises(NoRevAvailViolation, match="NULL"):
        crl_module.revocation_required(_cert_with(bad_value))
    # Without the extension the same companions are fine.
    assert crl_module.revocation_required(_cert_with(crldp)) is True
