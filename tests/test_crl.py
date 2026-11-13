"""CRL verification, delta CRLs, the RFC 10007 cRLSign check and RFC 9608 noRevAvail."""

from __future__ import annotations

import asn1core
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID, ObjectIdentifier
from pki_helpers import (
    DAY,
    HOUR,
    NOW,
    Party,
    _builder,
    crl_der,
    key_usage,
    make_ca,
    make_leaf,
    name,
)

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
    with pytest.raises(CrlError, match="no CRL from the certificate's issuer"):
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
            _verify(crl_der(decoy), issuer=decoy)


_FRESHEST = (
    x509.FreshestCRL(
        [
            x509.DistributionPoint(
                [x509.UniformResourceIdentifier("http://d.example/d")], None, None, None
            )
        ]
    ),
    False,
)


def _delta_pair(complete_revoked=(), delta_revoked=(), **delta_kw):
    # The CRL carries FreshestCRL here, so the delta is also one the CRL points at; the tests of
    # `rk.crl-explicit-delta` below leave it out.
    complete = _verify(crl_der(CA, complete_revoked, number=5, extra_extensions=[_FRESHEST]))
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
    with pytest.raises(CrlError, match="onlyContainsUserCerts"):
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
    # onlySomeReasons is decided by pkix now: one reason alone leaves the status UNDETERMINED.
    with pytest.raises(CrlError, match="no usable CRL covers the reasons"):
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


# -- CRL decisions are pkix's (rk.crl-decide-via-pkix) and the extensions asn1core's -------------

_IDP_OID = ObjectIdentifier("2.5.29.28")
_NUMBER_OID = ObjectIdentifier("2.5.29.20")


def _idp(**kw):
    base = {
        "full_name": None,
        "relative_name": None,
        "only_contains_user_certs": False,
        "only_contains_ca_certs": False,
        "only_some_reasons": None,
        "indirect_crl": False,
        "only_contains_attribute_certs": False,
    }
    return x509.IssuingDistributionPoint(**(base | kw))


def _der_integer(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() // 8) + 1, "big")
    return b"\x02" + asn1core.encode_length(len(body)) + body


def test_crl_extensions_are_read_by_asn1core():
    # The extensions come back as asn1core's types: one DER reader.
    verified = _verify(crl_der(CA, idp=_idp(only_contains_user_certs=True), number=7))
    assert isinstance(verified.idp, asn1core.extensions.IssuingDistributionPoint)
    assert verified.idp.only_contains_user_certs
    assert verified.number == 7
    # X.690 sec. 11.5: an encoded DEFAULT FALSE is not DER. The old reader accepted [1] FALSE.
    default_false = (x509.UnrecognizedExtension(_IDP_OID, b"\x30\x03\x81\x01\x00"), True)
    with pytest.raises(CrlError, match="malformed CRL extension"):
        _verify(crl_der(CA, extra_extensions=[default_false]))
    # RFC 5280 sec. 5.2.3 limits issuers to 20 octets; a verifier is not told to refuse more.
    # The old reader refused 21 octets, so every CRL after it was unusable.
    huge = 1 << 167  # 22 content octets with the sign octet; the old reader stopped at 21
    assert len(_der_integer(huge)) - 2 == 22
    number = (x509.UnrecognizedExtension(_NUMBER_OID, _der_integer(huge)), False)
    assert _verify(crl_der(CA, number=None, extra_extensions=[number])).number == huge


def test_status_of_agrees_with_pkix_crl_checker():
    import pkix.revocation as pr

    revoked = [(1002, NOW - DAY, x509.ReasonFlags.key_compromise)]
    complete = _verify(crl_der(CA, revoked, number=3))
    for cert, state in ((REVOKED, "revoked"), (LEAF, "good")):
        ours = crl_module.status_of(cert.parsed, complete, at=NOW)
        spki = CA.parsed.subject_public_key_info
        request = pr.RevocationRequest(cert.parsed, CA.parsed.subject, spki, CA.parsed, NOW, 1)
        theirs = pr.CrlChecker([complete.crl])(request)
        assert (ours.state, theirs.status) == (state, state)
        assert ours.answer == theirs
    # A CRL that cannot settle the status is an error here, never "good".
    other = make_leaf(make_ca("Elsewhere"))
    with pytest.raises(CrlError, match="undetermined"):
        crl_module.status_of(other.parsed, complete, at=NOW)


def test_reasons_mask_accumulates_across_partitioned_crls():
    flags = x509.ReasonFlags
    first = _idp(
        only_some_reasons=frozenset(
            {flags.key_compromise, flags.ca_compromise, flags.affiliation_changed}
        )
    )
    second = _idp(
        only_some_reasons=frozenset(
            {
                flags.superseded,
                flags.cessation_of_operation,
                flags.certificate_hold,
                flags.privilege_withdrawn,
                flags.aa_compromise,
            }
        )
    )
    one = _verify(crl_der(CA, idp=first, number=1))
    two = _verify(crl_der(CA, [(1002, NOW - DAY, flags.superseded)], idp=second, number=1))
    # One partition alone leaves reasons uncovered: UNDETERMINED, so an error, never good.
    with pytest.raises(CrlError, match="no usable CRL covers the reasons"):
        crl_module.status_of(LEAF.parsed, one, at=NOW)
    both = crl_module.status_of(LEAF.parsed, one, at=NOW, more_crls=[two.crl])
    assert both.state == "good"
    hit = crl_module.status_of(REVOKED.parsed, one, at=NOW, more_crls=[two.crl])
    assert (hit.state, hit.reason) == ("revoked", 4)


def _rdn(value: str) -> x509.RelativeDistinguishedName:
    return x509.RelativeDistinguishedName(
        [x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, value)]
    )


def test_relative_distribution_point_name_is_matched():
    verified = _verify(crl_der(CA, idp=_idp(relative_name=_rdn("p1"))))

    def leaf_with(point_rdn):
        key = make_leaf(CA).key
        point = x509.DistributionPoint(None, point_rdn, None, None)
        cert = (
            _builder(name("rdn.example"), CA.cert.subject, key, 1600)
            .add_extension(x509.CRLDistributionPoints([point]), critical=False)
            .sign(CA.key, hashes.SHA256())
        )
        return asn1core.parse_certificate(cert.public_bytes(serialization.Encoding.DER))

    assert crl_module.status_of(leaf_with(_rdn("p1")), verified, at=NOW).state == "good"
    with pytest.raises(CrlError, match="another distribution point"):
        crl_module.status_of(leaf_with(_rdn("p2")), verified, at=NOW)


def test_explicit_delta_is_applied_without_freshest_crl():
    # Row `rk.crl-explicit-delta`: no FreshestCRL on the CRL or the certificate, yet the caller
    # holds a delta that names the leaf. pkix's explicit-delta mode reads it (RFC 5280 sec. 6.3.3
    # (c), (h), (i)); it is neither ignored (a wrong "good") nor refused.
    complete = _verify(crl_der(CA, number=5))
    named = [(1001, NOW - HOUR, x509.ReasonFlags.key_compromise)]
    delta = _verify(crl_der(CA, named, number=7, delta_base=5))
    assert crl_module.status_of(LEAF.parsed, complete, at=NOW).state == "good"
    status = crl_module.status_of(LEAF.parsed, complete, delta, at=NOW)
    assert (status.state, status.reason, status.from_delta) == ("revoked", 1, True)
    assert status.revocation_date == NOW - HOUR
    # A delta that removes a held certificate is read the same way (step (k)).
    held = _verify(crl_der(CA, [(1003, NOW - DAY, x509.ReasonFlags.certificate_hold)], number=5))
    release = [(1003, NOW - HOUR, x509.ReasonFlags.remove_from_crl)]
    released = _verify(crl_der(CA, release, number=7, delta_base=5))
    assert crl_module.status_of(HELD.parsed, held, at=NOW).on_hold
    assert crl_module.status_of(HELD.parsed, held, released, at=NOW).state == "good"


def test_answer_details_come_from_pkix_for_the_entry_that_decided():
    # Row `rk.crl-answer-details`: reason code, date and delta origin are pkix's fields, so a
    # certificate named in a complete CRL keeps its own reason when a delta exists that does not
    # mention it, and an absent reason code is unspecified (0), not None.
    complete, delta = _delta_pair(
        complete_revoked=[(1002, NOW - 2 * DAY, x509.ReasonFlags.superseded)],
        delta_revoked=[(1001, NOW - HOUR, None)],
    )
    old = crl_module.status_of(REVOKED.parsed, complete, delta, at=NOW)
    assert (old.reason, old.revocation_date, old.from_delta, old.on_hold) == (
        4,
        NOW - 2 * DAY,
        False,
        False,
    )
    assert old.answer is not None
    assert (old.answer.reason_code, old.answer.on_delta) == (4, False)
    bare = crl_module.status_of(LEAF.parsed, complete, delta, at=NOW)
    assert (bare.state, bare.reason, bare.from_delta) == ("revoked", 0, True)
    held = _verify(crl_der(CA, [(1003, NOW - DAY, x509.ReasonFlags.certificate_hold)], number=5))
    assert crl_module.status_of(HELD.parsed, held, at=NOW).on_hold


def test_indirect_crl_entries_are_attributed_by_certificate_issuer():
    import pkix.anchors

    root = make_ca("Root")
    signer_key = make_leaf(root).key
    signer_cert = (
        _builder(name("CRL Signer"), root.cert.subject, signer_key, 50)
        .add_extension(key_usage(crl_sign=True), critical=True)
        .sign(root.key, hashes.SHA256())
    )
    signer = Party(signer_key, signer_cert)
    dp = x509.DistributionPoint(None, None, None, [x509.DirectoryName(signer_cert.subject)])

    def leaf(serial):
        cert = (
            _builder(name("ind.example"), root.cert.subject, make_leaf(root).key, serial)
            .add_extension(x509.CRLDistributionPoints([dp]), critical=False)
            .sign(root.key, hashes.SHA256())
        )
        return asn1core.parse_certificate(cert.public_bytes(serialization.Encoding.DER))

    # Entries name their certificate issuer (RFC 5280 sec. 5.3.3): without it they would be the
    # CRL signer's own certificates.
    entry = (
        x509.RevokedCertificateBuilder()
        .serial_number(7001)
        .revocation_date(NOW - DAY)
        .add_extension(
            x509.CertificateIssuer([x509.DirectoryName(root.cert.subject)]), critical=True
        )
        .add_extension(x509.CRLReason(x509.ReasonFlags.key_compromise), critical=False)
        .build()
    )
    indirect = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(signer_cert.subject)
        .last_update(NOW - HOUR)
        .next_update(NOW + DAY)
        .add_extension(x509.CRLNumber(1), critical=False)
        .add_extension(_idp(indirect_crl=True), critical=True)
        .add_revoked_certificate(entry)
        .sign(signer_key, hashes.SHA256())
        .public_bytes(serialization.Encoding.DER)
    )
    verified = crl_module.parse_and_verify(indirect, signer.parsed, at=NOW)
    anchor = pkix.anchors.load_anchor(root.cert.public_bytes(serialization.Encoding.DER))
    extra = {
        "issuer": root.parsed,
        "certificates": [signer.parsed],
        "anchor": anchor,
        "more_crls": [crl_der(root)],
        "at": NOW,
    }
    hit = crl_module.status_of(leaf(7001), verified, **extra)
    assert (hit.state, hit.reason) == ("revoked", 1)
    assert crl_module.status_of(leaf(7002), verified, **extra).state == "good"
    # Without the trust anchor (and without Root's own CRL, which would answer for the assumed
    # distribution point) the CRL signer's path cannot be validated: never "good".
    with pytest.raises(CrlError):
        crl_module.status_of(leaf(7002), verified, **{**extra, "anchor": None, "more_crls": []})
