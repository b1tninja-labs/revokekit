"""Generated test PKI: a CA, an OCSP delegate, leaves, signed OCSP responses and CRLs.

Everything is made here with the ``cryptography`` package, which is a *test* convenience only:
the code under test reads these bytes with asn1core and verifies with sigwire. Nothing generated
is a vector from a specification; the specification vectors in this repository are RFC 9919
appendix B (``tests/fixtures/rfc9919``).
"""

from __future__ import annotations

import datetime
from collections.abc import Sequence

import asn1core
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

_SHA256 = hashes.SHA256()
NOW = datetime.datetime(2026, 11, 13, 12, 0, 0, tzinfo=datetime.UTC)
HOUR = datetime.timedelta(hours=1)
DAY = datetime.timedelta(days=1)


def name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def new_key(kind: str = "ec"):
    if kind == "rsa":
        return rsa.generate_private_key(65537, 2048)
    return ec.generate_private_key(ec.SECP256R1())


class Party:
    """A key and the certificate that holds it."""

    def __init__(self, key, cert: x509.Certificate) -> None:
        self.key = key
        self.cert = cert

    @property
    def parsed(self) -> asn1core.Certificate:
        return asn1core.parse_certificate(self.cert.public_bytes(serialization.Encoding.DER))


def _builder(subject, issuer_name, key, serial, *, not_before=None, not_after=None):
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(not_before or NOW - 30 * DAY)
        .not_valid_after(not_after or NOW + 300 * DAY)
    )


def make_ca(common_name="Test CA", kind="ec", *, key_usage: x509.KeyUsage | None | bool = True):
    """A self-signed CA. ``key_usage=False`` leaves keyUsage out entirely (the RFC 10007 case)."""
    key = new_key(kind)
    subject = name(common_name)
    builder = _builder(subject, subject, key, 1).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    )
    if key_usage is True:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    elif isinstance(key_usage, x509.KeyUsage):
        builder = builder.add_extension(key_usage, critical=True)
    return Party(key, builder.sign(key, hashes.SHA256()))


def key_usage(**bits: bool) -> x509.KeyUsage:
    base = dict(  # noqa: C408
        digital_signature=False,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )
    base.update(bits)
    return x509.KeyUsage(**base)


def make_leaf(ca: Party, serial=1001, common_name="leaf.example", kind="ec", **kw) -> Party:
    key = new_key(kind)
    builder = _builder(name(common_name), ca.cert.subject, key, serial, **kw)
    return Party(key, builder.sign(ca.key, hashes.SHA256()))


def make_delegate(
    ca: Party,
    *,
    ocsp_signing=True,
    nocheck=True,
    serial=2001,
    issuer_name: x509.Name | None = None,
    signer_key=None,
    not_after=None,
    kind="ec",
) -> Party:
    key = new_key(kind)
    builder = _builder(
        name("OCSP Responder"),
        issuer_name or ca.cert.subject,
        key,
        serial,
        not_after=not_after,
    )
    if ocsp_signing:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]), critical=False
        )
    if nocheck:
        builder = builder.add_extension(x509.OCSPNoCheck(), critical=False)
    return Party(key, builder.sign(signer_key or ca.key, hashes.SHA256()))


def single_response(
    leaf: Party,
    ca: Party,
    *,
    status=ocsp.OCSPCertStatus.GOOD,
    this_update=None,
    next_update=None,
    revocation_time=None,
    reason=None,
    algorithm=_SHA256,
):
    return {
        "cert": leaf.cert,
        "issuer": ca.cert,
        "algorithm": algorithm,
        "status": status,
        "this_update": this_update or NOW - HOUR,
        "next_update": next_update or NOW + DAY,
        "revocation_time": revocation_time,
        "revocation_reason": reason,
    }


def ocsp_response(
    signer: Party,
    singles: list[dict],
    *,
    by_key=True,
    include_certs: list[Party] | None = None,
    nonce: bytes | None = None,
    extended_revoke=False,
    hash_algorithm=_SHA256,
) -> bytes:
    """A successful BasicOCSPResponse signed by ``signer``, as DER OCSPResponse bytes."""
    builder = ocsp.OCSPResponseBuilder()
    for s in singles:
        builder = builder.add_response(
            cert=s["cert"],
            issuer=s["issuer"],
            algorithm=s["algorithm"],
            cert_status=s["status"],
            this_update=s["this_update"],
            next_update=s["next_update"],
            revocation_time=s["revocation_time"],
            revocation_reason=s["revocation_reason"],
        )
    encoding = ocsp.OCSPResponderEncoding.HASH if by_key else ocsp.OCSPResponderEncoding.NAME
    builder = builder.responder_id(encoding, signer.cert)
    if include_certs:
        builder = builder.certificates([p.cert for p in include_certs])
    if nonce is not None:
        builder = builder.add_extension(x509.OCSPNonce(nonce), critical=False)
    if extended_revoke:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.5.5.7.48.1.9"), b"\x05\x00"),
            critical=False,
        )
    response = builder.sign(signer.key, hash_algorithm)
    return response.public_bytes(serialization.Encoding.DER)


def crl_der(
    ca: Party,
    revoked: Sequence[tuple[int, datetime.datetime, x509.ReasonFlags | None]] = (),
    *,
    number: int | None = 1,
    delta_base: int | None = None,
    idp: x509.IssuingDistributionPoint | None = None,
    this_update=None,
    next_update=None,
    signer: Party | None = None,
    aki=True,
    extra_extensions=(),
) -> bytes:
    signer = signer or ca
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca.cert.subject)
        .last_update(this_update or NOW - HOUR)
        .next_update(next_update or NOW + DAY)
    )
    if number is not None:
        builder = builder.add_extension(x509.CRLNumber(number), critical=False)
    if aki:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.key.public_key()),
            critical=False,
        )
    if delta_base is not None:
        builder = builder.add_extension(x509.DeltaCRLIndicator(delta_base), critical=True)
    if idp is not None:
        builder = builder.add_extension(idp, critical=True)
    for ext, critical in extra_extensions:
        builder = builder.add_extension(ext, critical=critical)
    for serial, when, reason in revoked:
        entry = x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(when)
        if reason is not None:
            entry = entry.add_extension(x509.CRLReason(reason), critical=False)
        builder = builder.add_revoked_certificate(entry.build())
    return builder.sign(signer.key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + asn1core.encode_length(len(content)) + content


def _generalized(value: datetime.datetime) -> bytes:
    return _tlv(0x18, value.strftime("%Y%m%d%H%M%SZ").encode())


def ocsp_response_multi(signer: Party, singles: list[tuple[bytes, bytes, bytes | None]]) -> bytes:
    """A hand-built response with several SingleResponses, signed by an EC ``signer``.

    cryptography's builder takes one response only, and RFC 9919 sec. 3.2.1 allows several, so
    this one assembles the DER itself. ``singles`` are (CertID DER, CertStatus DER, extra) with the
    thisUpdate and nextUpdate fixed to NOW - 1h and NOW + 1d.
    """
    import hashlib

    from cryptography.hazmat.primitives.asymmetric import ec as _ec

    spki = signer.cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    key_bits = asn1core.decode(spki, der=True)[0].children[1].content()[1:]
    key_hash = hashlib.sha1(key_bits).digest()  # noqa: S324 - the RFC 6960 KeyHash is SHA-1
    responder = _tlv(0xA2, _tlv(0x04, key_hash))
    body = b""
    for cert_id, status, _ in singles:
        body += _tlv(
            0x30,
            cert_id + status + _generalized(NOW - HOUR) + _tlv(0xA0, _generalized(NOW + DAY)),
        )
    tbs = _tlv(0x30, responder + _generalized(NOW - HOUR) + _tlv(0x30, body))
    signature = signer.key.sign(tbs, _ec.ECDSA(hashes.SHA256()))
    algorithm = bytes.fromhex("300a06082a8648ce3d040302")
    basic = _tlv(0x30, tbs + algorithm + _tlv(0x03, b"\x00" + signature))
    response_bytes = _tlv(
        0x30,
        _tlv(0x06, asn1core.encode_oid((1, 3, 6, 1, 5, 5, 7, 48, 1, 1))) + _tlv(0x04, basic),
    )
    return _tlv(0x30, bytes.fromhex("0a0100") + _tlv(0xA0, response_bytes))


GOOD_STATUS = b"\x80\x00"


def revoked_status(when: datetime.datetime) -> bytes:
    return _tlv(0xA1, _generalized(when))
