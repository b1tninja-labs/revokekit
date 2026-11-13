"""build requests (RFC 6960, RFC 9919): one unsigned request, SHA-256 CertID, optional nonce.

What is built is the profile of RFC 9919 sec. 3.1.1, not every request RFC 6960 sec. 4.1.1
allows: one Request in the requestList, no requestorName, no optionalSignature (RFC 9919
sec. 3.1.2 says clients SHOULD NOT sign), no singleRequestExtensions (MUST NOT), and a
requestExtensions that holds nothing but a nonce when a nonce is asked for. Signing and batches
are not offered; see the non-goals in README.md.

DER is assembled by hand with a private ``_tlv`` because asn1core has no builder yet; the lengths
come from ``asn1core.encode_length`` and the OIDs from ``asn1core.encode_oid``. The row in
ROADMAP.md that swaps this for the builder is the place to remove it.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, Literal

import asn1core

from . import nonce as _nonce

if TYPE_CHECKING:
    from typing import Any

    Certificate = Any  # DER bytes or an asn1core.Certificate

__all__ = [
    "RequestError",
    "build",
    "certid",
]

type HashName = Literal["sha256", "sha1"]

# id-sha256 and id-sha1. RFC 9919 sec. 3.1.1 requires SHA-256 and tolerates SHA-1 only for
# clients still compatible with RFC 5019. The AlgorithmIdentifier carries a NULL parameter, as
# the published example in RFC 9919 appendix B.4 does.
_HASHES: dict[str, tuple[tuple[int, ...], str]] = {
    "sha256": ((2, 16, 840, 1, 101, 3, 4, 2, 1), "sha256"),
    "sha1": ((1, 3, 14, 3, 2, 26), "sha1"),
}


class RequestError(ValueError):
    """A request that RFC 6960 or RFC 9919 would not let a client send."""


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + asn1core.encode_length(len(content)) + content


def _integer(value: int) -> bytes:
    """DER INTEGER, minimal two's complement. Zero and negatives are encoded, not refused.

    RFC 5280 sec. 4.1.2.2 says serial numbers MUST be positive, and in the same section that
    non-conforming CAs issue zero and negative ones and that certificate users SHOULD handle them
    gracefully. A request about such a certificate is still a request about that certificate.
    """
    magnitude = value if value >= 0 else ~value
    length = (magnitude.bit_length() + 8) // 8
    return _tlv(0x02, value.to_bytes(length, "big", signed=True))


def _certificate(value: Certificate, role: str) -> asn1core.Certificate:
    if isinstance(value, asn1core.Certificate):
        return value
    if isinstance(value, bytes):
        try:
            return asn1core.parse_certificate(value)
        except asn1core.Asn1Error as error:
            raise RequestError(f"{role} is not a DER certificate: {error}") from error
    raise TypeError(f"{role} must be DER bytes or an asn1core.Certificate")


def _key_bits(spki: bytes) -> bytes:
    """The subjectPublicKey value: no tag, no length, and no unused-bits octet.

    RFC 6960 sec. 4.1.1 says the hash is over "the value (excluding tag and length) of the subject
    public key field". The unused-bits octet is part of a BIT STRING's value, and the sentence
    alone does not say whether it is hashed. Verified errata 6165-6167 to RFC 6960 settle the
    parallel KeyHash of ResponderID as excluding it, and the RFC 9919 appendix B.4 example is
    reproduced byte for byte only that way (tests/test_request.py).
    """
    try:
        node, _ = asn1core.decode(spki, der=True)
        key = node.children[1]
        unused, bits = asn1core.check_bit_string(key.content())
    except (asn1core.Asn1Error, IndexError) as error:
        raise RequestError(f"issuer subjectPublicKeyInfo is not usable: {error}") from error
    if unused:
        raise RequestError("a public key BIT STRING does not end on an octet boundary")
    return bits


def certid(cert: Certificate, issuer: Certificate, *, hash_name: HashName = "sha256") -> bytes:
    """DER ``CertID`` for ``cert`` as issued by ``issuer`` (RFC 6960 sec. 4.1.1).

    issuerNameHash is the hash of the DER of the *issuer field of ``cert``*, which is
    checked to be the same name as ``issuer``'s subject; issuerKeyHash is the hash of the
    value of ``issuer``'s subjectPublicKey; serialNumber is ``cert``'s. ``hash_name`` is
    ``"sha256"`` (RFC 9919 sec. 3.1.1: MUST) or, only when named explicitly, ``"sha1"``.
    """
    if hash_name not in _HASHES:
        raise RequestError(f"hash_name must be 'sha256' or 'sha1', not {hash_name!r}")
    target = _certificate(cert, "cert")
    parent = _certificate(issuer, "issuer")
    if not asn1core.names_equal(target.issuer, parent.subject):
        raise RequestError("the certificate's issuer is not the given issuer's subject")
    oid, digest = _HASHES[hash_name]
    algorithm = _tlv(0x30, _tlv(0x06, asn1core.encode_oid(oid)) + b"\x05\x00")
    return _tlv(
        0x30,
        algorithm
        + _tlv(0x04, hashlib.new(digest, target.issuer.raw).digest())
        + _tlv(0x04, hashlib.new(digest, _key_bits(parent.subject_public_key_info)).digest())
        + _integer(target.serial),
    )


def build(
    cert: Certificate,
    issuer: Certificate,
    nonce: bytes | None = None,
    *,
    hash_name: HashName = "sha256",
) -> bytes:
    """DER ``OCSPRequest`` for one certificate (RFC 6960 sec. 4.1.1, RFC 9919 sec. 3.1.1).

    ``cert`` and ``issuer`` are DER bytes or ``asn1core.Certificate``. The request has one
    Request, SHA-256 CertID unless ``hash_name="sha1"`` is passed, and the nonce extension only
    when ``nonce`` is given, as RFC 9919 sec. 3.1.1 recommends nothing else in requestExtensions.
    A nonce must be 32 to 128 octets (RFC 9654 sec. 2.1); use ``nonce.generate``.
    """
    reqcert = certid(cert, issuer, hash_name=hash_name)
    request_list = _tlv(0x30, _tlv(0x30, reqcert))
    tbs = request_list
    if nonce is not None:
        if len(nonce) < _nonce.MIN_REQUESTER_LENGTH:
            raise _nonce.NonceError(
                f"a requester MUST use at least {_nonce.MIN_REQUESTER_LENGTH} octets "
                "(RFC 9654 sec. 2.1)"
            )
        extensions = _tlv(0x30, _nonce.encode_extension(nonce))
        tbs += _tlv(0xA2, extensions)
    return _tlv(0x30, _tlv(0x30, tbs))
