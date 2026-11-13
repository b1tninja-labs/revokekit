"""generation, echo verification and the missing nonce policy (RFC 9654).

RFC 9654 sec. 2.1 is the rule set this module follows, and it replaces RFC 8954, whose 32 octet
ceiling is gone: a Nonce is 1 to 128 octets, a requester uses at least 32, and a responder
must accept 16 to 32. The functions here are pure: no clock, no I/O, and the only randomness is
the ``rng`` a caller may inject.

RFC 9919 sec. 5 adds the client side of the policy. A client that sent no nonce MUST ignore any
nonce in the response; a client that did send one SHOULD NOT reject a response solely because
the nonce is missing, and falls back to the time checks in ``freshest``.
"""

from __future__ import annotations

import enum
import hmac
import secrets
from typing import TYPE_CHECKING

import asn1core

if TYPE_CHECKING:
    from collections.abc import Callable

__all__ = [
    "MAX_NONCE_LENGTH",
    "MIN_REQUESTER_LENGTH",
    "NONCE_OID",
    "NonceError",
    "NonceVerdict",
    "check",
    "decode_extension",
    "encode_extension",
    "generate",
]

# id-pkix-ocsp-nonce, RFC 9654 sec. 2.1: { id-pkix-ocsp 2 } under id-ad-ocsp.
NONCE_OID = "1.3.6.1.5.5.7.48.1.2"

# Nonce ::= OCTET STRING (SIZE (1..128)), RFC 9654 sec. 2.1.
MAX_NONCE_LENGTH = 128
# "An OCSP requester that implements the extension in this document MUST use a minimum length of
# 32 octets", RFC 9654 sec. 2.1. A responder accepts less (16 and up), a requester does not send it.
MIN_REQUESTER_LENGTH = 32

_NONCE_ARCS = asn1core.parse_oid_string(NONCE_OID)
_SEQUENCE = asn1core.Tag(16, True, asn1core.TagClass.universal)
_OID = asn1core.Tag(6, False, asn1core.TagClass.universal)
_OCTET_STRING = asn1core.Tag(4, False, asn1core.TagClass.universal)
_BOOLEAN = asn1core.Tag(1, False, asn1core.TagClass.universal)


class NonceError(ValueError):
    """A nonce or a Nonce extension that RFC 9654 sec. 2.1 does not allow."""


class NonceVerdict(enum.Enum):
    """What ``check`` decided about the echo of a nonce, and nothing about freshness.

    ``MATCH``: the response echoes the nonce that was sent.
    ``ABSENT_ALLOWED``: no echo, and the caller's policy tolerates that (or none was sent).
    ``ABSENT_REFUSED``: a nonce was sent, none came back, and the caller requires one.
    ``MISMATCH``: a nonce came back that is not the one that was sent.
    ``MALFORMED``: a nonce of 0 octets or more than 128 octets, which no party may send.
    """

    MATCH = "match"
    ABSENT_ALLOWED = "absent_allowed"
    ABSENT_REFUSED = "absent_refused"
    MISMATCH = "mismatch"
    MALFORMED = "malformed"


def generate(
    length: int = MIN_REQUESTER_LENGTH, *, rng: Callable[[int], bytes] | None = None
) -> bytes:
    """Make a request nonce, following RFC 9654 sec. 2.1.

    The length must be from 32 to 128 octets: a requester MUST use at least 32, and a Nonce can
    never exceed 128. The value comes from ``secrets.token_bytes`` unless ``rng`` is given, which
    is for tests and for platforms with their own source; RFC 9654 sec. 2.1 requires it be
    cryptographically strong (RFC 4086), and this function cannot check that of an injected one.
    """
    if isinstance(length, bool) or not isinstance(length, int):
        raise TypeError("length must be an int")
    if length < MIN_REQUESTER_LENGTH:
        raise NonceError(
            f"a requester MUST use at least {MIN_REQUESTER_LENGTH} octets (RFC 9654 sec. 2.1), "
            f"not {length}"
        )
    if length > MAX_NONCE_LENGTH:
        raise NonceError(f"a Nonce is at most {MAX_NONCE_LENGTH} octets (RFC 9654 sec. 2.1)")
    value = (rng or secrets.token_bytes)(length)
    if len(value) != length:
        raise NonceError("the random source returned the wrong number of octets")
    return value


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + asn1core.encode_length(len(content)) + content


def encode_extension(nonce: bytes) -> bytes:
    """DER of ``Extension { id-pkix-ocsp-nonce, OCTET STRING { OCTET STRING nonce } }``.

    Per RFC 9654 sec. 2.1 the extnValue is the encoded Nonce, so the nonce is wrapped twice in
    OCTET STRING: once as the Nonce, once as the extnValue. Any length from 1 to 128 is
    encodable here, because a responder-side test needs the short ones; whether a requester may
    *send* one is ``generate``'s rule.
    """
    if not isinstance(nonce, bytes):
        raise TypeError("nonce must be bytes")
    if not 1 <= len(nonce) <= MAX_NONCE_LENGTH:
        raise NonceError(f"a Nonce is 1 to {MAX_NONCE_LENGTH} octets (RFC 9654 sec. 2.1)")
    oid = _tlv(0x06, asn1core.encode_oid(_NONCE_ARCS))
    inner = _tlv(0x04, nonce)
    return _tlv(0x30, oid + _tlv(0x04, inner))


def decode_extension(der: bytes) -> bytes:
    """Return the nonce inside a DER Nonce extension, or raise ``NonceError``.

    Strict on purpose: the input must be exactly one DER Extension, with the nonce OID, an
    optional ``critical TRUE`` (DER omits ``FALSE``), and an extnValue that is exactly one
    OCTET STRING of 1 to 128 octets. Trailing bytes and a wrong OID are refused.
    """
    try:
        node, end = asn1core.decode(der, der=True)
        if end != len(der):
            raise NonceError("trailing bytes after the Extension")
        if node.tag != _SEQUENCE or len(node.children) not in (2, 3):
            raise NonceError("an Extension is a SEQUENCE of two or three fields")
        oid_node, *middle, value_node = node.children
        if oid_node.tag != _OID or asn1core.decode_oid(oid_node.content()) != _NONCE_ARCS:
            raise NonceError("the extension is not id-pkix-ocsp-nonce")
        if middle and (middle[0].tag != _BOOLEAN or middle[0].content() != b"\xff"):
            raise NonceError("critical, when present, must be TRUE in DER")
        if value_node.tag != _OCTET_STRING:
            raise NonceError("extnValue must be an OCTET STRING")
        wrapped = value_node.content()
        inner, inner_end = asn1core.decode(wrapped, der=True)
        if inner_end != len(wrapped):
            raise NonceError("trailing bytes inside extnValue")
    except asn1core.Asn1Error as error:
        raise NonceError(f"not a DER Nonce extension: {error}") from error
    if inner.tag != _OCTET_STRING:
        raise NonceError("the Nonce must be an OCTET STRING")
    nonce = inner.content()
    if not 1 <= len(nonce) <= MAX_NONCE_LENGTH:
        raise NonceError(f"a Nonce is 1 to {MAX_NONCE_LENGTH} octets (RFC 9654 sec. 2.1)")
    return nonce


def check(
    request_nonce: bytes | None,
    response_nonce: bytes | None,
    *,
    require: bool = False,
) -> NonceVerdict:
    """Compare the nonce sent with the nonce echoed (RFC 9654 sec. 2.1, RFC 9919 sec. 5).

    The decision table:

    * no nonce sent: the response's nonce, whatever it is, is ignored, because RFC 9919 sec. 5
      says a client that sent none MUST ignore one in the response. Verdict ``ABSENT_ALLOWED``.
    * nonce sent, none returned: ``ABSENT_REFUSED`` when ``require`` is true, otherwise
      ``ABSENT_ALLOWED``. RFC 9919 sec. 5 says such a client SHOULD NOT reject solely on this
      and falls back to time, so ``require`` is the caller's policy, not the RFC's.
    * either nonce 0 octets or longer than 128 octets: ``MALFORMED``.
    * nonce sent and a different one returned: ``MISMATCH``.
    * the same nonce: ``MATCH``. The comparison is constant time.

    A ``MATCH`` says only that the response is bound to the request. It does not make the
    response fresh; ``freshest.is_fresh`` is still required (RFC 9919 sec. 5).
    """
    if request_nonce is None:
        return NonceVerdict.ABSENT_ALLOWED
    if not 1 <= len(request_nonce) <= MAX_NONCE_LENGTH:
        return NonceVerdict.MALFORMED
    if response_nonce is None:
        return NonceVerdict.ABSENT_REFUSED if require else NonceVerdict.ABSENT_ALLOWED
    if not 1 <= len(response_nonce) <= MAX_NONCE_LENGTH:
        return NonceVerdict.MALFORMED
    if hmac.compare_digest(request_nonce, response_nonce):
        return NonceVerdict.MATCH
    return NonceVerdict.MISMATCH
