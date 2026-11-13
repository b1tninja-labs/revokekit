"""Parse OCSP responses and verify them: status, CertID matching, signature, authorized signer.

RFC 6960 sec. 4.2 gives the ASN.1 (read as EXPLICIT TAGS, appendix B.1) and RFC 9919 sec. 3.2 the
profile. What is verified is the DER of ``tbsResponseData`` *as it arrived*: ``parse`` keeps that
slice and never re-encodes it (sec. 4.2.1: "computed on the hash of the DER encoding of
ResponseData"). Whether the signer may speak for the CA is RFC 6960 sec. 4.2.2.2, applied by
``authorize_signer``. Signature arithmetic is ``sigwire.verify`` through ``_verify``; the
delegate's own signature, validity and the signature scheme tables are ``pkix``'s.

Nothing here reads a clock or the network: ``at`` is always passed in.
"""

from __future__ import annotations

import datetime
import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

import asn1core
import sigwire.verify as sv
from asn1core import Node, Tag, TagClass

from . import freshest as _freshest
from . import nonce as _nonce
from ._verify import SignatureCheck, verify_signed
from .errors import (
    ResponderNotAuthorized,
    ResponseError,
    ResponseStatusError,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

__all__ = [
    "BasicResponse",
    "CertId",
    "OcspResponse",
    "ResponderId",
    "Signer",
    "SingleResponse",
    "VerifiedResponse",
    "authorize_signer",
    "match",
    "parse",
    "parse_and_verify",
    "parse_certid",
    "verify_signature",
]

ID_PKIX_OCSP_BASIC = (1, 3, 6, 1, 5, 5, 7, 48, 1, 1)
ID_PKIX_OCSP_NONCE = (1, 3, 6, 1, 5, 5, 7, 48, 1, 2)
ID_PKIX_OCSP_NOCHECK = (1, 3, 6, 1, 5, 5, 7, 48, 1, 5)
ID_PKIX_OCSP_EXTENDED_REVOKE = (1, 3, 6, 1, 5, 5, 7, 48, 1, 9)
ID_KP_OCSP_SIGNING = (1, 3, 6, 1, 5, 5, 7, 3, 9)
_EXT_KEY_USAGE = "2.5.29.37"
_NOCHECK_DOTTED = ".".join(str(arc) for arc in ID_PKIX_OCSP_NOCHECK)

#: OCSPResponseStatus (RFC 6960 sec. 4.2.1); 4 is "not used" and is refused.
STATUS_NAMES = {
    0: "successful",
    1: "malformedRequest",
    2: "internalError",
    3: "tryLater",
    5: "sigRequired",
    6: "unauthorized",
}

_HASHES = {
    (1, 3, 14, 3, 2, 26): "sha1",
    (2, 16, 840, 1, 101, 3, 4, 2, 4): "sha224",
    (2, 16, 840, 1, 101, 3, 4, 2, 1): "sha256",
    (2, 16, 840, 1, 101, 3, 4, 2, 2): "sha384",
    (2, 16, 840, 1, 101, 3, 4, 2, 3): "sha512",
}

_SEQUENCE = Tag(16, True, TagClass.universal)
_INTEGER = Tag(2, False, TagClass.universal)
_OID = Tag(6, False, TagClass.universal)
_OCTET_STRING = Tag(4, False, TagClass.universal)
_BIT_STRING = Tag(3, False, TagClass.universal)
_ENUMERATED = Tag(10, False, TagClass.universal)
_GENERALIZED_TIME = Tag(24, False, TagClass.universal)

_EPOCH = datetime.datetime(1970, 1, 1, tzinfo=datetime.UTC)


def _ctx(number: int, constructed: bool) -> Tag:
    return Tag(number, constructed, TagClass.context)


@dataclass(frozen=True, slots=True)
class CertId:
    """CertID (RFC 6960 sec. 4.1.1): which certificate a SingleResponse is about."""

    hash_oid: tuple[int, ...]
    issuer_name_hash: bytes
    issuer_key_hash: bytes
    serial: int
    raw: bytes


@dataclass(frozen=True, slots=True)
class SingleResponse:
    """One SingleResponse. ``status`` is ``good``, ``revoked`` or ``unknown``."""

    cert_id: CertId
    status: Literal["good", "revoked", "unknown"]
    revocation_time: datetime.datetime | None
    revocation_reason: int | None
    this_update: datetime.datetime
    next_update: datetime.datetime | None
    extensions: tuple[asn1core.Extension, ...]

    @property
    def is_non_issued_signal(self) -> bool:
        """The shape RFC 6960 sec. 2.2 requires for "revoked" on a non-issued certificate.

        Reason certificateHold (6) and revocationTime 1970-01-01. It stays ``revoked``: sec. 2.2
        says the point is to make the client reject, so it is never read as good.
        """
        return (
            self.status == "revoked"
            and self.revocation_reason == 6
            and self.revocation_time == _EPOCH
        )


@dataclass(frozen=True, slots=True)
class ResponderId:
    """ResponderID: exactly one of ``by_name`` and ``by_key`` (a SHA-1 KeyHash) is set."""

    by_name: asn1core.Name | None
    by_key: bytes | None


@dataclass(frozen=True, slots=True)
class BasicResponse:
    """BasicOCSPResponse. ``tbs_response_data`` is the signed region, byte for byte."""

    tbs_response_data: bytes
    responder: ResponderId
    produced_at: datetime.datetime
    responses: tuple[SingleResponse, ...]
    extensions: tuple[asn1core.Extension, ...]
    signature_algorithm_raw: bytes
    signature: bytes
    certs: tuple[asn1core.Certificate, ...]

    def extension(self, oid: tuple[int, ...]) -> asn1core.Extension | None:
        for ext in self.extensions:
            if ext.oid == oid:
                return ext
        return None

    @property
    def nonce(self) -> bytes | None:
        """The echoed nonce (RFC 9654 sec. 2.1), or None. A malformed one raises ``NonceError``."""
        ext = self.extension(ID_PKIX_OCSP_NONCE)
        return None if ext is None else _nonce.decode_extension(ext.raw)

    @property
    def extended_revoke(self) -> bool:
        """Whether the responder says it uses the extended revoked definition (sec. 4.4.8)."""
        return self.extension(ID_PKIX_OCSP_EXTENDED_REVOKE) is not None


@dataclass(frozen=True, slots=True)
class OcspResponse:
    """OCSPResponse. ``basic`` is None exactly when ``status`` is not ``successful``."""

    status: int
    response_type: tuple[int, ...] | None
    basic: BasicResponse | None

    @property
    def status_name(self) -> str:
        return STATUS_NAMES[self.status]


def _only_child(node: Node, what: str) -> Node:
    if len(node.children) != 1:
        raise ResponseError(f"{what} wraps exactly one value")
    return node.children[0]


def _time(node: Node, what: str) -> datetime.datetime:
    if node.tag != _GENERALIZED_TIME or node.payload is None:
        raise ResponseError(f"{what} is a GeneralizedTime")
    try:
        return asn1core.check_generalized_time(node.payload)
    except asn1core.Asn1Error as error:
        raise ResponseError(f"{what} is not a valid GeneralizedTime: {error}") from error


def _octets(node: Node, what: str) -> bytes:
    if node.tag != _OCTET_STRING or node.payload is None:
        raise ResponseError(f"{what} is an OCTET STRING")
    return node.payload


def _extensions(slot: Node, what: str) -> tuple[asn1core.Extension, ...]:
    try:
        return asn1core.parse_extensions(_only_child(slot, what))
    except asn1core.Asn1Error as error:
        raise ResponseError(f"{what}: {error}") from error


def parse_certid(source: bytes | Node) -> CertId:
    """Read a CertID from DER (what ``request.certid`` returns) or from a parsed node."""
    if isinstance(source, bytes):
        try:
            node, end = asn1core.decode(source, der=True)
        except asn1core.Asn1Error as error:
            raise ResponseError(f"CertID is not DER: {error}") from error
        if end != len(source):
            raise ResponseError("trailing bytes after the CertID")
    else:
        node = source
    if node.tag != _SEQUENCE or len(node.children) != 4:
        raise ResponseError("CertID is a SEQUENCE of four fields")
    algorithm, name_hash, key_hash, serial = node.children
    if algorithm.tag != _SEQUENCE or not algorithm.children or algorithm.children[0].tag != _OID:
        raise ResponseError("CertID hashAlgorithm is an AlgorithmIdentifier")
    if serial.tag != _INTEGER or serial.payload is None:
        raise ResponseError("CertID serialNumber is an INTEGER")
    try:
        oid = asn1core.decode_oid(algorithm.children[0].content())
        value = asn1core.check_integer(serial.payload)
    except asn1core.Asn1Error as error:
        raise ResponseError(f"CertID: {error}") from error
    return CertId(
        oid,
        _octets(name_hash, "issuerNameHash"),
        _octets(key_hash, "issuerKeyHash"),
        value,
        node.raw,
    )


def _single(node: Node) -> SingleResponse:
    if node.tag != _SEQUENCE or not 3 <= len(node.children) <= 5:
        raise ResponseError("SingleResponse is a SEQUENCE of three to five fields")
    fields = list(node.children)
    cert_id = parse_certid(fields.pop(0))
    status_node = fields.pop(0)
    revocation_time = None
    reason = None
    if status_node.tag == _ctx(0, False) and status_node.payload == b"":
        status: Literal["good", "revoked", "unknown"] = "good"
    elif status_node.tag == _ctx(2, False) and status_node.payload == b"":
        status = "unknown"
    elif status_node.tag == _ctx(1, True):
        status = "revoked"
        parts = status_node.children
        if not 1 <= len(parts) <= 2:
            raise ResponseError("RevokedInfo is a time and an optional reason")
        revocation_time = _time(parts[0], "revocationTime")
        if len(parts) == 2:
            if parts[1].tag != _ctx(0, True):
                raise ResponseError("revocationReason is [0] EXPLICIT")
            enum = _only_child(parts[1], "revocationReason")
            if enum.tag != _ENUMERATED or enum.payload is None:
                raise ResponseError("CRLReason is an ENUMERATED")
            reason = asn1core.check_integer(enum.payload)
    else:
        raise ResponseError(
            f"CertStatus is [0] NULL, [1] RevokedInfo or [2] NULL: {status_node.tag!r}"
        )
    this_update = _time(fields.pop(0), "thisUpdate")
    next_update = None
    extensions: tuple[asn1core.Extension, ...] = ()
    for field in fields:
        if field.tag == _ctx(0, True) and next_update is None and not extensions:
            next_update = _time(_only_child(field, "nextUpdate"), "nextUpdate")
        elif field.tag == _ctx(1, True) and not extensions:
            extensions = _extensions(field, "singleExtensions")
        else:
            raise ResponseError(f"unexpected field in SingleResponse: {field.tag!r}")
    return SingleResponse(
        cert_id, status, revocation_time, reason, this_update, next_update, extensions
    )


def _responder_id(node: Node) -> ResponderId:
    if node.tag == _ctx(1, True):
        try:
            return ResponderId(asn1core.parse_name(_only_child(node, "byName")), None)
        except asn1core.Asn1Error as error:
            raise ResponseError(f"responderID byName: {error}") from error
    if node.tag == _ctx(2, True):
        return ResponderId(None, _octets(_only_child(node, "byKey"), "KeyHash"))
    raise ResponseError(f"ResponderID is [1] byName or [2] byKey, found {node.tag!r}")


def _basic(raw: bytes) -> BasicResponse:
    try:
        node, end = asn1core.decode(raw, der=True)
    except asn1core.Asn1Error as error:
        raise ResponseError(f"BasicOCSPResponse is not DER: {error}") from error
    if end != len(raw):
        raise ResponseError("trailing bytes after the BasicOCSPResponse")
    if node.tag != _SEQUENCE or not 3 <= len(node.children) <= 4:
        raise ResponseError("BasicOCSPResponse is a SEQUENCE of three or four fields")
    tbs, algorithm, signature = node.children[:3]
    if tbs.tag != _SEQUENCE or algorithm.tag != _SEQUENCE or signature.tag != _BIT_STRING:
        raise ResponseError("BasicOCSPResponse is tbsResponseData, an algorithm and a BIT STRING")
    try:
        unused, sig_bytes = asn1core.check_bit_string(signature.payload or b"")
    except asn1core.Asn1Error as error:
        raise ResponseError(f"signature: {error}") from error
    if unused:
        raise ResponseError("a signature is whole octets")

    certs: tuple[asn1core.Certificate, ...] = ()
    if len(node.children) == 4:
        slot = node.children[3]
        if slot.tag != _ctx(0, True):
            raise ResponseError("certs is [0] EXPLICIT")
        sequence = _only_child(slot, "certs")
        if sequence.tag != _SEQUENCE:
            raise ResponseError("certs is a SEQUENCE OF Certificate")
        try:
            certs = tuple(asn1core.parse_certificate(c.raw) for c in sequence.children)
        except asn1core.Asn1Error as error:
            raise ResponseError(f"a certificate in certs is unusable: {error}") from error

    fields = list(tbs.children)
    if fields and fields[0].tag == _ctx(0, True):
        # RFC 6960 sec. 4.2.2.3: the version MUST be v1 (0), which is the DEFAULT, and DER never
        # encodes a DEFAULT value. Any [0] here is therefore either a wrong version or not DER.
        raise ResponseError("ResponseData version is v1, the DEFAULT, and DER omits it")
    if len(fields) < 3:
        raise ResponseError("ResponseData needs a responderID, producedAt and responses")
    responder = _responder_id(fields[0])
    produced_at = _time(fields[1], "producedAt")
    if fields[2].tag != _SEQUENCE:
        raise ResponseError("responses is a SEQUENCE OF SingleResponse")
    responses = tuple(_single(child) for child in fields[2].children)
    extensions: tuple[asn1core.Extension, ...] = ()
    rest = fields[3:]
    if rest:
        if len(rest) != 1 or rest[0].tag != _ctx(1, True):
            raise ResponseError("only [1] responseExtensions may follow responses")
        extensions = _extensions(rest[0], "responseExtensions")
    return BasicResponse(
        tbs.raw, responder, produced_at, responses, extensions, algorithm.raw, sig_bytes, certs
    )


def parse(raw: bytes) -> OcspResponse:
    """Read an OCSPResponse (RFC 6960 sec. 4.2.1, RFC 9919 sec. 3.2.1) without trusting it.

    An error status carries no ``responseBytes`` and a successful one must carry them; either
    breach, a status of 4 ("not used"), or a response type other than id-pkix-ocsp-basic is an
    error here. Nothing is verified: use ``parse_and_verify``.
    """
    try:
        node, end = asn1core.decode(raw, der=True)
    except asn1core.Asn1Error as error:
        raise ResponseError(f"OCSPResponse is not DER: {error}") from error
    if end != len(raw):
        raise ResponseError("trailing bytes after the OCSPResponse")
    if node.tag != _SEQUENCE or not 1 <= len(node.children) <= 2:
        raise ResponseError("OCSPResponse is a SEQUENCE of a status and optional responseBytes")
    status_node = node.children[0]
    if status_node.tag != _ENUMERATED or status_node.payload is None:
        raise ResponseError("responseStatus is an ENUMERATED")
    status = asn1core.check_integer(status_node.payload)
    if status not in STATUS_NAMES:
        raise ResponseError(f"responseStatus {status} is not defined (4 is 'not used')")
    if len(node.children) == 1:
        if status == 0:
            raise ResponseError("a successful response carries responseBytes")
        return OcspResponse(status, None, None)
    if status != 0:
        raise ResponseError(
            f"responseStatus {STATUS_NAMES[status]} must not carry responseBytes "
            "(RFC 6960 sec. 4.2.1)"
        )
    wrapper = node.children[1]
    if wrapper.tag != _ctx(0, True):
        raise ResponseError("responseBytes is [0] EXPLICIT")
    response_bytes = _only_child(wrapper, "responseBytes")
    if response_bytes.tag != _SEQUENCE or len(response_bytes.children) != 2:
        raise ResponseError("ResponseBytes is a SEQUENCE of a type and an OCTET STRING")
    type_node, body = response_bytes.children
    if type_node.tag != _OID or type_node.payload is None:
        raise ResponseError("responseType is an OBJECT IDENTIFIER")
    response_type = asn1core.decode_oid(type_node.payload)
    if response_type != ID_PKIX_OCSP_BASIC:
        raise ResponseError("only id-pkix-ocsp-basic responses are read (RFC 6960 sec. 4.2.1)")
    return OcspResponse(status, response_type, _basic(_octets(body, "response")))


def _key_hash(spki: bytes, digest: str) -> bytes:
    from .request import _key_bits

    return hashlib.new(digest, _key_bits(spki)).digest()


def match(
    basic: BasicResponse, cert: asn1core.Certificate, issuer: asn1core.Certificate
) -> SingleResponse:
    """The SingleResponse for ``cert``, found by comparing *every* CertID in the response.

    RFC 6960 sec. 4.2.2.3 says the response MUST include one for each requested certificate and
    RFC 9919 sec. 3.2.1 allows several (for instance one SHA-1 and one SHA-256 CertID for the same
    certificate), so each is compared on its own hash algorithm, name hash, key hash and serial.
    Raises ``ResponseError`` if none matches, or if matching ones disagree on the status.
    """
    found = []
    for single in basic.responses:
        digest = _HASHES.get(single.cert_id.hash_oid)
        if digest is None or single.cert_id.serial != cert.serial:
            continue
        if single.cert_id.issuer_name_hash != hashlib.new(digest, cert.issuer.raw).digest():
            continue
        if single.cert_id.issuer_key_hash != _key_hash(issuer.subject_public_key_info, digest):
            continue
        found.append(single)
    if not found:
        raise ResponseError("no SingleResponse is about this certificate and issuer")
    if len({s.status for s in found}) > 1:
        raise ResponseError("matching SingleResponses disagree on the certificate status")
    return found[0]


@dataclass(frozen=True, slots=True)
class Signer:
    """The certificate that signed, and why it may."""

    certificate: asn1core.Certificate
    #: ``ca`` (the issuer itself), ``configured`` (a locally trusted responder) or ``delegate``.
    kind: Literal["ca", "configured", "delegate"]
    #: id-pkix-ocsp-nocheck is present, so the delegate's own revocation need not be checked
    #: (RFC 6960 sec. 4.2.2.2.1). False for a delegate means the caller must decide.
    nocheck: bool


def _ocsp_signing(cert: asn1core.Certificate) -> bool:
    ext = cert.extension(_EXT_KEY_USAGE)
    if ext is None:
        return False
    try:
        node, _ = asn1core.decode(ext.value, der=True)
        return any(
            child.tag == _OID and asn1core.decode_oid(child.content()) == ID_KP_OCSP_SIGNING
            for child in node.children
        )
    except asn1core.Asn1Error:
        return False


def _matches_responder(cert: asn1core.Certificate, responder: ResponderId) -> bool:
    if responder.by_key is not None:
        try:
            return _key_hash(cert.subject_public_key_info, "sha1") == responder.by_key
        except ValueError:
            return False
    return responder.by_name is not None and asn1core.names_equal(cert.subject, responder.by_name)


def authorize_signer(
    basic: BasicResponse,
    issuer: asn1core.Certificate,
    *,
    at: datetime.datetime,
    certs: Iterable[asn1core.Certificate] = (),
    configured: Iterable[asn1core.Certificate] = (),
) -> Signer:
    """Find the responder's certificate and decide whether RFC 6960 sec. 4.2.2.2 lets it answer.

    The candidate is whichever of ``issuer``, ``basic.certs`` and ``certs`` matches the ResponderID
    (byKey by SHA-1 of the key bits, byName by name; RFC 9919 sec. 3.2.2). It is accepted when it
    is (1) in ``configured``, (2) the CA's own certificate, or (3) carries id-kp-OCSPSigning, is
    issued directly by the CA (name match and the CA's signature verifying under ``issuer``'s key)
    and is valid at ``at``. "Signed by the same key as the certificate in question" holds by
    construction because ``issuer`` is the key the caller checks the target certificate against.
    Raises ``ResponderNotAuthorized``.
    """
    from pkix import errors as pkix_errors
    from pkix import validity

    pool = [issuer, *basic.certs, *certs]
    candidates = [c for c in pool if _matches_responder(c, basic.responder)]
    if not candidates:
        raise ResponderNotAuthorized("no certificate matches the ResponderID")
    configured_raw = {c.raw for c in configured}
    reasons: list[str] = []
    for cand in candidates:
        if cand.raw in configured_raw:
            return Signer(cand, "configured", False)
        if cand.raw == issuer.raw or (
            cand.subject_public_key_info == issuer.subject_public_key_info
            and asn1core.names_equal(cand.subject, issuer.subject)
        ):
            return Signer(cand, "ca", False)
        if not _ocsp_signing(cand):
            reasons.append("it lacks id-kp-OCSPSigning")
            continue
        if not asn1core.names_equal(cand.issuer, issuer.subject):
            reasons.append("it was not issued by the CA's name")
            continue
        try:
            validity.check_signature(cand, issuer)
        except pkix_errors.PkixError as error:
            reasons.append(f"the CA's signature on it does not verify: {error}")
            continue
        if not validity.check_validity(cand, at).ok:
            reasons.append("it is not valid at the time given")
            continue
        return Signer(cand, "delegate", cand.extension(_NOCHECK_DOTTED) is not None)
    raise ResponderNotAuthorized("the responder is not authorized: " + "; ".join(reasons))


def verify_signature(
    basic: BasicResponse, signer: asn1core.Certificate, *, policy: sv.Policy = sv.DEFAULT
) -> SignatureCheck:
    """Verify the signature over the stored ``tbsResponseData`` under ``signer``'s key.

    Raises ``SignatureInvalid``, ``SignatureUnsupported`` or ``SignaturePolicyRefused``.
    """
    return verify_signed(
        basic.signature_algorithm_raw,
        signer.subject_public_key_info,
        basic.tbs_response_data,
        basic.signature,
        policy=policy,
    )


@dataclass(frozen=True, slots=True)
class VerifiedResponse:
    """A response whose signer, signature and freshness were checked and that is about ``cert``."""

    response: OcspResponse
    single: SingleResponse
    signer: Signer
    signature: SignatureCheck
    freshness: _freshest.Freshness
    nonce: _nonce.NonceVerdict

    @property
    def status(self) -> str:
        return self.single.status


def parse_and_verify(
    raw: bytes,
    cert: asn1core.Certificate,
    issuer: asn1core.Certificate,
    *,
    at: datetime.datetime,
    responder_certs: Iterable[asn1core.Certificate] = (),
    configured_signers: Iterable[asn1core.Certificate] = (),
    request_nonce: bytes | None = None,
    require_nonce: bool = False,
    tolerance: datetime.timedelta = datetime.timedelta(0),
    policy: sv.Policy = sv.DEFAULT,
) -> VerifiedResponse:
    """Parse and verify an OCSP response about ``cert`` (RFC 6960 sec. 4.2, RFC 9919 sec. 3.2).

    In order: an unsuccessful status raises ``ResponseStatusError``; the signer is authorized
    (``authorize_signer``); the signature over the stored ``tbsResponseData`` is verified (RFC 9919
    sec. 3.2.2: clients MUST validate it); the SingleResponse for ``cert`` is found (``match``);
    the nonce is checked when ``request_nonce`` is given (``nonce.check``); and the SingleResponse
    must be fresh at ``at`` (``freshest.is_fresh``; RFC 9919 sec. 5 requires nextUpdate). Any
    failure raises; a returned object means the status in it may be acted on.
    """
    parsed = parse(raw)
    if parsed.basic is None:
        raise ResponseStatusError(f"responder answered {parsed.status_name}", parsed.status)
    basic = parsed.basic
    signer = authorize_signer(
        basic, issuer, at=at, certs=responder_certs, configured=configured_signers
    )
    signature = verify_signature(basic, signer.certificate, policy=policy)
    single = match(basic, cert, issuer)
    try:
        echoed = basic.nonce
    except _nonce.NonceError as error:
        raise ResponseError(f"malformed nonce in the response: {error}") from error
    verdict = _nonce.check(request_nonce, echoed, require=require_nonce)
    if verdict in (
        _nonce.NonceVerdict.MISMATCH,
        _nonce.NonceVerdict.MALFORMED,
        _nonce.NonceVerdict.ABSENT_REFUSED,
    ):
        raise ResponseError(f"nonce check failed: {verdict.value}")
    fresh = _freshest.is_fresh(single.this_update, single.next_update, now=at, tolerance=tolerance)
    if not fresh:
        raise ResponseError(f"the response is not fresh: {fresh.reason.value}")
    return VerifiedResponse(parsed, single, signer, signature, fresh, verdict)
