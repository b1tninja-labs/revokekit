"""CRL verification, delta CRLs and the certificate-side rules (RFC 5280 sec. 5 and 6.3).

``parse_and_verify`` reads a CRL with asn1core and verifies the signature over the stored
``tbsCertList`` through ``sigwire.verify`` (sec. 6.3.3 step (g)), after the issuer checks of steps
(b) and (f): the CRL issuer name must be the certificate issuer's subject, and the issuer
certificate must carry keyUsage with cRLSign (RFC 10007, which replaces the original step (f)).
``status_of`` combines a complete CRL and an optional delta CRL by RFC 5280 sec. 5.2.4 and 6.3.3
steps (i) to (k).

What is refused rather than guessed, each with a ROADMAP row: indirect CRLs, ``onlySomeReasons``,
and any critical extension this module does not process (sec. 5.2: "MUST NOT use that CRL").

``fetch`` is still a placeholder: it needs the bounded HTTP client (row ``crl.fetch()``).
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

import asn1core
import sigwire.verify as sv
from asn1core import Tag, TagClass

from ._verify import SignatureCheck, verify_signed
from .errors import CrlError, NoRevAvailViolation

if TYPE_CHECKING:
    from typing import Any

    DistributionPoint = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "CrlStatus",
    "IssuingDistributionPoint",
    "VerifiedCrl",
    "check_issuer_key_usage",
    "fetch",
    "norevavail_problems",
    "parse_and_verify",
    "revocation_required",
    "status_of",
]

_CRL_NUMBER = (2, 5, 29, 20)
_DELTA_CRL_INDICATOR = (2, 5, 29, 27)
_ISSUING_DISTRIBUTION_POINT = (2, 5, 29, 28)
_AUTHORITY_KEY_ID = (2, 5, 29, 35)
_ISSUER_ALT_NAME = (2, 5, 29, 18)
_FRESHEST_CRL = (2, 5, 29, 46)
_KNOWN_CRL_EXTENSIONS = frozenset(
    {_CRL_NUMBER, _DELTA_CRL_INDICATOR, _ISSUING_DISTRIBUTION_POINT, _AUTHORITY_KEY_ID}
    | {_ISSUER_ALT_NAME, _FRESHEST_CRL}
)
# Critical ones among these that the module acts on: the delta indicator and the IDP.
_ACTED_ON_CRITICAL = frozenset({_DELTA_CRL_INDICATOR, _ISSUING_DISTRIBUTION_POINT})
_ENTRY_REASON = (2, 5, 29, 21)
_ENTRY_INVALIDITY_DATE = (2, 5, 29, 24)
_ENTRY_KNOWN = frozenset({_ENTRY_REASON, _ENTRY_INVALIDITY_DATE})

_KEY_USAGE = "2.5.29.15"
_BASIC_CONSTRAINTS = "2.5.29.19"
_CRL_DISTRIBUTION_POINTS = "2.5.29.31"
_FRESHEST_CRL_DOTTED = "2.5.29.46"
_AUTHORITY_INFO_ACCESS = "1.3.6.1.5.5.7.1.1"
_NO_REV_AVAIL = "2.5.29.56"
_OCSP_NOCHECK = "1.3.6.1.5.5.7.48.1.5"
_ID_AD_OCSP = (1, 3, 6, 1, 5, 5, 7, 48, 1)
_CRL_SIGN_BIT = 6  # KeyUsage ::= BIT STRING { ..., cRLSign (6), ... } (RFC 5280 sec. 4.2.1.3)
_VERSION_V3 = 2  # asn1core reports the encoded number: v3 is 2
_MAX_CRL_NUMBER_OCTETS = 20  # RFC 5280 sec. 5.2.3

_SEQUENCE = Tag(16, True, TagClass.universal)
_INTEGER = Tag(2, False, TagClass.universal)
_OID = Tag(6, False, TagClass.universal)
_BIT_STRING = Tag(3, False, TagClass.universal)
_BOOLEAN = Tag(1, False, TagClass.universal)


def _ctx(number: int, constructed: bool) -> Tag:
    return Tag(number, constructed, TagClass.context)


# -- certificate-side rules ----------------------------------------------------------------------


def check_issuer_key_usage(cert: asn1core.Certificate) -> None:
    """RFC 10007 sec. 4, the replacement for step (f) of RFC 5280 sec. 6.3.3.

    "If the version of the CRL issuer's certificate is version 3 (v3), then verify that the key
    usage extension is present and verify that the cRLSign bit is set." A v1 or v2 certificate has
    no extensions field and is not checked. Raises ``CrlError``.
    """
    if cert.version != _VERSION_V3:
        return
    ext = cert.extension(_KEY_USAGE)
    if ext is None:
        raise CrlError(
            "the CRL issuer's v3 certificate has no keyUsage extension (RFC 10007 sec. 4)"
        )
    try:
        node, end = asn1core.decode(ext.value, der=True)
        if end != len(ext.value) or node.tag != _BIT_STRING or node.payload is None:
            raise CrlError("keyUsage is not a single BIT STRING")
        _unused, bits = asn1core.check_bit_string(node.payload)
    except asn1core.Asn1Error as error:
        raise CrlError(f"keyUsage is not DER: {error}") from error
    # X.690 sec. 11.2.2: trailing zero bits are removed, so a short string means "not set".
    index, mask = divmod(_CRL_SIGN_BIT, 8)
    set_ = index < len(bits) and bool(bits[index] & (0x80 >> mask))
    if not set_:
        raise CrlError("the CRL issuer's keyUsage does not assert cRLSign (RFC 10007 sec. 4)")


def norevavail_problems(cert: asn1core.Certificate) -> list[str]:
    """What RFC 9608 sec. 3 forbids next to noRevAvail; empty when the extension is absent or fine.

    A certificate with noRevAvail MUST NOT be a CA (basicConstraints cA TRUE), MUST NOT carry CRL
    Distribution Points or Freshest CRL, and its Authority Information Access MUST NOT hold an
    id-ad-ocsp method; "the relying party MUST consider the certificate invalid" otherwise. The
    value must be NULL (sec. 2: '0500'H). Criticality is a CA obligation (sec. 2) and is not a
    relying-party invalidity condition, so it is not reported.
    """
    ext = cert.extension(_NO_REV_AVAIL)
    if ext is None:
        return []
    problems: list[str] = []
    if ext.value != b"\x05\x00":
        problems.append("the noRevAvail value is not NULL")
    if _is_ca(cert):
        problems.append("noRevAvail on a certificate with basicConstraints cA TRUE")
    if cert.extension(_CRL_DISTRIBUTION_POINTS) is not None:
        problems.append("noRevAvail with CRL Distribution Points")
    if cert.extension(_FRESHEST_CRL_DOTTED) is not None:
        problems.append("noRevAvail with Freshest CRL")
    if _has_ocsp_access(cert):
        problems.append("noRevAvail with an id-ad-ocsp access method")
    return problems


def _is_ca(cert: asn1core.Certificate) -> bool:
    ext = cert.extension(_BASIC_CONSTRAINTS)
    if ext is None:
        return False
    try:
        node, _ = asn1core.decode(ext.value, der=True)
    except asn1core.Asn1Error:
        return False
    return (
        bool(node.children)
        and node.children[0].tag == _BOOLEAN
        and node.children[0].payload == b"\xff"
    )


def _has_ocsp_access(cert: asn1core.Certificate) -> bool:
    ext = cert.extension(_AUTHORITY_INFO_ACCESS)
    if ext is None:
        return False
    try:
        node, _ = asn1core.decode(ext.value, der=True)
        return any(
            description.children
            and description.children[0].tag == _OID
            and asn1core.decode_oid(description.children[0].content()) == _ID_AD_OCSP
            for description in node.children
        )
    except asn1core.Asn1Error:
        return False


def revocation_required(cert: asn1core.Certificate) -> bool:
    """Whether revocation status must be determined for ``cert`` (RFC 9608 sec. 4).

    False when noRevAvail or id-pkix-ocsp-nocheck is present: "Step (a)(3) is skipped". True
    otherwise. A certificate that breaks the sec. 3 rules is invalid, which raises
    ``NoRevAvailViolation`` instead of answering.
    """
    problems = norevavail_problems(cert)
    if problems:
        raise NoRevAvailViolation("; ".join(problems) + " (RFC 9608 sec. 3)")
    return cert.extension(_NO_REV_AVAIL) is None and cert.extension(_OCSP_NOCHECK) is None


# -- CRLs ----------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class IssuingDistributionPoint:
    """IssuingDistributionPoint (RFC 5280 sec. 5.2.5). ``names`` are the raw fullName GeneralNames."""

    raw: bytes
    names: frozenset[bytes]
    has_relative_name: bool
    only_user_certs: bool
    only_ca_certs: bool
    only_some_reasons: bool
    indirect: bool
    only_attribute_certs: bool


@dataclass(frozen=True, slots=True)
class VerifiedCrl:
    """A CRL whose issuer, key usage and signature were checked."""

    crl: asn1core.Crl
    signature: SignatureCheck
    number: int | None
    #: BaseCRLNumber of a delta CRL; None for a complete CRL.
    base_number: int | None
    idp: IssuingDistributionPoint | None
    authority_key_id: bytes | None

    @property
    def is_delta(self) -> bool:
        return self.base_number is not None


def _integer_extension(ext: asn1core.Extension, what: str) -> int:
    try:
        node, end = asn1core.decode(ext.value, der=True)
        if end != len(ext.value) or node.tag != _INTEGER or node.payload is None:
            raise CrlError(f"{what} is not a single INTEGER")
        value = asn1core.check_integer(node.payload)
    except asn1core.Asn1Error as error:
        raise CrlError(f"{what} is not DER: {error}") from error
    if value < 0 or len(node.payload) > _MAX_CRL_NUMBER_OCTETS + 1:
        raise CrlError(f"{what} is outside 0..2^160 (RFC 5280 sec. 5.2.3)")
    return value


def _flag(node: asn1core.Node) -> bool:
    if node.payload not in (b"\xff", b"\x00"):
        raise CrlError("a BOOLEAN in the issuing distribution point is not DER")
    return node.payload == b"\xff"


def _idp(ext: asn1core.Extension) -> IssuingDistributionPoint:
    try:
        node, end = asn1core.decode(ext.value, der=True)
    except asn1core.Asn1Error as error:
        raise CrlError(f"issuingDistributionPoint is not DER: {error}") from error
    if end != len(ext.value) or node.tag != _SEQUENCE:
        raise CrlError("issuingDistributionPoint is a SEQUENCE")
    names: frozenset[bytes] = frozenset()
    relative = False
    flags = {1: False, 2: False, 3: False, 4: False, 5: False}
    last = -1
    for field in node.children:
        number = field.tag.number
        if field.tag.tag_class != TagClass.context or number <= last or number > 5:
            raise CrlError("issuingDistributionPoint fields are out of order or unknown")
        last = number
        if number == 0:
            # DistributionPointName is a CHOICE, so [0] is EXPLICIT: it wraps [0] fullName or [1] rdn.
            if len(field.children) != 1:
                raise CrlError("distributionPoint wraps one DistributionPointName")
            choice = field.children[0]
            if choice.tag == _ctx(0, True):
                names = frozenset(child.raw for child in choice.children)
            elif choice.tag == _ctx(1, True):
                relative = True
            else:
                raise CrlError(
                    "DistributionPointName is [0] fullName or [1] nameRelativeToCRLIssuer"
                )
        elif number == 3:
            flags[3] = True
        else:
            flags[number] = _flag(field)
    return IssuingDistributionPoint(
        ext.value, names, relative, flags[1], flags[2], flags[3], flags[4], flags[5]
    )


def _inner_signature_algorithm(crl: asn1core.Crl) -> bytes:
    """tbsCertList.signature (RFC 5280 sec. 5.1.2.2), which MUST equal signatureAlgorithm (5.1.1.2)."""
    try:
        tbs, _ = asn1core.decode(crl.tbs_cert_list, der=True)
    except asn1core.Asn1Error as exc:
        raise CrlError(f"tbsCertList is not DER: {exc}") from exc
    fields = list(tbs.children)
    if fields and fields[0].tag.is_universal() and fields[0].tag.number == 2:
        fields.pop(0)  # version, present only in a v2 CRL
    if not fields:
        raise CrlError("tbsCertList has no signature field")
    return fields[0].raw


def parse_and_verify(
    raw: bytes,
    issuer: asn1core.Certificate,
    *,
    at: datetime.datetime,
    policy: sv.Policy = sv.DEFAULT,
) -> VerifiedCrl:
    """Read a CRL and verify it as issued by ``issuer`` (RFC 5280 sec. 6.3.3 steps (b), (f), (g)).

    Order: the CRL's issuer name equals ``issuer``'s subject; ``issuer`` asserts cRLSign (RFC 10007
    ``check_issuer_key_usage``); the outer signatureAlgorithm equals the inner (sec. 5.1.1.2); no
    critical extension is left unprocessed (sec. 5.2); the signature over the stored
    ``tbsCertList`` verifies; and ``at`` is not before thisUpdate or after nextUpdate (sec. 6.3.3
    step (a)(1): a current time past nextUpdate means fetch a newer one). Raises ``CrlError`` or
    a ``Signature*`` error. Path validation of ``issuer`` is the caller's (``pkix``).
    """
    try:
        crl = asn1core.parse_crl(raw)
    except asn1core.Asn1Error as error:
        raise CrlError(f"not a usable CRL: {error}") from error
    if not asn1core.names_equal(crl.issuer, issuer.subject):
        raise CrlError("the CRL issuer is not the issuer certificate's subject (step (b)(1))")
    check_issuer_key_usage(issuer)

    tbs, _ = asn1core.decode(crl.tbs_cert_list, der=True)
    fields = list(tbs.children)
    if fields and fields[0].tag == _INTEGER:
        fields.pop(0)
    if fields[0].raw != crl.signature_algorithm_raw:
        raise CrlError(
            "signatureAlgorithm differs from tbsCertList.signature (RFC 5280 sec. 5.1.1.2)"
        )

    for ext in crl.extensions:
        if ext.critical and ext.oid not in _ACTED_ON_CRITICAL:
            raise CrlError(
                f"unprocessed critical CRL extension {ext.dotted_oid} (RFC 5280 sec. 5.2)"
            )
    for entry in crl.revoked:
        for ext in entry.extensions:
            if ext.critical and ext.oid not in _ENTRY_KNOWN:
                raise CrlError(
                    f"unprocessed critical entry extension {ext.dotted_oid} (RFC 5280 sec. 5.3)"
                )

    by_oid = {ext.oid: ext for ext in crl.extensions}
    number = _integer_extension(by_oid[_CRL_NUMBER], "cRLNumber") if _CRL_NUMBER in by_oid else None
    base = None
    if _DELTA_CRL_INDICATOR in by_oid:
        delta = by_oid[_DELTA_CRL_INDICATOR]
        if not delta.critical:
            raise CrlError("the delta CRL indicator MUST be critical (RFC 5280 sec. 5.2.4)")
        base = _integer_extension(delta, "deltaCRLIndicator")
        if number is None or base >= number:
            raise CrlError("a delta CRL needs a cRLNumber above its BaseCRLNumber")
    idp = (
        _idp(by_oid[_ISSUING_DISTRIBUTION_POINT]) if _ISSUING_DISTRIBUTION_POINT in by_oid else None
    )
    aki = by_oid[_AUTHORITY_KEY_ID].value if _AUTHORITY_KEY_ID in by_oid else None

    signature = verify_signed(
        crl.signature_algorithm_raw,
        issuer.subject_public_key_info,
        crl.tbs_cert_list,
        crl.signature_value,
        policy=policy,
        inner_algorithm_raw=_inner_signature_algorithm(crl),
        what="CRL",
    )
    if crl.this_update > at:
        raise CrlError("the CRL's thisUpdate is in the future")
    if crl.next_update is not None and at > crl.next_update:
        raise CrlError("the CRL is past its nextUpdate; fetch a current one (step (a)(1))")
    return VerifiedCrl(crl, signature, number, base, idp, aki)


def _scope_check(
    crl: VerifiedCrl, cert: asn1core.Certificate, dp_names: frozenset[bytes] | None
) -> None:
    """Steps (b)(2)(i) to (iv) for the IDP, plus the refusals this module makes."""
    idp = crl.idp
    if idp is None:
        return
    if idp.indirect:
        raise CrlError("indirect CRLs are not supported yet (ROADMAP rk.crl-indirect)")
    if idp.only_some_reasons:
        raise CrlError("onlySomeReasons CRLs are not supported yet (ROADMAP rk.crl-reasons)")
    if idp.only_attribute_certs:
        raise CrlError("onlyContainsAttributeCerts is asserted (step (b)(2)(iv))")
    is_ca = _is_ca(cert)
    if idp.only_user_certs and is_ca:
        raise CrlError("the CRL covers only user certificates and this is a CA (step (b)(2)(ii))")
    if idp.only_ca_certs and not is_ca:
        raise CrlError("the CRL covers only CA certificates and this is not one (step (b)(2)(iii))")
    if idp.has_relative_name:
        raise CrlError("nameRelativeToCRLIssuer distribution points are not supported yet")
    if idp.names and (dp_names is None or not (idp.names & dp_names)):
        raise CrlError(
            "no name in the CRL's distribution point matches the certificate's (step (b)(2)(i))"
        )


def _crldp_names(cert: asn1core.Certificate) -> frozenset[bytes] | None:
    """The raw fullName GeneralNames of every DistributionPoint in the certificate, or None."""
    ext = cert.extension(_CRL_DISTRIBUTION_POINTS)
    if ext is None:
        return None
    try:
        node, _ = asn1core.decode(ext.value, der=True)
    except asn1core.Asn1Error:
        return None
    names: set[bytes] = set()
    for point in node.children:
        for field in point.children:
            if (
                field.tag == _ctx(0, True)
                and field.children
                and field.children[0].tag == _ctx(0, True)
            ):
                names.update(child.raw for child in field.children[0].children)
    return frozenset(names)


@dataclass(frozen=True, slots=True)
class CrlStatus:
    """The answer of RFC 5280 sec. 6.3.3 for one certificate. ``good`` means not on the CRL."""

    state: Literal["good", "revoked"]
    reason: int | None
    revocation_date: datetime.datetime | None
    #: The entry came from the delta CRL.
    from_delta: bool
    #: Revoked with reason certificateHold (6): a temporary state.
    on_hold: bool


def _can_combine(complete: VerifiedCrl, delta: VerifiedCrl) -> None:
    """RFC 5280 sec. 5.2.4 conditions (a) to (d), with the key and AKI of sec. 6.3.3 (c)."""
    if complete.is_delta:
        raise CrlError("the complete CRL carries a delta CRL indicator")
    if not delta.is_delta:
        raise CrlError("the delta CRL has no delta CRL indicator")
    base = delta.base_number
    if base is None:  # unreachable after is_delta; keeps the type checker and python -O honest
        raise CrlError("the delta CRL has no delta CRL indicator")
    if not asn1core.names_equal(complete.crl.issuer, delta.crl.issuer):
        raise CrlError("the delta and complete CRLs have different issuers (sec. 5.2.4 (a))")
    if (complete.idp is None) != (delta.idp is None) or (
        complete.idp is not None and delta.idp is not None and complete.idp.raw != delta.idp.raw
    ):
        raise CrlError("the delta and complete CRLs differ in scope (sec. 5.2.4 (b))")
    if complete.authority_key_id != delta.authority_key_id:
        raise CrlError(
            "the delta and complete CRLs differ in authority key identifier (sec. 6.3.3 (c)(3))"
        )
    if complete.number is None or delta.number is None:
        raise CrlError("combining needs both cRLNumbers")
    if complete.number < base:
        raise CrlError("the complete CRL is older than the delta's base (sec. 5.2.4 (c))")
    if complete.number >= delta.number:
        raise CrlError("the delta CRL does not follow the complete CRL (sec. 5.2.4 (d))")


def status_of(
    cert: asn1core.Certificate,
    complete: VerifiedCrl,
    delta: VerifiedCrl | None = None,
    *,
    at: datetime.datetime,
) -> CrlStatus:
    """Revocation status of ``cert`` from a complete CRL and, optionally, its delta CRL.

    RFC 5280 sec. 6.3.3: the delta is searched first (step (i)), then the complete CRL if the
    certificate was not found there (step (j)); a ``removeFromCRL`` entry means unrevoked (step
    (k)). The delta must be current at ``at`` (sec. 5.2.4: between thisUpdate and nextUpdate) and
    combinable with the complete CRL. ``cert`` must be issued by the CRL's issuer, and the IDP
    scope is checked against it. Raises ``CrlError``; a CRL that cannot establish the status never
    returns ``good``.
    """
    if complete.is_delta:
        raise CrlError("status_of needs a complete CRL first; a delta CRL cannot stand alone")
    if not asn1core.names_equal(cert.issuer, complete.crl.issuer):
        raise CrlError(
            "the certificate was not issued by the CRL issuer (indirect CRLs unsupported)"
        )
    dp_names = _crldp_names(cert)
    _scope_check(complete, cert, dp_names)
    if delta is not None:
        _can_combine(complete, delta)
        _scope_check(delta, cert, dp_names)
        if not (
            delta.crl.this_update <= at
            and (delta.crl.next_update is None or at <= delta.crl.next_update)
        ):
            raise CrlError("the delta CRL is not current (sec. 5.2.4)")
    sources: list[tuple[VerifiedCrl, bool]] = [(complete, False)]
    if delta is not None:
        sources.insert(0, (delta, True))
    for source, is_delta in sources:
        entry = source.crl.revoked_by_serial(cert.serial)
        if entry is None:
            continue
        reason = entry.reason if entry.reason is not None else 0
        if reason == 8:  # removeFromCRL: step (k) turns it back into UNREVOKED
            return CrlStatus("good", None, None, is_delta, False)
        return CrlStatus("revoked", reason, entry.revocation_date, is_delta, reason == 6)
    return CrlStatus("good", None, None, False, False)


async def fetch(distribution_point: DistributionPoint, reason: int | None) -> Any:
    """Pending behaviour defined by RFC 5280 sec. 4.2.1.13.

    Not implemented yet. See the ``crl.fetch()`` row in ROADMAP.md; this stub raises on
    purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("fetch() is not implemented: RFC 5280 sec. 4.2.1.13")
