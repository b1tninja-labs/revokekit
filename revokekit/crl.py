"""CRL verification, delta CRLs and the certificate-side rules (RFC 5280 sec. 5 and 6.3).

``parse_and_verify`` reads a CRL with asn1core and verifies the signature over the stored
``tbsCertList`` through ``sigwire.verify`` (sec. 6.3.3 step (g)), after the issuer checks of steps
(b) and (f): the CRL issuer name must be the certificate issuer's subject, and the issuer
certificate must carry keyUsage with cRLSign (RFC 10007, which replaces the original step (f)).
``status_of`` hands the verified CRLs to ``pkix.revocation.CrlChecker``, which implements RFC 5280
sec. 6.3.3 (IDP scope, reasons masks, indirect CRLs, delta CRLs); revokekit keeps the fetching,
caching and freshness around it. Any critical extension this module does not process makes the CRL
unusable (sec. 5.2: "MUST NOT use that CRL").

``fetch`` is still a placeholder: it needs the bounded HTTP client (row ``crl.fetch()``).
"""

from __future__ import annotations

import datetime
from collections.abc import Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

import asn1core
import asn1core.extensions
import pkix.revocation
import sigwire.verify as sv
from asn1core import Tag, TagClass

from ._verify import SignatureCheck, verify_signed
from .errors import CrlError, NoRevAvailViolation

if TYPE_CHECKING:
    from typing import Any

    from pkix.anchors import TrustAnchor

    DistributionPoint = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "CrlStatus",
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
_ENTRY_CERTIFICATE_ISSUER = (2, 5, 29, 29)  # sec. 5.3.3, read by pkix
_ENTRY_KNOWN = frozenset({_ENTRY_REASON, _ENTRY_INVALIDITY_DATE, _ENTRY_CERTIFICATE_ISSUER})

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

_INTEGER = Tag(2, False, TagClass.universal)
_OID = Tag(6, False, TagClass.universal)
_BIT_STRING = Tag(3, False, TagClass.universal)
_BOOLEAN = Tag(1, False, TagClass.universal)


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
class VerifiedCrl:
    """A CRL whose issuer, key usage and signature were checked."""

    crl: asn1core.Crl
    signature: SignatureCheck
    number: int | None
    #: BaseCRLNumber of a delta CRL; None for a complete CRL.
    base_number: int | None
    idp: asn1core.extensions.IssuingDistributionPoint | None
    authority_key_id: bytes | None
    #: The certificate whose key verified the signature.
    issuer: asn1core.Certificate

    @property
    def is_delta(self) -> bool:
        return self.base_number is not None


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
    # One DER reader: asn1core decodes the three extensions. It refuses an encoded DEFAULT FALSE in
    # the IDP (X.690 sec. 11.5) and accepts a CRLNumber of any length: the 20-octet ceiling of
    # RFC 5280 sec. 5.2.3 binds issuers ("MUST NOT use ... more than 20 octets"), not verifiers.
    try:
        number = (
            asn1core.extensions.parse_crl_number(by_oid[_CRL_NUMBER].value)
            if _CRL_NUMBER in by_oid
            else None
        )
        base = None
        if _DELTA_CRL_INDICATOR in by_oid:
            delta = by_oid[_DELTA_CRL_INDICATOR]
            if not delta.critical:
                raise CrlError("the delta CRL indicator MUST be critical (RFC 5280 sec. 5.2.4)")
            base = asn1core.extensions.parse_delta_crl_indicator(delta.value)
            if number is None or base >= number:
                raise CrlError("a delta CRL needs a cRLNumber above its BaseCRLNumber")
        idp = (
            asn1core.extensions.parse_issuing_distribution_point(
                by_oid[_ISSUING_DISTRIBUTION_POINT].value
            )
            if _ISSUING_DISTRIBUTION_POINT in by_oid
            else None
        )
    except asn1core.extensions.ExtensionError as error:
        raise CrlError(f"malformed CRL extension: {error}") from error
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
    return VerifiedCrl(crl, signature, number, base, idp, aki, issuer)


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
    #: pkix's answer, which is the decision; the fields above are read back for convenience.
    answer: pkix.revocation.RevocationAnswer | None = None


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
    issuer: asn1core.Certificate | None = None,
    certificates: Iterable[asn1core.Certificate] = (),
    anchor: TrustAnchor | None = None,
    more_crls: Iterable[bytes | asn1core.Crl] = (),
    policy: sv.Policy = sv.DEFAULT,
) -> CrlStatus:
    """Revocation status of ``cert`` from a complete CRL and, optionally, its delta CRL.

    The decision is ``pkix.revocation.CrlChecker`` (RFC 5280 sec. 6.3.3 in full: IDP scope,
    reasons_mask, indirect CRLs, certificateIssuer, delta CRLs). This function hands it the CRLs
    revokekit has fetched and verified; it does not decide anything itself. ``issuer`` is the
    certificate that issued ``cert`` (default: the CRL's signer, right for a direct CRL); for an
    indirect CRL pass it, with ``certificates`` and ``anchor`` so the CRL signer's own path can be
    validated (step (f)); ``more_crls`` are further complete CRLs for that path and for CRLs that
    partition the reasons (step (d)), unverified here and checked by pkix. A delta given here must combine with the complete CRL (sec. 5.2.4 (a) to
    (d)) and be current at ``at``, else ``CrlError``: the pair is the caller's claim.

    Anything but good or revoked (UNDETERMINED, or evidence pkix cannot process) raises
    ``CrlError``: a CRL that cannot establish the status never returns ``good``.
    """
    if complete.is_delta:
        raise CrlError("status_of needs a complete CRL first; a delta CRL cannot stand alone")
    if delta is not None:
        _can_combine(complete, delta)
        if not (
            delta.crl.this_update <= at
            and (delta.crl.next_update is None or at <= delta.crl.next_update)
        ):
            raise CrlError("the delta CRL is not current (sec. 5.2.4)")
    cert_issuer = issuer if issuer is not None else complete.issuer
    extra_crls: list[asn1core.Crl] = []
    for item in more_crls:
        if isinstance(item, asn1core.Crl):
            extra_crls.append(item)
            continue
        try:
            extra_crls.append(asn1core.parse_crl(item))
        except asn1core.Asn1Error:
            continue  # pkix would never use an unreadable CRL either
    crls = [complete.crl, *([delta.crl] if delta is not None else []), *extra_crls]
    checker = pkix.revocation.CrlChecker(
        crls, certificates=certificates, policy=policy, use_deltas=delta is not None
    )
    request = pkix.revocation.RevocationRequest(
        certificate=cert,
        issuer_name=cert_issuer.subject,
        issuer_spki=cert_issuer.subject_public_key_info,
        issuer_certificate=cert_issuer,
        at=at,
        index=1,
        anchor=anchor,
    )
    answer = checker(request)
    if answer.status not in ("good", "revoked"):
        raise CrlError(f"{answer.status}: {answer.reason}")
    if (
        delta is not None
        and "with delta" not in answer.reason
        and any(e.serial == cert.serial for e in delta.crl.revoked)
    ):
        # pkix reads a delta only when the CRL or the certificate carries FreshestCRL (sec. 6.3.3
        # (h)); a delta handed in explicitly that it left unread, and that mentions this
        # certificate, would make the answer disagree with the caller's evidence: refuse instead.
        raise CrlError(
            "the delta CRL names this certificate but pkix did not apply it: neither the CRL nor "
            "the certificate carries FreshestCRL (ROADMAP rk.crl-explicit-delta)"
        )
    entry, from_delta = None, False
    sources = [(delta.crl, True)] if delta is not None else []
    sources += [(complete.crl, False), *((c, False) for c in extra_crls)]
    for source, is_delta in sources:
        found = [e for e in source.revoked if e.serial == cert.serial]
        if found:
            entry, from_delta = found[0] if len(found) == 1 else None, is_delta
            break
    if answer.status == "good":
        return CrlStatus("good", None, None, from_delta and entry is not None, False, answer)
    # The decision is pkix's; the reason code and date are read back from the entry for the
    # caller. An indirect CRL may hold several entries for one serial (one per certificate
    # issuer): then the details stay None rather than guessed (ROADMAP rk.crl-answer-details).
    reason = None if entry is None else (entry.reason if entry.reason is not None else 0)
    when = None if entry is None else entry.revocation_date
    return CrlStatus("revoked", reason, when, from_delta, reason == 6, answer)


async def fetch(distribution_point: DistributionPoint, reason: int | None) -> Any:
    """Pending behaviour defined by RFC 5280 sec. 4.2.1.13.

    Not implemented yet. See the ``crl.fetch()`` row in ROADMAP.md; this stub raises on
    purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("fetch() is not implemented: RFC 5280 sec. 4.2.1.13")
