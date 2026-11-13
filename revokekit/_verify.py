"""One signature check over a stored signed region, shared by OCSP responses and CRLs.

The check goes through pkix's public seam, `pkix.validity.check_signed_data` (row
`rk.verify-seam-public`): pkix decides which verification an AlgorithmIdentifier asks for and reads
the SubjectPublicKeyInfo, and the arithmetic is `sigwire.verify`'s underneath it. revokekit no
longer imports pkix's private `_algorithms`. Failure is an exception, never a result.
"""

from __future__ import annotations

from dataclasses import dataclass

import sigwire.verify as sv
from pkix import errors as pkix_errors
from pkix import validity

from .errors import SignatureInvalid, SignaturePolicyRefused, SignatureUnsupported

__all__ = ["SignatureCheck", "verify_signed"]


@dataclass(frozen=True, slots=True)
class SignatureCheck:
    """What a successful check established."""

    algorithm: str
    scheme: str
    hash_name: str | None
    key: str


def verify_signed(
    algorithm_raw: bytes,
    spki: bytes,
    message: bytes,
    signature: bytes,
    *,
    policy: sv.Policy = sv.DEFAULT,
    inner_algorithm_raw: bytes | None = None,
    what: str = "signed object",
) -> SignatureCheck:
    """Verify ``signature`` over ``message`` (the stored DER bytes) under the key in ``spki``.

    ``inner_algorithm_raw`` is the copy of the algorithm inside the signed part, where the format
    repeats it (a CRL's tbsCertList.signature, RFC 5280 section 5.1.1.2); pkix refuses a pair that
    differs. A BasicOCSPResponse names its algorithm once (RFC 6960 section 4.2.1), so it passes
    None and the one copy is compared with itself.
    """
    inner = algorithm_raw if inner_algorithm_raw is None else inner_algorithm_raw
    try:
        found = validity.check_signed_data(
            message, algorithm_raw, inner, signature, spki, policy=policy, what=what
        )
    except pkix_errors.SignaturePolicyRefused as exc:
        raise SignaturePolicyRefused(str(exc)) from exc
    except pkix_errors.SignatureUnsupported as exc:
        raise SignatureUnsupported(str(exc)) from exc
    except pkix_errors.MalformedAlgorithm as exc:
        raise SignatureUnsupported(f"algorithm or key unusable: {exc}") from exc
    except pkix_errors.SignatureInvalid as exc:
        raise SignatureInvalid(str(exc)) from exc
    return SignatureCheck(found.algorithm, found.scheme, found.hash_name, found.key)
