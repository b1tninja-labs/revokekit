"""What a failed revocation check means: fail closed, with OCSP as the caller's explicit fallback.

PORTFOLIO.md section 9 item 15 decided the contract (row `rk.soft-fail-policy`): "revokekit fails
closed by default. When a CRL cannot establish status, the result is 'unknown', never 'good'. A
fallback to OCSP is the caller's explicit choice." RFC 5280 section 6.3.3 is the same rule in its
own words: a revocation status that has not been determined is returned as UNDETERMINED.

`decide` runs the sources a caller hands it, as callables, so a fetch, a parse and a verification
that fail are all the same thing here: an exception from the callable. Each failure is recorded as a
reason. The answer is "good" or "revoked" only when a source that was allowed to answer said so.
"""

from __future__ import annotations

import enum
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from .crl import CrlStatus
from .errors import RevokekitError
from .response import VerifiedResponse

__all__ = ["Decision", "Fallback", "decide"]


class Fallback(enum.Enum):
    """What to do when the CRL cannot establish a status. NONE is the default and fails closed."""

    NONE = "none"
    OCSP = "ocsp"


@dataclass(frozen=True, slots=True)
class Decision:
    """The status, which source gave it, and why any source before it did not."""

    state: Literal["good", "revoked", "unknown"]
    #: "crl", "ocsp", or None when no source answered.
    source: Literal["crl", "ocsp"] | None
    reasons: tuple[str, ...]

    @property
    def acceptable(self) -> bool:
        """True only for "good": "unknown" is never read as good (fail closed)."""
        return self.state == "good"


def decide(
    crl: Callable[[], CrlStatus] | None,
    ocsp: Callable[[], VerifiedResponse] | None = None,
    *,
    fallback: Fallback = Fallback.NONE,
) -> Decision:
    """Revocation status from a CRL, falling back to OCSP only when the caller asks.

    ``crl`` returns a ``crl.CrlStatus`` (for example ``crl.status_of`` over a fetched and verified
    CRL) or raises; ``ocsp`` returns a ``response.VerifiedResponse`` (``response.parse_and_verify``)
    or raises. A ``RevokekitError`` or ``OSError`` from either is a source that could not answer;
    any other exception is a bug and propagates.

    With ``fallback=Fallback.NONE`` the OCSP source is never consulted, and a CRL that cannot
    answer gives "unknown". With ``Fallback.OCSP`` it is consulted after the CRL fails, and an
    OCSP "unknown" (RFC 6960 sec. 2.2) stays "unknown".
    """
    reasons: list[str] = []
    if crl is None:
        reasons.append("no CRL source")
    else:
        try:
            status = crl()
        except (RevokekitError, OSError) as error:
            reasons.append(f"CRL: {error}")
        else:
            return Decision(status.state, "crl", tuple(reasons))
    if fallback is not Fallback.OCSP:
        reasons.append("no fallback: failing closed (PORTFOLIO.md section 9 item 15)")
        return Decision("unknown", None, tuple(reasons))
    if ocsp is None:
        reasons.append("OCSP fallback requested but no OCSP source given")
        return Decision("unknown", None, tuple(reasons))
    try:
        verified = ocsp()
    except (RevokekitError, OSError) as error:
        reasons.append(f"OCSP: {error}")
        return Decision("unknown", None, tuple(reasons))
    state = verified.single.status
    return Decision(state, "ocsp", tuple(reasons))
