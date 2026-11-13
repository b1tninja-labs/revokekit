"""thisUpdate, nextUpdate, maxAge and skew tolerance (RFC 6960, RFC 9919).

The rules are RFC 9919 sec. 5 (read whole): the client MUST check that nextUpdate exists and
MUST reject the response if it does not; the current time MUST fall between thisUpdate and
nextUpdate; a response after nextUpdate is stale and MUST be rejected, except that a client MAY
allow a small configured tolerance after nextUpdate. RFC 6960 sec. 2.4 gives the meaning of the
fields. Nothing here reads a clock: ``now`` is always passed in.

A matching nonce does not relax any of this. RFC 9919 sec. 5 makes the time check mandatory for
clients and the nonce an additional mechanism, so ``is_fresh`` takes no nonce argument.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from datetime import datetime, timedelta

__all__ = [
    "Freshness",
    "Reason",
    "is_fresh",
]


class Reason(enum.Enum):
    """Why a response is, or is not, fresh."""

    FRESH = "fresh"
    NO_NEXT_UPDATE = "no_next_update"
    STALE = "stale"
    NOT_YET_VALID = "not_yet_valid"
    TOO_OLD = "too_old"
    BAD_INTERVAL = "bad_interval"


@dataclass(frozen=True, slots=True)
class Freshness:
    """The verdict and the single reason that decided it."""

    fresh: bool
    reason: Reason

    def __bool__(self) -> bool:
        return self.fresh


def _aware(value: datetime, name: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{name} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware: RFC 9919 sec. 5 compares GMT times")


def is_fresh(
    this_update: datetime,
    next_update: datetime | None,
    *,
    now: datetime,
    tolerance: timedelta = timedelta(0),
    early_tolerance: timedelta = timedelta(0),
    max_age: timedelta | None = None,
) -> Freshness:
    """Decide whether a response may be accepted on time grounds (RFC 9919 sec. 5).

    ``this_update`` and ``next_update`` come from the SingleResponse; ``now`` is the caller's
    accurate clock. In the order the checks run:

    1. ``next_update`` of None is rejected (RFC 9919 sec. 5: "MUST reject the response").
    2. ``next_update`` earlier than ``this_update`` is a malformed interval.
    3. ``now`` later than ``next_update + tolerance`` is stale. ``tolerance`` is the RFC 9919
       sec. 5 allowance after nextUpdate and defaults to none; the RFC gives no number.
    4. ``now`` earlier than ``this_update - early_tolerance`` is not yet valid. The RFC says
       the current time must fall between the two and names no allowance before thisUpdate, so
       ``early_tolerance`` is a project convention, explicit and defaulting to none.
    5. ``max_age`` is a local policy, not in RFC 9919: when given, ``now - this_update`` above it
       is rejected. It defaults to None because the RFC supplies no default to copy.

    The boundaries are accepting: ``now == next_update`` and ``now == this_update`` are fresh.
    A naive datetime is refused with ValueError rather than guessed to be UTC.
    """
    _aware(this_update, "this_update")
    _aware(now, "now")
    if next_update is not None:
        _aware(next_update, "next_update")
    for name, span in (("tolerance", tolerance), ("early_tolerance", early_tolerance)):
        if span < timedelta(0):
            raise ValueError(f"{name} must not be negative")
    if max_age is not None and max_age < timedelta(0):
        raise ValueError("max_age must not be negative")

    if next_update is None:
        return Freshness(False, Reason.NO_NEXT_UPDATE)
    if next_update < this_update:
        return Freshness(False, Reason.BAD_INTERVAL)
    if now > next_update + tolerance:
        return Freshness(False, Reason.STALE)
    if now < this_update - early_tolerance:
        return Freshness(False, Reason.NOT_YET_VALID)
    if max_age is not None and now - this_update > max_age:
        return Freshness(False, Reason.TOO_OLD)
    return Freshness(True, Reason.FRESH)
