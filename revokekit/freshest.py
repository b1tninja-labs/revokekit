"""thisUpdate, nextUpdate, maxAge and skew tolerance (RFC 6960, RFC 9919).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime, timedelta
    from typing import Any

    Response = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "is_fresh",
]


def is_fresh(response: Response, at: datetime, tolerance: timedelta) -> bool:
    """Pending behaviour defined by RFC 9919.

    Not implemented yet. See the ``freshest.is_fresh()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("is_fresh() is not implemented: RFC 9919")
