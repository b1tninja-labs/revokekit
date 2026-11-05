"""verify a TLS server's stapled response against the connection (RFC 7633).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    Certificate = Any  # placeholder: give it a real type in the milestone that needs it
    Response = Any  # placeholder: give it a real type in the milestone that needs it
    Status = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "verify_stapled",
]


def verify_stapled(response: Response, peer_cert: Certificate, sans: list) -> Status:
    """Pending behaviour defined by RFC 7633.

    Not implemented yet. See the ``stapling.verify_stapled()`` row in ROADMAP.md; this
    stub raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("verify_stapled() is not implemented: RFC 7633")
