"""parse and verify signatures, including delegated responders (RFC 6960).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    Response = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "parse_and_verify",
]


def parse_and_verify(raw: bytes, responder_certs: list) -> Response:
    """Pending behaviour defined by RFC 6960.

    Not implemented yet. See the ``response.parse_and_verify()`` row in ROADMAP.md; this
    stub raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("parse_and_verify() is not implemented: RFC 6960")
