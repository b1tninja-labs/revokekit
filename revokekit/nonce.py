"""generation, echo verification and the missing nonce policy (RFC 9654).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    NoncePolicy = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "check",
    "generate",
]


def generate(length: int) -> bytes:
    """Pending behaviour defined by RFC 9654.

    Not implemented yet. See the ``nonce.generate()`` row in ROADMAP.md; this stub raises
    on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("generate() is not implemented: RFC 9654")


def check(request_nonce: bytes | None, response_nonce: bytes | None, policy: NoncePolicy) -> None:
    """Pending behaviour defined by RFC 9654.

    Not implemented yet. See the ``nonce.check()`` row in ROADMAP.md; this stub raises on
    purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("check() is not implemented: RFC 9654")
