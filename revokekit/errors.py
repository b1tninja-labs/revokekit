"""The exceptions revokekit raises. A refusal is an exception, never a result that says "fine"."""

from __future__ import annotations

__all__ = [
    "CrlError",
    "NoRevAvailViolation",
    "ResponderNotAuthorized",
    "ResponseError",
    "ResponseStatusError",
    "RevokekitError",
    "SignatureInvalid",
    "SignaturePolicyRefused",
    "SignatureUnsupported",
]


class RevokekitError(Exception):
    """Base of everything this package raises on purpose."""


class ResponseError(RevokekitError, ValueError):
    """An OCSP response that is malformed, or that breaks a rule of RFC 6960 or RFC 9919."""


class ResponseStatusError(ResponseError):
    """The responder answered with an error status (RFC 6960 sec. 4.2.1); ``status`` is its number."""

    def __init__(self, message: str, status: int) -> None:
        super().__init__(message)
        self.status = status


class CrlError(RevokekitError, ValueError):
    """A CRL that cannot be used: malformed, wrong issuer or scope, or not combinable with its base."""


class SignatureInvalid(RevokekitError):
    """The signature does not verify under the key it was checked against."""


class SignatureUnsupported(RevokekitError):
    """The signature algorithm or key type is one this package does not verify."""


class SignaturePolicyRefused(RevokekitError):
    """The signature algorithm is understood but the verification policy refuses it."""


class ResponderNotAuthorized(RevokekitError):
    """The key that signed the response is not one RFC 6960 sec. 4.2.2.2 lets answer for the CA."""


class NoRevAvailViolation(RevokekitError):
    """A certificate with noRevAvail that breaks RFC 9608 sec. 3, so a relying party MUST reject it."""
