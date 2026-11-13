"""RSASSA-PSS and Ed25519 signatures on OCSP responses and CRLs (row `rk.response-sigalg-coverage`).

RFC 6960 sec. 4.2.1 and RFC 5280 sec. 5.1.1.2 let a response or a CRL carry any signature algorithm
the signer's key supports; RFC 4055 sec. 3.1 defines RSASSA-PSS with its parameters and RFC 8410
sec. 3 (with RFC 8032) Ed25519. Both go through `_verify.verify_signed`, which is pkix's public
`validity.check_signed_data` (row `rk.verify-seam-public`). `cryptography`'s OCSP builder signs only
with PKCS #1 v1.5 for RSA, so the PSS response is re-signed here over the stored tbsResponseData.
"""

from __future__ import annotations

import ast
import pathlib

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, padding
from cryptography.hazmat.primitives.serialization import Encoding
from pki_helpers import (
    DAY,
    NOW,
    Party,
    _builder,
    crl_der,
    make_ca,
    make_leaf,
    name,
    ocsp_response,
    single_response,
)

from revokekit import crl as crl_module
from revokekit import response
from revokekit.errors import SignatureInvalid

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _tlv(tag: int, body: bytes) -> bytes:
    n = len(body)
    if n < 0x80:
        return bytes([tag, n]) + body
    size = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(size)]) + size + body


def _oid(*arcs: int) -> bytes:
    body = bytes([40 * arcs[0] + arcs[1]])
    for arc in arcs[2:]:
        chunk = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunk.append(0x80 | (arc & 0x7F))
            arc >>= 7
        body += bytes(reversed(chunk))
    return _tlv(0x06, body)


SHA256_ALG = _tlv(0x30, _oid(2, 16, 840, 1, 101, 3, 4, 2, 1) + b"\x05\x00")
# RSASSA-PSS-params (RFC 4055 sec. 3.1): SHA-256, MGF1 with SHA-256, saltLength 32.
PSS_ALG = _tlv(
    0x30,
    _oid(1, 2, 840, 113549, 1, 1, 10)
    + _tlv(
        0x30,
        _tlv(0xA0, SHA256_ALG)
        + _tlv(0xA1, _tlv(0x30, _oid(1, 2, 840, 113549, 1, 1, 8) + SHA256_ALG))
        + _tlv(0xA2, b"\x02\x01\x20"),
    ),
)
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)


def _pss_response(ca: Party, leaf: Party) -> bytes:
    """An OCSPResponse whose BasicOCSPResponse is RSASSA-PSS signed (RFC 6960 sec. 4.2.1)."""
    plain = ocsp_response(ca, [single_response(leaf, ca)])
    basic = response.parse(plain).basic
    assert basic is not None
    tbs = basic.tbs_response_data
    signature = ca.key.sign(tbs, PSS, hashes.SHA256())
    body = _tlv(0x30, tbs + PSS_ALG + _tlv(0x03, b"\x00" + signature))
    response_bytes = _tlv(0x30, _oid(1, 3, 6, 1, 5, 5, 7, 48, 1, 1) + _tlv(0x04, body))
    return _tlv(0x30, b"\x0a\x01\x00" + _tlv(0xA0, response_bytes))


def _ed25519_ca() -> tuple[Party, Party]:
    key = ed25519.Ed25519PrivateKey.generate()
    subject = name("Ed25519 CA")
    usage = x509.KeyUsage(True, False, False, False, False, True, True, False, False)
    cert = (
        _builder(subject, subject, key, 1)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(usage, critical=True)
        .sign(key, None)
    )
    ca = Party(key, cert)
    leaf_key = ed25519.Ed25519PrivateKey.generate()
    leaf = Party(leaf_key, _builder(name("ed.example"), subject, leaf_key, 1001).sign(key, None))
    return ca, leaf


def test_pss_and_ed25519_response_signatures_verify():
    rsa_ca = make_ca("RSA CA", kind="rsa")
    rsa_leaf = make_leaf(rsa_ca, kind="rsa")
    raw = _pss_response(rsa_ca, rsa_leaf)
    verified = response.parse_and_verify(raw, rsa_leaf.parsed, rsa_ca.parsed, at=NOW)
    assert verified.signature.scheme == "rsa-pss"
    assert verified.signature.hash_name == "sha256"
    tampered = bytearray(raw)
    tampered[-1] ^= 0x01
    with pytest.raises(SignatureInvalid):
        response.parse_and_verify(bytes(tampered), rsa_leaf.parsed, rsa_ca.parsed, at=NOW)

    ed_ca, ed_leaf = _ed25519_ca()
    ed_raw = ocsp_response(ed_ca, [single_response(ed_leaf, ed_ca)], hash_algorithm=None)
    ed = response.parse_and_verify(ed_raw, ed_leaf.parsed, ed_ca.parsed, at=NOW)
    assert ed.signature.scheme == "ed25519"
    assert ed.signature.key == "Ed25519"


def test_pss_and_ed25519_crl_signatures_verify():
    rsa_ca = make_ca("RSA CRL CA", kind="rsa")
    revoked_leaf = make_leaf(rsa_ca, serial=1002, kind="rsa")
    builder_raw = crl_der(rsa_ca, [(1002, NOW - DAY, None)])
    # crl_der signs with PKCS #1 v1.5; re-sign the same CRL contents with PSS through cryptography.
    parsed = x509.load_der_x509_crl(builder_raw)
    pss_builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(parsed.issuer)
        .last_update(parsed.last_update_utc)
        .next_update(parsed.next_update_utc)
    )
    for ext in parsed.extensions:
        pss_builder = pss_builder.add_extension(ext.value, ext.critical)
    for entry in parsed:
        pss_builder = pss_builder.add_revoked_certificate(entry)
    pss_raw = pss_builder.sign(rsa_ca.key, hashes.SHA256(), rsa_padding=PSS).public_bytes(
        Encoding.DER
    )
    verified = crl_module.parse_and_verify(pss_raw, rsa_ca.parsed, at=NOW)
    assert verified.signature.scheme == "rsa-pss"
    assert crl_module.status_of(revoked_leaf.parsed, verified, at=NOW).state == "revoked"

    ed_ca, ed_leaf = _ed25519_ca()
    ed_builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ed_ca.cert.subject)
        .last_update(NOW - DAY)
        .next_update(NOW + DAY)
        .add_extension(x509.CRLNumber(1), critical=False)
    )
    ed_raw = ed_builder.sign(ed_ca.key, None).public_bytes(Encoding.DER)
    ed = crl_module.parse_and_verify(ed_raw, ed_ca.parsed, at=NOW)
    assert ed.signature.scheme == "ed25519"
    assert crl_module.status_of(ed_leaf.parsed, ed, at=NOW).state == "good"


def test_revokekit_no_longer_imports_pkix_private_algorithms():
    """Row `rk.verify-seam-public`: the seam is pkix's public `validity.check_signed_data`."""
    for path in (ROOT / "revokekit").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                names = [f"{node.module}.{alias.name}" for alias in node.names]
            elif isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            else:
                continue
            assert not any("pkix._algorithms" in n for n in names), path.name
