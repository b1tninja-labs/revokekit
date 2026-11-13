"""RFC 9919 sec. 3.1.1 request profile, checked against the RFC 9919 appendix B.4 example."""

from __future__ import annotations

import base64
import hashlib
import pathlib

import asn1core
import asn1core.pem as pem
import pytest

from revokekit import nonce, request
from revokekit.request import RequestError

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "rfc9919"


def _der(name):
    return pem.certificates((FIXTURES / name).read_bytes())[0].der


ROOT = _der("root_ca.pem")
LEAF = _der("end_entity.pem")
B4 = base64.b64decode((FIXTURES / "ocsp_request.b64").read_bytes())
NONCE = bytes(range(32))


def _fields(der):
    """(OCSPRequest, tbsRequest, the single CertID) of a DER OCSPRequest."""
    top, end = asn1core.decode(der, der=True)
    assert end == len(der)
    tbs = top.children[0]
    cert_id = tbs.children[0].children[0].children[0]
    return top, tbs, cert_id


def test_request_matches_rfc9919_appendix_b4():
    assert request.build(LEAF, ROOT) == B4


def test_certificate_objects_and_der_bytes_build_the_same_request():
    parsed = (asn1core.parse_certificate(LEAF), asn1core.parse_certificate(ROOT))
    assert request.build(*parsed) == B4


def test_certid_hashes_are_over_the_issuer_name_der_and_key_bits():
    leaf = asn1core.parse_certificate(LEAF)
    root = asn1core.parse_certificate(ROOT)
    _, _, cert_id = _fields(B4)
    assert cert_id.children[1].content() == hashlib.sha256(leaf.issuer.raw).digest()
    spki, _ = asn1core.decode(root.subject_public_key_info, der=True)
    _, bits = asn1core.check_bit_string(spki.children[1].content())
    assert cert_id.children[2].content() == hashlib.sha256(bits).digest()


def test_certid_issuer_key_hash_excludes_unused_bits_octet():
    root = asn1core.parse_certificate(ROOT)
    spki, _ = asn1core.decode(root.subject_public_key_info, der=True)
    with_octet = spki.children[1].content()
    assert with_octet[0] == 0
    _, _, cert_id = _fields(request.build(LEAF, ROOT))
    assert cert_id.children[2].content() != hashlib.sha256(with_octet).digest()


def test_sha256_is_the_default_and_sha1_requires_explicit_opt_in():
    _, _, default_id = _fields(request.build(LEAF, ROOT))
    algorithm = default_id.children[0].children[0]
    assert asn1core.decode_oid(algorithm.content()) == (2, 16, 840, 1, 101, 3, 4, 2, 1)
    _, _, legacy = _fields(request.build(LEAF, ROOT, hash_name="sha1"))
    assert asn1core.decode_oid(legacy.children[0].children[0].content()) == (1, 3, 14, 3, 2, 26)
    assert len(legacy.children[1].content()) == 20
    with pytest.raises(RequestError):
        request.build(LEAF, ROOT, hash_name="md5")


def test_two_requests_are_never_emitted():
    _, tbs, _ = _fields(request.build(LEAF, ROOT, NONCE))
    request_list = tbs.children[0]
    assert len(request_list.children) == 1
    assert len(request_list.children[0].children) == 1  # no singleRequestExtensions


def test_unsigned_and_unnamed():
    top, tbs, _ = _fields(request.build(LEAF, ROOT, NONCE))
    assert len(top.children) == 1  # no optionalSignature
    assert [child.tag.number for child in tbs.children] == [16, 2]  # no version, no requestorName


def test_nonce_extension_is_only_extension():
    _, tbs, _ = _fields(request.build(LEAF, ROOT, NONCE))
    extensions = tbs.children[1]
    assert extensions.tag.number == 2
    assert extensions.tag.constructed
    sequence = extensions.children[0]
    assert len(sequence.children) == 1
    assert sequence.children[0].raw == nonce.encode_extension(NONCE)


def test_no_nonce_means_no_request_extensions():
    _, tbs, _ = _fields(request.build(LEAF, ROOT))
    assert len(tbs.children) == 1


def test_short_nonce_refused_because_a_requester_uses_at_least_32():
    with pytest.raises(nonce.NonceError):
        request.build(LEAF, ROOT, b"x" * 31)
    with pytest.raises(nonce.NonceError):
        request.build(LEAF, ROOT, b"x" * 129)


def test_serial_encoding_is_minimal_twos_complement():
    cases = {
        0: "020100",
        1: "020101",
        127: "02017f",
        128: "02020080",
        255: "020200ff",
        256: "02020100",
        -1: "0201ff",
        -128: "020180",
        -129: "0202ff7f",
    }
    for value, expected in cases.items():
        assert request._integer(value).hex() == expected


def test_serial_with_high_bit_is_positive_integer():
    assert request._integer(0x80).hex() == "02020080"
    assert request._integer(2**159).hex().startswith("02150080")


def test_serial_of_the_example_is_read_from_the_certificate():
    _, _, cert_id = _fields(B4)
    assert asn1core.check_integer(cert_id.children[3].content()) == 27979789


def test_issuer_that_did_not_issue_the_certificate_is_refused():
    with pytest.raises(RequestError, match="issuer"):
        request.build(ROOT, LEAF)  # root's issuer is itself, not LEAF's subject


def test_garbage_certificates_are_refused():
    with pytest.raises(RequestError):
        request.build(b"\x30\x00", ROOT)
    with pytest.raises(TypeError):
        request.build("LEAF", ROOT)
