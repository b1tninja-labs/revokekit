"""RFC 9654 sec. 2.1 nonce rules and RFC 9919 sec. 5 client policy.

The 47 octet vector is the example printed in RFC 9654 sec. 2.1 (rfclib, 2026-11-13).
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from revokekit import nonce
from revokekit.nonce import NonceError, NonceVerdict

RFC9654_EXAMPLE = bytes.fromhex(
    "302f06092b0601050507300102042204"
    "20dd49d4072c449da1c317bd1c1bdffe"
    "dbe150312ec4cd0add18e5bd6f84bf14"
    "c8"
)
RFC9654_NONCE = RFC9654_EXAMPLE[-32:]
NONCE = bytes(range(32))


def test_extension_encoding_matches_the_rfc9654_example():
    assert (
        len(RFC9654_EXAMPLE) == 2 + 47
    )  # the RFC prints SEQUENCE length 47, after a 2 octet header
    assert nonce.decode_extension(RFC9654_EXAMPLE) == RFC9654_NONCE
    assert nonce.encode_extension(RFC9654_NONCE) == RFC9654_EXAMPLE


def test_generate_uses_the_injected_source_and_defaults_to_32():
    seen = []

    def rng(count):
        seen.append(count)
        return b"\x07" * count

    assert nonce.generate(rng=rng) == b"\x07" * 32
    assert nonce.generate(128, rng=rng) == b"\x07" * 128
    assert seen == [32, 128]
    assert len(nonce.generate()) == 32


def test_generate_refuses_below_32_and_above_128():
    for length in (0, 1, 31, 129, 1000):
        with pytest.raises(NonceError):
            nonce.generate(length)
    with pytest.raises(TypeError):
        nonce.generate(True)


def test_generate_refuses_a_source_that_returns_the_wrong_length():
    with pytest.raises(NonceError):
        nonce.generate(32, rng=lambda _: b"x")


def test_encode_refuses_empty_and_129_octets():
    for bad in (b"", b"a" * 129):
        with pytest.raises(NonceError):
            nonce.encode_extension(bad)
    assert nonce.decode_extension(nonce.encode_extension(b"a" * 128)) == b"a" * 128
    assert nonce.decode_extension(nonce.encode_extension(b"a")) == b"a"


def test_check_match_mismatch_absent():
    assert nonce.check(NONCE, NONCE) is NonceVerdict.MATCH
    assert nonce.check(NONCE, bytes(reversed(NONCE))) is NonceVerdict.MISMATCH
    assert nonce.check(NONCE, None) is NonceVerdict.ABSENT_ALLOWED
    assert nonce.check(NONCE, None, require=True) is NonceVerdict.ABSENT_REFUSED


def test_response_nonce_of_zero_length_is_malformed():
    assert nonce.check(NONCE, b"") is NonceVerdict.MALFORMED
    assert nonce.check(NONCE, b"", require=True) is NonceVerdict.MALFORMED


def test_nonce_of_129_octets_is_malformed():
    assert nonce.check(NONCE, b"a" * 129) is NonceVerdict.MALFORMED
    assert nonce.check(b"a" * 129, NONCE) is NonceVerdict.MALFORMED
    assert nonce.check(b"", NONCE) is NonceVerdict.MALFORMED


def test_requestless_nonce_in_response_is_ignored():
    """RFC 9919 sec. 5: a client that sent no nonce MUST ignore one in the response."""
    assert nonce.check(None, NONCE) is NonceVerdict.ABSENT_ALLOWED
    assert nonce.check(None, NONCE, require=True) is NonceVerdict.ABSENT_ALLOWED
    assert nonce.check(None, b"") is NonceVerdict.ABSENT_ALLOWED
    assert nonce.check(None, None) is NonceVerdict.ABSENT_ALLOWED


def test_extension_with_trailing_bytes_refused():
    with pytest.raises(NonceError):
        nonce.decode_extension(RFC9654_EXAMPLE + b"\x00")


def test_extension_with_the_wrong_oid_or_shape_is_refused():
    wrong_oid = bytearray(RFC9654_EXAMPLE)
    wrong_oid[12] ^= 0x01  # last arc of the OID
    not_wrapped = bytes.fromhex("302506092b06010505073001020420") + RFC9654_NONCE
    for bad in (bytes(wrong_oid), not_wrapped, b"", b"\x30\x00", RFC9654_EXAMPLE[:-1]):
        with pytest.raises(NonceError):
            nonce.decode_extension(bad)


def test_extension_with_zero_length_nonce_is_refused():
    der = bytes.fromhex("300f06092b0601050507300102" + "04020400")
    with pytest.raises(NonceError):
        nonce.decode_extension(der)


def test_extension_critical_true_is_read_and_false_is_not_der():
    body = bytes.fromhex("06092b0601050507300102") + b"\x01\x01\xff" + RFC9654_EXAMPLE[13:]
    critical = b"\x30" + bytes([len(body)]) + body
    assert nonce.decode_extension(critical) == RFC9654_NONCE
    explicit_false = critical.replace(b"\x01\x01\xff", b"\x01\x01\x00")
    with pytest.raises(NonceError):
        nonce.decode_extension(explicit_false)


def test_comparison_is_constant_time():
    """check() compares with hmac.compare_digest and never with == or != on the nonces."""
    tree = ast.parse(pathlib.Path(nonce.__file__).read_text(encoding="utf-8"))
    check_fn = next(
        n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "check"
    )
    calls = [
        n.func.attr
        for n in ast.walk(check_fn)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
    ]
    assert "compare_digest" in calls
    for node in ast.walk(check_fn):
        if isinstance(node, ast.Compare) and any(
            isinstance(op, ast.Eq | ast.NotEq) for op in node.ops
        ):
            names = {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
            assert not names & {"request_nonce", "response_nonce"}
