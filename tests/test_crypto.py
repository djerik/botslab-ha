"""Unit tests for the QUC login crypto primitives (pure, no HA needed)."""

from __future__ import annotations

import base64
import hashlib
import urllib.parse

from custom_components.botslab import crypto
from custom_components.botslab.const import QUC_MSIGKEY, QUC_RSA_PUBKEY_B64


def test_des_parad_round_trip() -> None:
    """encrypt_params -> decrypt_response must recover the url-encoded params."""
    a117 = crypto.gen_key_material()
    assert len(a117) == 117
    params = {
        "username": "user@example.com",
        "password": crypto.md5_hex("secret"),
        "method": "UserIntf.login",
    }
    parad = crypto.encrypt_params(params, a117)
    recovered = urllib.parse.parse_qs(crypto.decrypt_response(parad, a117).decode())
    assert recovered["username"] == ["user@example.com"]
    assert recovered["password"] == [crypto.md5_hex("secret")]


def test_des_key_is_last_eight_chars() -> None:
    """The DES key/iv is the last 8 chars of the 117-char key material."""
    a117 = "x" * 109 + "ABCDEFGH"
    assert crypto.des_key_from_material(a117) == b"ABCDEFGH"


def test_rsa_key_material_block_size() -> None:
    """RSA/PKCS1 over the 1024-bit key yields a 128-byte cipher block."""
    a117 = crypto.gen_key_material()
    enc = crypto.encrypt_key_material(a117, QUC_RSA_PUBKEY_B64)
    assert len(base64.b64decode(enc)) == 128


def test_compute_sig_sorted_and_excludes_sig() -> None:
    """sig = md5(concat(sorted 'k=v', skipping any existing sig) + msigkey)."""
    params = {"b": "2", "a": "1", "sig": "STALE"}
    expected = hashlib.md5(("a=1b=2" + QUC_MSIGKEY).encode()).hexdigest()
    assert crypto.compute_sig(params, QUC_MSIGKEY) == expected


def test_md5_hex_matches_hashlib() -> None:
    """md5_hex is lowercase hex MD5 of the UTF-8 bytes."""
    assert crypto.md5_hex("botslab") == hashlib.md5(b"botslab").hexdigest()
