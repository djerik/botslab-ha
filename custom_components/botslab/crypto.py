"""QUC login crypto primitives (pure, no HA imports).

QUC login request/response crypto, as used by the Botslab app:
  - password field  = MD5(password)
  - sig             = MD5( "".join(f"{k}={v}" for sorted params) + QUC_MSIGKEY )
  - parad           = base64( DES/CBC/PKCS5( urlencode(params) ) )  key=iv=last 8 of a117
  - key             = base64( RSA/ECB/PKCS1( a117 ) )               (a117 = random 117 chars)
  - response `ret`  = DES/CBC/PKCS5 decrypt with the same key/iv
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import string
import urllib.parse

from Crypto.Cipher import DES, PKCS1_v1_5
from Crypto.PublicKey import RSA

_ALPHANUM = string.ascii_letters + string.digits


def md5_hex(text: str) -> str:
    """Lowercase hex MD5 of a UTF-8 string."""
    return hashlib.md5(text.encode("utf-8")).hexdigest()  # noqa: S324 - required by protocol


def rand_str(n: int, alphabet: str = _ALPHANUM) -> str:
    """Cryptographically-random string of length n."""
    return "".join(secrets.choice(alphabet) for _ in range(n))


def gen_key_material() -> str:
    """Random 117-char string; its last 8 chars become the DES key/iv."""
    return rand_str(117)


def _pkcs5_pad(data: bytes) -> bytes:
    pad = 8 - (len(data) % 8)
    return data + bytes([pad]) * pad


def _pkcs5_unpad(data: bytes) -> bytes:
    return data[: -data[-1]]


def compute_sig(params: dict[str, str], msigkey: str) -> str:
    """QUC signature over the (decoded) params, excluding any existing 'sig'."""
    concat = "".join(f"{k}={params[k]}" for k in sorted(params) if k != "sig")
    return md5_hex(concat + msigkey)


def des_key_from_material(a117: str) -> bytes:
    """Derive the 8-byte DES key/iv (last 8 chars of the key material)."""
    return a117[-8:].encode("utf-8")


def encrypt_params(params: dict[str, str], a117: str) -> str:
    """DES/CBC/PKCS5-encrypt the url-encoded params -> base64 (`parad`)."""
    key = des_key_from_material(a117)
    plaintext = urllib.parse.urlencode(params).encode("utf-8")
    ct = DES.new(key, DES.MODE_CBC, key).encrypt(_pkcs5_pad(plaintext))  # noqa: S304 - protocol
    return base64.b64encode(ct).decode("ascii")


def encrypt_key_material(a117: str, rsa_pub_b64: str) -> str:
    """RSA/ECB/PKCS1-encrypt the 117-char key material -> base64 (`key`)."""
    rsa = RSA.import_key(base64.b64decode(rsa_pub_b64))
    ct = PKCS1_v1_5.new(rsa).encrypt(a117.encode("utf-8"))
    return base64.b64encode(ct).decode("ascii")


def decrypt_response(ret_b64: str, a117: str) -> bytes:
    """DES/CBC/PKCS5-decrypt a response `ret` using the same key material."""
    key = des_key_from_material(a117)
    pt = DES.new(key, DES.MODE_CBC, key).decrypt(base64.b64decode(ret_b64))  # noqa: S304 - protocol
    return _pkcs5_unpad(pt)
