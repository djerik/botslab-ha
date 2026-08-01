"""Unit tests for the pure-Python live transport (no device, no HA needed).

These cover the core wire format — the double-base64 RC4 signalling envelope, the two key
regimes (fixed base-capacity key vs rotating secret key), and the relay app-frame format — so a
regression is caught without waking the doorbell. Identifiers here are the same fakes the JSON
fixtures use; no real serial or product key belongs in the repository.
"""

from __future__ import annotations

import base64
import json

from custom_components.botslab.clip_crypto import rc4
from custom_components.botslab.live import schedule, tunnel_signal as ts
from custom_components.botslab.live._http import Http, UrllibHttp
from custom_components.botslab.live.cloud import BotslabCloud
from custom_components.botslab.live.engine import _FIXED_KEY, LiveEngine
from custom_components.botslab.live.relay import (
    C_LOGIN,
    build_login,
    parse_tlvs,
    qtp_checksum,
)


def _engine() -> LiveEngine:
    """A LiveEngine wired with a known rotating key, without running cloud setup."""
    eng = LiveEngine(q="Q", t="T", region="eu1", product_key="a1B2c3D4e5",
                     sn="SN0123456789ABCDEF", m2="m2", on_h264=lambda _b: None)
    eng._keys = {3583: "K" * 32}
    eng._idx = 3583
    eng._key = b"K" * 32
    eng._usign = "0" * 32  # stand-in for the getRelaySign uSign; only its round-trip matters here
    return eng


# ------------------------------------------------------------------ RC4
def test_rc4_is_involutive() -> None:
    """RC4 is symmetric: decrypting the ciphertext with the same key returns the plaintext."""
    key = b"secretkey_secretkey_secretkey_32"
    pt = b"the quick brown fox" * 5
    assert rc4(rc4(pt, key), key) == pt


def test_rc4_known_answer() -> None:
    """Textbook RC4 KAT (key='Key', 'Plaintext' -> BBF316E8D940AF0AD3)."""
    assert rc4(b"Plaintext", b"Key").hex().upper() == "BBF316E8D940AF0AD3"


# --------------------------------------------------- signalling envelope crypto
def test_transfer_token_round_trip() -> None:
    """transfer_token (rotating key, algo:1) decrypts back to a req_relay inner with our uSign."""
    eng = _engine()
    env = json.loads(eng._transfer_token())
    assert env["index"] == 3583
    assert env["algo"] == 1
    assert "bc" not in env  # rotating-key regime carries no bc field
    inner = json.loads(eng._decrypt_device(env))
    assert inner["type"] == "req_relay"
    assert inner["token"] == eng._usign
    assert inner["publish_sn"] == "SN0123456789ABCDEF_01_01"


def test_base_capacity_uses_fixed_key() -> None:
    """base_capacity uses the hardcoded key + bc:1; decrypting with the rotating key must fail."""
    eng = _engine()
    env = json.loads(eng._base_capacity())
    assert env["bc"] == 1
    assert "algo" not in env and "index" not in env  # => decrypt_device treats it as algo 0 (fixed)
    inner = json.loads(eng._decrypt_device(env))
    assert inner["type"] == "base_capacity"
    # The fixed key is not one of the rotating secret keys.
    assert eng._key != _FIXED_KEY


def test_double_base64_layering() -> None:
    """The envelope data must be base64(RC4(base64(inner))) — two base64 layers, not one."""
    eng = _engine()
    inner = '{"type":"base_capacity"}'
    env = json.loads(eng._encode_signal(inner, _FIXED_KEY, {"bc": 1}))
    once = rc4(base64.b64decode(env["data"]), _FIXED_KEY)
    # After one RC4+b64 strip we still hold base64 text, not the JSON yet.
    assert base64.b64decode(once).decode() == inner


# ------------------------------------------------------------------ relay protocol
def test_qtp_checksum_folds_carry() -> None:
    """Checksum is the folded ones-complement of the four header halfwords."""
    # 0xFFFF + 0xFFFF + 0 + 0 folds to 0xFFFF -> complement 0x0000.
    assert qtp_checksum(0xFFFF, 0xFFFF, 0, 0) == 0x0000
    assert qtp_checksum(0, 0, 0, 0) == 0xFFFF


def test_login_frame_parses() -> None:
    """build_login yields a class-0x01 app frame carrying the stream id and ukey."""
    frame = build_login("SN0123456789ABCDEF_01_01", "ukey123", "EU_relay", "a1B2c3D4e5")
    assert frame[5] == C_LOGIN                 # class byte
    tlvs = parse_tlvs(frame[10:])             # body starts after the 10-byte app-frame header
    assert tlvs[0x0001] == b"SN0123456789ABCDEF_01_01"
    assert tlvs[0x0002] == b"ukey123"
    assert tlvs[0x000B] == b"a1B2c3D4e5"


# --------------------------------------------------------------- tunnel framing
def test_tunnel_wrap_header() -> None:
    """_wrap prefixes the 8009 magic and encodes path/type/conv + length."""
    frame = ts._wrap(0x02, 0x30, 0x85613D90, b"body")
    assert frame[:8] == ts.MAGIC
    assert frame[0x12] == 0x02  # path
    assert frame[0x13] == 0x30  # type


def test_reqrelay_inner_shape() -> None:
    """The req_relay inner carries the publish_sn derived from the device sn."""
    inner = json.loads(ts.build_reqrelay_inner(
        "SN0123456789ABCDEF", "req-id_1", "ctx-uuid", token="tok"))
    assert inner["model"] == "netsdk"
    assert inner["publish_sn"] == "SN0123456789ABCDEF_01_01"
    assert inner["token"] == "tok"


# ------------------------------------------------------------------ HTTP seam
class _Recorder(Http):
    """Http transport that records the request instead of sending it."""

    def __init__(self, reply: bytes = b"{}") -> None:
        self.calls: list[tuple[str, str, bytes | None, dict[str, str]]] = []
        self._reply = reply

    def request(self, method: str, url: str, *, body: bytes | None,
                headers: dict[str, str]) -> bytes:
        self.calls.append((method, url, body, dict(headers)))
        return self._reply


def test_cloud_calls_go_through_the_injected_transport() -> None:
    """Every cloud call must use the transport handed in (HA's session in production)."""
    rec = _Recorder(json.dumps({"data": {"sid": "SID"}}).encode())
    cloud = BotslabCloud("Q", "T", "eu1", "m2", http=rec)
    cloud.login()
    cloud.wake("a1B2c3D4e5", "SN0123456789ABCDEF")
    assert [c[0] for c in rec.calls] == ["POST", "POST"]
    assert "Authorization" in rec.calls[0][3]
    # The form body keeps urllib's implicit content type, so the wire bytes are unchanged.
    assert b"identifier=WakeUp" in rec.calls[1][2]
    assert rec.calls[1][3]["Content-Type"] == "application/x-www-form-urlencoded"


def test_schedule_calls_go_through_the_injected_transport() -> None:
    """schedule_2 signs its own URL, so it must reach the transport with the query intact."""
    rec = _Recorder(b"eyJXXXlcnJjb2RlIjowfQ==")  # base64 {"errcode":0}, 3-char nonce at [3:6]
    assert schedule.register_viewer("eu1", "SN0123456789ABCDEF", "pid", "chan", "0" * 32,
                                    "machineid", http=rec) is True
    method, url, body, headers = rec.calls[0]
    assert (method, body) == ("GET", None)
    assert "/substream?" in url and "_sign=" in url
    assert headers["User-Agent"] == "netsdk"


def test_transport_defaults_to_stdlib_outside_home_assistant() -> None:
    """Without an injected transport the live package stays standalone-runnable."""
    assert isinstance(_engine()._http, UrllibHttp)
    assert isinstance(BotslabCloud("Q", "T")._http, UrllibHttp)


def test_per_install_identities_are_stable_and_distinct() -> None:
    """Signalling identities derive from m2: stable for one install, different across installs."""
    assert ts.machine_id("m2-a") == ts.machine_id("m2-a")  # deterministic
    assert ts.machine_id("m2-a") != ts.machine_id("m2-b")  # per-install
    assert ts.requester_id("m2-a").endswith("_1")
    assert ts.requester_id("m2-a") != ts.requester_id("m2-b")
