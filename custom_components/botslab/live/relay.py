"""Relay app-protocol — the ``20 14 11 04`` framing carried over the TURN relay (e.g. :80).

Login = class 0x01 {stream_id, ukey, cluster, product_key}; start = class 0x09; media =
class 0x02 (encrypted H.264, decrypt with get_keys[index]).

This module is the wire *format* only. The transport that carries it lives in :mod:`relay_tcp`.
The relay also speaks a QTP reliable-UDP ("udx") transport, which we no longer use: reimplementing
its reassembly by hand mis-assembled large multi-packet keyframes, so they decoded top-only and
washed out. The app delegates that to a reliable-UDP library, so we let TCP provide reliable
in-order delivery instead. ``qtp_checksum`` remains because the relay may still wrap TCP payloads
in the same 14-byte header (see ``relay_tcp._detect_framing``).
"""

from __future__ import annotations

from dataclasses import dataclass
import struct

APP_MAGIC = bytes.fromhex("20141104")
APP_VER = 0x00

# app classes (over the relay)
C_LOGIN = 0x01
C_LOGIN_RESP = 0x69
C_CONFIG = 0x05
C_START = 0x09
C_MEDIA = 0x02

# TLV ids
T_STREAM_ID = 0x0001   # login: "<sn>_<channel>_<stream>", e.g. SN0123456789ABCDEF_01_01
T_UKEY = 0x0002        # login: base64 token (stable per device, from schedule)
T_CLUSTER = 0x0005     # login: cluster, e.g. "EU_relay"
T_PRODUCT_KEY = 0x000B  # login: product_key, identifying the device model
T_FLAG15 = 0x0015      # login: 4-byte flag = 0
T_RESULT = 0x0016      # login resp: BE32 result (0 = ok)
T_STREAM_TYPE = 0x000C  # start: stream type (0)


def tlv(id_: int, value: bytes) -> bytes:
    return struct.pack(">HH", id_, len(value)) + value


def parse_tlvs(body: bytes) -> dict[int, bytes]:
    out, i = {}, 0
    while i + 4 <= len(body):
        tid, tl = struct.unpack_from(">HH", body, i)
        i += 4
        out[tid] = body[i:i + tl]
        i += tl
    return out


def app_frame(cls: int, body: bytes) -> bytes:
    return APP_MAGIC + bytes([APP_VER, cls]) + struct.pack(">I", len(body)) + body


def build_login(stream_id: str, ukey: str, cluster: str, product_key: str) -> bytes:
    """class 0x01 login — TLVs 0x0001 stream_id, 0x0002 ukey, 0x0005 cluster, 0x000b product_key."""
    body = (tlv(T_STREAM_ID, stream_id.encode()) + tlv(T_UKEY, ukey.encode())
            + tlv(T_CLUSTER, cluster.encode()) + tlv(T_PRODUCT_KEY, product_key.encode())
            + tlv(T_FLAG15, b"\x00\x00\x00\x00"))
    return app_frame(C_LOGIN, body)


def build_start(stream_type: int = 0) -> bytes:
    return app_frame(C_START, tlv(T_STREAM_TYPE, struct.pack(">I", stream_type)))


@dataclass
class AppFrame:
    cls: int
    body: bytes

    @property
    def tlvs(self) -> dict[int, bytes]:
        return parse_tlvs(self.body)


def qtp_checksum(conv: int, sn: int, una: int, flags: int) -> int:
    """Internet checksum (ones-complement) over the 4 header halfwords before the cksum field.
    cksum = ~fold(conv + sn + una + flags) & 0xffff."""
    s = conv + sn + una + flags
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF
