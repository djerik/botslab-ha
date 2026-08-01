"""Byte-exact codec tests for :mod:`custom_components.botslab.live.tunnel_proto`.

Fixtures are real datagrams captured from the app while it streamed live video (owner account). They
pin the wire format so a refactor cannot silently break interop with the relay/tracker.
"""

import struct

from custom_components.botslab.live.tunnel_proto import (
    CMD_LOGIN,
    CMD_TUNNEL_REQ,
    QtpReassembler,
    parse_frame_head,
    qtp_unpack,
    tunnel_pack,
    tunnel_unpack,
)

# --- real, complete tunnel datagrams (GOLDEN_MEDIA.log) -----------------------
# login response: inner_len 0x1c, cmd 0x0201, token 9595fe, seq 0xe3, 20-byte body
TUN_LOGIN = bytes.fromhex(
    "80090000201605180000000000000000001c02019595fee3256135a83989003320fb00000000000000000000"
)
# tunnel_req response: inner_len 0x13, cmd 0x0203, token 9595fe, seq 0xe5, 11-byte body
TUN_REQ = bytes.fromhex(
    "80090000201605180000000000000000001302039595fee5256135a839890000000000"
)

# --- real QTP media frame heads (GOLDEN_MEDIA.log, media relay 18.185.227.156:80) ---
QTP_KEYFRAME = bytes.fromhex(
    "c804000400021d001af5000049ec201411040002000049e2"
)  # conv c804 sn 4 una 2 flags 1d00 plen 49ec; app-frame ver00 cls02 len49e2
QTP_PFRAME = bytes.fromhex(
    "c804001400111d001ad6000024172014110400030000240d"
)  # cls 03 (P-frame), len 240d


def test_tunnel_unpack_fields():
    m = tunnel_unpack(TUN_LOGIN)
    assert m is not None
    assert m.cmd == CMD_LOGIN
    assert m.token == bytes.fromhex("9595fe")
    assert m.seq == 0xE3
    assert len(m.body) == 20

    r = tunnel_unpack(TUN_REQ)
    assert r.cmd == CMD_TUNNEL_REQ
    assert r.token == bytes.fromhex("9595fe")
    assert r.seq == 0xE5


def test_tunnel_roundtrip_byte_exact():
    for pkt in (TUN_LOGIN, TUN_REQ):
        assert tunnel_pack(tunnel_unpack(pkt)) == pkt


def test_tunnel_unpack_rejects_non_tunnel():
    assert tunnel_unpack(b"\x00" * 40) is None
    assert tunnel_unpack(b"short") is None


def test_qtp_header_and_frame_head():
    q = qtp_unpack(QTP_KEYFRAME)
    assert q.conv == 0xC804
    assert q.flags == 0x1D00
    assert q.sn == 4 and q.una == 2
    head = parse_frame_head(q.payload)
    assert head is not None
    assert head.cls == 0x02  # keyframe
    assert head.length == 0x49E2

    p = qtp_unpack(QTP_PFRAME)
    assert parse_frame_head(p.payload).cls == 0x03  # P-frame


def _qtp(sn: int, payload: bytes) -> bytes:
    """Build a minimal QTP media datagram (conv c804, flags 1d00) carrying ``payload``."""
    return struct.pack(">HHHHHI", 0xC804, sn, 0, 0x1D00, 0, len(payload)) + payload


def test_qtp_reassembler_concatenates_fragments():
    # A keyframe app-frame (16-byte VCL slice) split across two datagrams reassembles to one frame.
    slice_body = bytes(range(16))
    whole = (
        bytes.fromhex("20141104")
        + bytes([0x00, 0x02])
        + len(slice_body).to_bytes(4, "big")
        + slice_body
    )
    r = QtpReassembler()
    r.feed(qtp_unpack(_qtp(1, whole[:8])))   # lead fragment (carries the 20141104 head)
    assert r.take_frames() == []             # frame not complete yet
    r.feed(qtp_unpack(_qtp(2, whole[8:])))   # tail fragment completes it
    assert r.take_frames() == [(0x02, whole[10:])]   # (class, app-frame body) == the slice
