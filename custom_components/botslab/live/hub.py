"""Direct-to-hub QTP/UDX video transport — the app's real live-video path.

The battery doorbell streams through an always-on **hub** (base station) on the LAN. The app opens
a QTP/FastUdx (reliable-UDP) connection straight to the hub and receives the full video there; the
cloud relay only carries audio once a LAN viewer is active (its ``req_relay_res`` returns
``flag:0``). Home Assistant, on the same LAN (e.g. a Synology NAS), can do the same.

On the wire the hub media is the SAME ``20 14 11 04`` app-protocol as the cloud relay — class 0x02
keyframe / 0x03 P-frame / 0x0a audio, ver 0x00, device header + key index (BE @0x2c) + Annex-B AU
@0x38 — so the existing :mod:`engine` media handler and ChaCha decrypt consume it unchanged. Only
the transport differs: QTP over UDP to the hub instead of TCP to the relay. This reuses the QTP
reliable-UDP client used for the relay; on the LAN loss/reorder is minimal,
so its simple reassembly does not hit the WAN washout it had over the cloud.

The hub's LAN address arrives in ``req_relay_res``'s ``la`` field (little-endian u32 IP + port); the
engine parses it into ``hub_addr`` and hands it here.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
import secrets
import socket
import struct

from .relay import (
    APP_MAGIC,
    APP_VER,
    C_LOGIN,
    C_LOGIN_RESP,
    C_MEDIA,
    C_START,
    T_RESULT,
    AppFrame,
    build_login,
    build_start,
    qtp_checksum,
)

_DEV_HDR = b"\x00\x00\x00\x00\x00\x03"
_APP_CLASSES = frozenset({C_LOGIN, C_MEDIA, 0x03, 0x05, C_START, 0x0A, C_LOGIN_RESP})


def qtp_pack(conv: int, sn: int, una: int, cmd: int, payload: bytes) -> bytes:
    """14-byte QTP header + payload. flags = 0x1d00 | cmd (0x02 = data-push on the client side)."""
    flags = 0x1D00 | (cmd & 0xFF)
    cks = qtp_checksum(conv, sn, una, flags)
    return struct.pack(">HHHHHI", conv, sn, una, flags, cks, len(payload)) + payload


@dataclass
class QtpPacket:
    conv: int
    sn: int
    una: int
    flags: int
    payload: bytes


def qtp_unpack(buf: bytes) -> QtpPacket:
    conv, sn, una, flags = struct.unpack_from(">HHHH", buf, 0)
    if len(buf) < 14:  # 10-byte control/ACK packet (no plen field)
        return QtpPacket(conv, sn, una, flags, b"")
    plen = struct.unpack_from(">I", buf, 10)[0]
    return QtpPacket(conv, sn, una, flags, buf[14:14 + plen])


class HubClient:
    """QTP/UDX client to the hub, yielding the same app-frames the cloud relay does.

    Mirrors the engine-facing surface of :class:`~.relay_tcp.TcpRelayClient` — ``connect``,
    ``login``, ``start``, ``drain``, ``close`` — plus the reliable-UDP reassembly and window ACKs
    the UDP transport needs (which TCP handled for the relay).
    """

    def __init__(self, hub_addr: tuple[str, int], stream_id: str, ukey: str,
                 cluster: str, product_key: str) -> None:
        self.hub, self.stream_id, self.ukey = hub_addr, stream_id, ukey
        self.cluster, self.product_key = cluster, product_key
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        with contextlib.suppress(OSError):
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
        self.sock.settimeout(3.0)
        self.conv = 0            # assigned by handshake()
        self.own_id = 0
        self.sn = 0
        self.peer_sn = 0
        # reliable-UDP reassembly (a keyframe spans ~20 QTP DATA packets)
        self._seg: dict[int, bytes] = {}
        self._rcv_nxt = 0
        self._rcv_max = 0
        self._stream = bytearray()

    # ------------------------------------------------------------------ connect / handshake
    def connect(self) -> bool:
        with contextlib.suppress(OSError):
            self.sock.connect(self.hub)
            return True
        return False

    def _control(self, cmd: int, conv: int, own_id_field: int, ts_echo: int = 0,
                 my_ts: int = 0x11223344) -> bytes:
        """48-byte QTP control packet (channel 0, flags 0x0c00) — the SYN/ACK handshake carrier."""
        flags = 0x0C00
        b = bytearray(48)
        struct.pack_into(">HHHH", b, 0, conv, 0, cmd, flags)
        struct.pack_into(">H", b, 8, qtp_checksum(conv, 0, cmd, flags))
        struct.pack_into("<H", b, 0x0A, socket.AF_INET)
        struct.pack_into(">H", b, 0x0C, self.hub[1])
        b[0x0E:0x12] = bytes(int(x) for x in self.hub[0].split("."))
        struct.pack_into(">H", b, 0x1A, own_id_field)
        struct.pack_into(">I", b, 0x1E, my_ts)
        struct.pack_into(">I", b, 0x22, ts_echo)
        b[0x26] = 0x01
        return bytes(b)

    @staticmethod
    def _swap(v: int) -> int:
        return struct.unpack("<H", struct.pack(">H", v))[0]

    def handshake(self) -> bool:
        """4-way QTP handshake: SYN -> SYN-ACK -> ACK; conv/id byteswapped in the data phase."""
        self.own_id = struct.unpack(">H", secrets.token_bytes(2))[0]
        self.sock.send(self._control(0x0001, 0x0000, self.own_id))
        try:
            data = self.sock.recv(2048)
        except (TimeoutError, OSError):
            return False
        self.conv = self._swap(struct.unpack_from(">H", data, 0x1A)[0])
        relay_ts = struct.unpack_from(">I", data, 0x22)[0]
        self.sock.send(self._control(0x0003, self.conv, self._swap(self.own_id), ts_echo=relay_ts))
        return self.conv != 0

    # ------------------------------------------------------------------ login / stream
    def _send_app(self, cmd: int, frame: bytes) -> None:
        self.sn += 1
        with contextlib.suppress(OSError):
            self.sock.send(qtp_pack(self.conv, self.sn, self.peer_sn, cmd, frame))

    def _ack(self) -> None:
        with contextlib.suppress(OSError):
            self.sock.send(qtp_pack(self.conv, self.sn, self.peer_sn, 0x02, b""))

    def flow_ack(self) -> None:
        """0x1120 flow-control ACK crediting the hub's send window (byte-exact from the app)."""
        sn = self._rcv_max or self._rcv_nxt
        una = self._rcv_nxt
        cks = qtp_checksum(self.conv, sn, una, 0x1120)
        pkt = (struct.pack(">HHHHH", self.conv, sn, una, 0x1120, cks)
               + struct.pack("<I", una) + b"\x00\x00")
        with contextlib.suppress(OSError):
            self.sock.send(pkt)

    def login(self, retries: int = 4) -> bool:
        frame = build_login(self.stream_id, self.ukey, self.cluster, self.product_key)
        for _ in range(retries):
            self._send_app(0x02, frame)
            self.sock.settimeout(2.0)
            try:
                data = self.sock.recv(4096)
            except (TimeoutError, OSError):
                continue
            pkt = qtp_unpack(data)
            self.peer_sn = max(self.peer_sn, pkt.sn)
            self._ack()
            f = _parse_app(pkt.payload)
            if f and f.cls == C_LOGIN_RESP:
                return f.tlvs.get(T_RESULT) == b"\x00\x00\x00\x00"
            if f and f.cls == C_MEDIA:
                return True
        return False

    def start(self) -> None:
        self._send_app(0x02, build_start())
        self._ack()

    # ------------------------------------------------------------------ receive / reassemble
    def absorb(self, pkt: QtpPacket) -> None:
        """Feed a received QTP packet into the reassembly buffer, advancing the cumulative ACK."""
        if not pkt.payload:
            if self._rcv_nxt:
                self.peer_sn = self._rcv_nxt
            return
        self._seg[pkt.sn] = pkt.payload
        self._rcv_max = max(self._rcv_max, pkt.sn)
        if self._rcv_nxt == 0 and 1 in self._seg:
            self._rcv_nxt = 1
            self._stream += self._seg.pop(1)
        while (self._rcv_nxt + 1) in self._seg:
            self._rcv_nxt += 1
            self._stream += self._seg.pop(self._rcv_nxt)
        if len(self._seg) > 8192:
            self._seg.clear()
        self.peer_sn = self._rcv_nxt if self._rcv_nxt else pkt.sn

    def _next_frame(self, start: int) -> int:
        s = self._stream
        j = s.find(APP_MAGIC, start)
        while j != -1:
            if j + 16 <= len(s) and s[j + 4] == APP_VER and s[j + 5] in _APP_CLASSES and (
                    s[j + 5] not in (C_MEDIA, 0x03) or bytes(s[j + 10:j + 16]) == _DEV_HDR):
                return j
            j = s.find(APP_MAGIC, j + 4)
        return -1

    def take_frames(self) -> list[AppFrame]:
        out: list[AppFrame] = []
        while True:
            i = self._next_frame(0)
            if i < 0:
                if len(self._stream) > (1 << 20):
                    del self._stream[:-3]
                break
            if i + 10 > len(self._stream):
                break
            ln = struct.unpack_from(">I", self._stream, i + 6)[0]
            end = i + 10 + ln
            nxt = self._next_frame(i + 16)
            if nxt != -1 and nxt < end:
                end = nxt
            elif nxt == -1 and end > len(self._stream):
                break
            out.append(AppFrame(self._stream[i + 5], bytes(self._stream[i + 10:end])))
            del self._stream[:end]
        return out

    def drain(self, max_reads: int = 1024) -> list[AppFrame]:
        """Read queued QTP packets, absorb + ACK them, and return completed app-frames."""
        for _ in range(max_reads):
            try:
                data = self.sock.recv(1 << 16)
            except (TimeoutError, BlockingIOError, OSError):
                break
            if not data:
                break
            self.absorb(qtp_unpack(data))
            self.flow_ack()
        return self.take_frames()

    def close(self) -> None:
        with contextlib.suppress(OSError):
            self.sock.close()


def _parse_app(payload: bytes) -> AppFrame | None:
    if payload[:4] != APP_MAGIC:
        return None
    ln = struct.unpack_from(">I", payload, 6)[0]
    return AppFrame(payload[5], payload[10:10 + ln])
