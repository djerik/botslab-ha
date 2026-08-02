"""QTP/UDX (reliable-UDP) transport to the cloud media relay — the leg that carries the video.

Class named ``HubClient`` for historical reasons: the app can also reach an always-on **hub** (base
station) on the LAN, and this client was first written for that. In this integration it dials the
same cloud relay (``sched["relay"]``, e.g. ``18.185.227.156:80``) the TCP leg uses, over QTP/UDP
instead of TCP — and that is the difference that matters: the device forwards the **video** (class
0x02/0x03) over QTP while the TCP relay leg (:mod:`relay_tcp`) gets only **audio** (class 0x0a).

On the wire the media is the SAME ``20 14 11 04`` app-protocol either way — class 0x02 keyframe /
0x03 P-frame / 0x0a audio, ver 0x00, device header + key index (BE @0x2c) + Annex-B AU @0x38 — so
the existing :mod:`engine` media handler and ChaCha decrypt consume it unchanged. Only the transport
differs, so this client adds the reliable-UDP reassembly + window ACKs that TCP handled for the
relay: QTP is lossy over the WAN, hence the gap-skip/resync in ``absorb``/``take_frames``.

(The LAN hub's own address is advertised in ``req_relay_res``'s ``la`` field, but we do not use it —
the cloud relay carries the video fine, so there is no dependency on being on the doorbell's LAN.)
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
import logging
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

_LOGGER = logging.getLogger(__name__)

_DEV_HDR = b"\x00\x00\x00\x00\x00\x03"
_APP_CLASSES = frozenset({C_LOGIN, C_MEDIA, 0x03, 0x05, C_START, 0x0A, C_LOGIN_RESP})
# Datagrams piled up behind a missing sn before we give up on it and skip the gap. A keyframe is
# ~14 datagrams, so this is comfortably past "reordered" and squarely "lost" without discarding a
# whole keyframe's worth of buffered data.
_GAP_SKIP = 48


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
    """Parse a QTP datagram. The QTP header is **10 bytes** (conv/sn/una/flags/cksum); the payload
    is everything after it. Only the FIRST datagram of an app-frame carries a 4-byte app-frame
    length prefix + the ``20141104`` header at payload[4:]; continuation datagrams carry raw
    ciphertext at payload[0:]. Taking ``buf[14:]`` (as if every datagram had a 4-byte plen field)
    dropped 4 ciphertext bytes per continuation datagram, desynchronising the per-slice ChaCha
    keystream a few datagrams in — the "top decodes, rest green" bug. The app-frame length prefix
    is harmless: the frame parsers resync on the ``20141104`` magic."""
    conv, sn, una, flags = struct.unpack_from(">HHHH", buf, 0)
    return QtpPacket(conv, sn, una, flags, buf[10:])


class HubClient:
    """QTP/UDX client to the cloud media relay, yielding the same app-frames the TCP leg does.

    Mirrors the engine-facing surface of :class:`~.relay_tcp.TcpRelayClient` — ``connect``,
    ``login``, ``start``, ``drain``, ``close`` — plus the reliable-UDP reassembly and window ACKs
    the UDP transport needs (which TCP handled for the relay). See the module docstring for why the
    class is called ``HubClient`` despite dialing the relay.
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
        self._gaps: list[int] = []   # byte offsets in _stream where a lost datagram was skipped

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

    def handshake(self, retries: int = 3) -> bool:
        """4-way QTP handshake: SYN -> SYN-ACK -> ACK; conv/id byteswapped in the data phase.

        The SYN and its SYN-ACK are each a single UDP datagram, so one lost packet would fail the
        whole video leg (observed as a 3s timeout, then a blank stream). Resend the SYN a few times
        with a short per-try timeout so a transient loss is recovered here rather than costing the
        session its video.
        """
        self.own_id = struct.unpack(">H", secrets.token_bytes(2))[0]
        self.sock.settimeout(1.0)
        for _ in range(retries):
            try:
                self.sock.send(self._control(0x0001, 0x0000, self.own_id))
                data = self.sock.recv(2048)
            except (TimeoutError, OSError):
                continue
            if len(data) < 0x26:  # stray/short datagram — ignore and resend
                continue
            self.conv = self._swap(struct.unpack_from(">H", data, 0x1A)[0])
            relay_ts = struct.unpack_from(">I", data, 0x22)[0]
            self.sock.send(
                self._control(0x0003, self.conv, self._swap(self.own_id), ts_echo=relay_ts))
            if self.conv != 0:
                return True
        return False

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

    def login(self, retries: int = 3) -> bool:
        frame = build_login(self.stream_id, self.ukey, self.cluster, self.product_key)
        for attempt in range(retries):
            self._send_app(0x02, frame)
            self.sock.settimeout(2.0)
            # The hub answers a login with several packets (a control echo, a flow ACK, then the
            # login-response app-frame), so read a few before re-sending rather than one recv.
            for _ in range(8):
                try:
                    data = self.sock.recv(4096)
                except (TimeoutError, OSError):
                    break
                pkt = qtp_unpack(data)
                self.peer_sn = max(self.peer_sn, pkt.sn)
                self._ack()
                f = _parse_app(pkt.payload)
                if f is None:
                    _LOGGER.debug("hub login[%d]: %dB flags=%#06x (control/ack)",
                                  attempt, len(data), pkt.flags)
                    continue
                _LOGGER.debug("hub login[%d] resp: cls=%#x body=%s tlvs=%s", attempt, f.cls,
                              f.body[:40].hex(), {hex(k): v.hex() for k, v in f.tlvs.items()})
                # The relay answers with cls 0x69 (C_LOGIN_RESP) + a T_RESULT TLV; the hub answers
                # with cls 0x01 (it echoes the login class) and no T_RESULT. Accept either: require
                # result==0 when a T_RESULT is present, else treat the app-frame reply as the ack.
                if f.cls in (C_LOGIN_RESP, C_LOGIN):
                    return f.tlvs.get(T_RESULT) in (None, b"\x00\x00\x00\x00")
                if f.cls == C_MEDIA:
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
        if self._rcv_nxt and pkt.sn <= self._rcv_nxt:
            return  # already consumed (stale/duplicate) — dropping it keeps min(_seg) ahead of us
        self._seg[pkt.sn] = pkt.payload
        self._rcv_max = max(self._rcv_max, pkt.sn)
        # Start from the lowest sn we have seen (the relay's first data sn is not always 1).
        if self._rcv_nxt == 0 and self._seg:
            self._rcv_nxt = min(self._seg) - 1
        self._drain_ordered()
        # Loss recovery: the relay does NOT retransmit, so a lost datagram would stall the in-order
        # stream forever (segments pile up, get dumped at 8192, and nothing ever parses -> media=0).
        # Once enough later datagrams have piled up behind the gap, skip the missing sn(s) and
        # resync; take_frames re-locks on the next frame's 20141104 magic, so only the frame
        # spanning the gap is lost (the next keyframe restores the picture) instead of the session.
        # Stale packets are dropped above, so min(_seg) is always the next real segment ahead of us.
        if len(self._seg) > _GAP_SKIP:
            nxt = min(self._seg)
            if nxt - self._rcv_nxt > 1:
                self._gaps.append(len(self._stream))  # discontinuity lands here in the byte stream
                self._rcv_nxt = nxt - 1
                self._drain_ordered()
        if len(self._seg) > 8192:
            self._seg.clear()
        self.peer_sn = self._rcv_nxt if self._rcv_nxt else pkt.sn

    def _drain_ordered(self) -> None:
        """Append every in-order buffered segment, advancing the receive cursor."""
        while (self._rcv_nxt + 1) in self._seg:
            self._rcv_nxt += 1
            self._stream += self._seg.pop(self._rcv_nxt)

    def _consume(self, k: int) -> None:
        """Drop ``k`` leading bytes from the stream, shifting the recorded gap offsets with it."""
        del self._stream[:k]
        if self._gaps:
            self._gaps = [g - k for g in self._gaps if g - k > 0]

    def _find_keyframe(self, start: int) -> int:
        """Offset of the next class-0x02 (keyframe) app-frame head at/after ``start``, or -1."""
        s = self._stream
        j = s.find(APP_MAGIC, start)
        while j != -1:
            if j + 10 <= len(s) and s[j + 4] == APP_VER and s[j + 5] == C_MEDIA:
                return j
            j = s.find(APP_MAGIC, j + 4)
        return -1

    def take_frames(self) -> list[AppFrame]:
        """Split the reassembled stream into app-frames, trusting each frame's declared length.

        A keyframe spans ~14 QTP datagrams; only the first carries the ``20141104`` magic and the
        rest are raw ciphertext continuation. Once locked onto a real frame head we consume exactly
        its declared length and land on the next head — so spurious ``20141104`` sequences inside
        the encrypted video body are never scanned. The old splitter capped each frame at the next
        magic it could find, which truncated every multi-datagram video keyframe (a magic almost
        always occurs inside ~19 KB of ciphertext) and left only single-datagram audio surviving —
        the "audio only, no class 0x02/0x03" symptom. We only resync (scan for a magic) when the
        buffer is not positioned on a valid head, e.g. across the login/control bytes up front.
        """
        out: list[AppFrame] = []
        s = self._stream
        while len(s) >= 10:
            if s[:4] == APP_MAGIC and s[4] == APP_VER and s[5] in _APP_CLASSES:
                ln = struct.unpack_from(">I", s, 6)[0]
                if ln <= (1 << 21):
                    end = 10 + ln
                    if len(s) < end:
                        break                       # frame still arriving over more datagrams
                    # A frame straddling a skipped-gap discontinuity is corrupt (missing bytes).
                    # Resync forward to the next KEYFRAME (class 0x02) — a self-contained restart —
                    # rather than the next magic, which could be spurious inside the corrupt region.
                    # This freezes for one GOP (~1-2s) but emits no garbage NAL to the decoder.
                    if any(0 < g < end for g in self._gaps):
                        kf = self._find_keyframe(4)
                        if kf < 0:
                            break                   # no clean keyframe buffered yet — wait for one
                        self._consume(kf)
                        continue
                    out.append(AppFrame(s[5], bytes(s[10:end])))
                    self._consume(end)
                    continue
            # Not positioned on a valid app-frame head — resync to the next magic.
            j = s.find(APP_MAGIC, 1)
            if j < 0:
                if len(s) > (1 << 20):
                    self._consume(len(s) - 3)
                break
            self._consume(j)
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
            pkt = qtp_unpack(data)
            # Only reassemble media DATA (flags 0x1d00); control/ACK packets share neither the sn
            # space nor the payload framing and would corrupt the sn-ordered stream.
            if pkt.flags == 0x1D00:
                self.absorb(pkt)
            self.flow_ack()
        return self.take_frames()

    def close(self) -> None:
        with contextlib.suppress(OSError):
            self.sock.close()


def _parse_app(payload: bytes) -> AppFrame | None:
    # The first datagram's payload leads with a 4-byte app-frame length prefix, so find the magic
    # rather than requiring it at offset 0 (see qtp_unpack).
    i = payload.find(APP_MAGIC)
    if i < 0 or i + 10 > len(payload):
        return None
    ln = struct.unpack_from(">I", payload, i + 6)[0]
    return AppFrame(payload[i + 5], payload[i + 10:i + 10 + ln])
