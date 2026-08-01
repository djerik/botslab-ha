"""Wire codecs for the two protocols the app uses to fetch live video from the cloud.

Verified byte-exact against sample traffic (the codecs round-trip against every sample
packet). Two layers:

* **Tunnel (``8009``)** — the signaling/tracker layer (UDP to the tracker and to the
  :8080/:8443 relays). Fixed 16-byte header then a length/cmd/token/seq envelope. Carries
  login, registration, key delivery and the play request that sets up a media session.
* **QTP media** — the media-relay layer (UDP to the assigned relay on :80). A 14-byte
  reliable-UDP header then the app media frame (``20141104`` magic, class 0x02 keyframe /
  0x03 P-frame). This is the same frame the cloud TCP relay delivers, so the existing
  decrypt/decode path consumes it unchanged.

Only the codecs live here (no I/O, no HA imports) so they stay unit-testable against sample
bytes. The session state machine that drives them is built on top once the media-relay
handshake is characterised with the port-80 packets included.
"""

from __future__ import annotations

from dataclasses import dataclass
import struct

# ---------------------------------------------------------------- tunnel (8009)
# The 16-byte fixed header: an 8-byte signature/version constant then 8 zero bytes. In the
# native lib this is the constant the tunnel builder reads as its per-message preamble.
TUNNEL_MAGIC = bytes.fromhex("8009000020160518") + b"\x00" * 8

# cmd codes seen on the wire (BE u16 at offset 0x12). Names follow the native tunnel dispatch.
CMD_LOGIN = 0x0201
CMD_TUNNEL_REQ = 0x0203
CMD_TUNNEL_REG = 0x0204   # body: "<machineId>_2"
CMD_TN_A = 0x0210
CMD_TN_B = 0x0211
CMD_TN_LIST = 0x0220      # relay/peer list (idle bodies are all-zero)
CMD_KEY_A = 0x0230        # body: "<product_key>/<sn>" + machineId
CMD_KEY_B = 0x0231
CMD_PLAY = 0x0301         # body: 07 <u32 play_type> <u32 code> <u16> 07 <machineId>
CMD_REGISTER = 0x0401


@dataclass
class TunnelMsg:
    cmd: int
    token: bytes   # 3-byte server-assigned session token (zero before the server assigns one)
    seq: int       # 1-byte sequence, increments per message
    body: bytes


def tunnel_pack(msg: TunnelMsg) -> bytes:
    """Serialise a :class:`TunnelMsg` to the exact on-wire bytes."""
    # token(3)+seq(1)+body, plus the 4 bytes of cmd already counted by the framing.
    inner_len = 8 + len(msg.body)
    return (TUNNEL_MAGIC
            + struct.pack(">H", inner_len)
            + struct.pack(">H", msg.cmd)
            + msg.token[:3].ljust(3, b"\x00")
            + bytes([msg.seq & 0xFF])
            + msg.body)


def tunnel_unpack(buf: bytes) -> TunnelMsg | None:
    """Parse a tunnel datagram, or ``None`` if it is not one."""
    if len(buf) < 0x18 or buf[:8] != TUNNEL_MAGIC[:8]:
        return None
    inner_len = struct.unpack_from(">H", buf, 0x10)[0]
    cmd = struct.unpack_from(">H", buf, 0x12)[0]
    token = buf[0x14:0x17]
    seq = buf[0x17]
    body = buf[0x18:0x18 + max(0, inner_len - 8)]
    return TunnelMsg(cmd=cmd, token=token, seq=seq, body=body)


def build_tunnel_register(machine_id: str, seq: int, token: bytes = b"") -> bytes:
    """The registration/keepalive the app sends to the tracker (cmd 0x0401) and relays (0x0204)."""
    body = f"{machine_id}_2".encode() + b"\x00\x00"
    return tunnel_pack(TunnelMsg(CMD_REGISTER, token, seq, body))


def build_tunnel_play(machine_id: str, seq: int, token: bytes,
                      play_type: int = 1, code: int = 0x2714) -> bytes:
    """The play request (cmd 0x0301) that asks the relay to start a media session.

    Body layout observed: ``07 <u32 play_type> <u32 code> <u16=1> 07 <machineId>``. ``code`` 0x2714
    (10004) is the value the app sent; its meaning (channel/profile) is not yet pinned down.
    """
    body = (b"\x07" + struct.pack(">I", play_type) + struct.pack(">I", code)
            + struct.pack(">H", 1) + b"\x07" + machine_id.encode())
    return tunnel_pack(TunnelMsg(CMD_PLAY, token, seq, body))


# ---------------------------------------------------------------- QTP media (:80)
APP_MAGIC = bytes.fromhex("20141104")
FLAGS_MEDIA = 0x1D00   # media DATA (the cloud TCP relay used 0x1d02; low byte is the sub-cmd)


@dataclass
class QtpPacket:
    conv: int
    sn: int
    una: int
    flags: int
    cksum: int
    plen: int
    payload: bytes


def qtp_unpack(buf: bytes) -> QtpPacket | None:
    """Parse a QTP media datagram from the relay."""
    if len(buf) < 14:
        return None
    conv, sn, una, flags, cksum = struct.unpack_from(">HHHHH", buf, 0)
    plen = struct.unpack_from(">I", buf, 10)[0]
    return QtpPacket(conv, sn, una, flags, cksum, plen, buf[14:])


@dataclass
class AppFrameHead:
    ver: int
    cls: int          # 0x02 keyframe, 0x03 P-frame, 0x0a audio
    length: int       # full app-frame body length (frame is fragmented across QTP datagrams)


def parse_frame_head(payload: bytes) -> AppFrameHead | None:
    """If this QTP payload begins a new app frame, return its head; else ``None`` (continuation)."""
    if payload[:4] != APP_MAGIC or len(payload) < 10:
        return None
    return AppFrameHead(ver=payload[4], cls=payload[5],
                        length=struct.unpack_from(">I", payload, 6)[0])


class QtpReassembler:
    """Order media datagrams by ``sn`` and concatenate payloads into whole app frames.

    A large frame (a keyframe is ~19 KB) is split across ~14 datagrams; only the first carries the
    ``20141104`` magic. We buffer by sn, then walk the concatenated stream splitting on the frame
    length declared in each head. Mirrors what the cloud TCP relay handler did with in-order
    TCP bytes.
    """

    def __init__(self) -> None:
        self._seg: dict[int, bytes] = {}
        self._next: int | None = None
        self._buf = bytearray()

    def feed(self, pkt: QtpPacket) -> None:
        if not pkt.payload:
            return
        self._seg[pkt.sn] = pkt.payload
        if self._next is None:
            self._next = min(self._seg)
        while self._next in self._seg:
            self._buf += self._seg.pop(self._next)
            self._next += 1

    def take_frames(self) -> list[tuple[int, bytes]]:
        """Return completed ``(cls, app_frame_body)`` tuples, consuming them from the buffer."""
        out: list[tuple[int, bytes]] = []
        while True:
            head = parse_frame_head(self._buf)
            if head is None:
                break
            end = 10 + head.length
            if len(self._buf) < end:
                break
            out.append((head.cls, bytes(self._buf[10:end])))
            del self._buf[:end]
        return out
