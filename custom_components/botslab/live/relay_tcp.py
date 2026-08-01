"""TCP relay transport — carries the app-protocol defined in :mod:`relay`.

The relay accepts a real TCP connection on the same address/port it serves UDX on, and the app
supports it (relay_type: 1=udx, 2=tcp, 3=udx_and_tcp). Over TCP the kernel guarantees complete,
in-order, retransmitted delivery, so this module has **no reassembly, window, ACK or reconnect
logic at all** — it reads the byte stream and parses the same ``20141104`` app-frames. That
removes the failure mode of the former UDX path, whose hand-rolled reliable-UDP mis-assembled
large multi-packet keyframes (their tail arrived corrupt, so big keyframes decoded top-only and
washed out). The app delegates that job to a reliable-UDP library, so letting TCP do it instead
avoids reimplementing it.

What is still required, exactly as on the UDX path: the app-frame **length fields cannot be
trusted** (a media frame's declared length, and the device's own length at body 0x30, can overrun
into the following frames). Frames are therefore bounded by resyncing on the device frame header
``00 00 00 00 00 03 <seq16>`` that starts every media app-frame body.

The wire framing over TCP is auto-detected on first bytes (see :meth:`_detect_framing`): either the
app-frames are written raw, or each is wrapped in the same 14-byte QTP header used on UDX (whose
sequencing/ACK fields are redundant here because TCP already orders the stream).
"""

from __future__ import annotations

import contextlib
import logging
import socket
import struct

from .relay import (
    APP_MAGIC,
    APP_VER,
    C_CONFIG,
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

# Every media app-frame body starts with this device frame header; requiring it distinguishes a real
# frame boundary from a coincidental 20141104 inside encrypted slice ciphertext.
_DEV_HDR = b"\x00\x00\x00\x00\x00\x03"
_APP_CLASSES = frozenset({C_LOGIN, C_MEDIA, 0x03, C_CONFIG, C_START, 0x0A, C_LOGIN_RESP})
_QTP_HDR = 14
_RECV = 1 << 16


class TcpRelayClient:
    """Read decrypted-ready app-frames from the relay over TCP."""

    def __init__(self, relay: tuple[str, int], stream_id: str, ukey: str,
                 cluster: str, product_key: str) -> None:
        self.relay, self.stream_id, self.ukey = relay, stream_id, ukey
        self.cluster, self.product_key = cluster, product_key
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(5.0)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self._stream = bytearray()
        self._qtp_framed: bool | None = None   # None until detected on the first bytes
        self._sn = 0
        self.conv = 0

    # ------------------------------------------------------------------ connect / login
    def connect(self) -> bool:
        try:
            self.sock.connect(self.relay)
        except OSError as err:
            _LOGGER.debug("tcp relay connect failed: %s", err)
            return False
        return True

    def _wrap(self, frame: bytes) -> bytes:
        """Frame an outgoing app-frame for the wire (QTP header only if the peer uses one)."""
        if not self._qtp_framed:
            return frame
        self._sn += 1
        flags = 0x1D00 | 0x02
        cks = qtp_checksum(self.conv, self._sn, 0, flags)
        return struct.pack(">HHHHHI", self.conv, self._sn, 0, flags, cks, len(frame)) + frame

    def _send(self, frame: bytes) -> None:
        with contextlib.suppress(OSError):
            self.sock.sendall(self._wrap(frame))

    def login(self, retries: int = 2) -> bool:
        """Send the class 0x01 login and wait for the 0x69 result.

        The outgoing framing is unknown until the peer replies, so the raw form is tried first and
        the QTP-wrapped form second; whichever draws a reply also fixes ``_qtp_framed`` for reads.
        """
        frame = build_login(self.stream_id, self.ukey, self.cluster, self.product_key)
        for attempt in range(retries):
            self._qtp_framed = bool(attempt)          # attempt 0 raw, attempt 1 QTP-wrapped
            self._send(frame)
            if (ok := self._await_login()) is not None:
                return ok
        return False

    def _await_login(self, timeout: float = 3.0) -> bool | None:
        """Read until a login result arrives. None = no intelligible reply (try other framing)."""
        self.sock.settimeout(timeout)
        while True:
            try:
                chunk = self.sock.recv(_RECV)
            except (TimeoutError, OSError):
                return None
            if not chunk:
                return None
            self._stream += chunk
            self._detect_framing()
            for f in self.take_frames():
                if f.cls == C_LOGIN_RESP:
                    return f.tlvs.get(T_RESULT) == b"\x00\x00\x00\x00"
                if f.cls == C_MEDIA:                  # some relays start media immediately
                    return True

    def start(self) -> None:
        self._send(build_start())

    # ------------------------------------------------------------------ framing
    def _detect_framing(self) -> None:
        """Decide once whether the peer wraps app-frames in the 14-byte QTP header."""
        if self._qtp_framed is not None and self._stream:
            # confirm/repair the guess from what actually arrived
            if self._stream[:4] == APP_MAGIC:
                self._qtp_framed = False
            elif len(self._stream) >= _QTP_HDR + 4 and \
                    bytes(self._stream[_QTP_HDR:_QTP_HDR + 4]) == APP_MAGIC:
                self._qtp_framed = True
                self.conv = struct.unpack_from(">H", self._stream, 0)[0]

    def _strip_qtp(self) -> None:
        """Drop QTP headers so ``_stream`` holds a pure app-frame byte stream."""
        if not self._qtp_framed:
            return
        while len(self._stream) >= _QTP_HDR:
            if bytes(self._stream[:4]) == APP_MAGIC:      # already unwrapped
                return
            plen = struct.unpack_from(">I", self._stream, 10)[0]
            if len(self._stream) < _QTP_HDR + plen:
                return
            del self._stream[:_QTP_HDR]        # header consumed; payload joins the stream
            return

    def _next_frame(self, start: int) -> int:
        """Offset of the next genuine app-frame at/after ``start`` (see module docstring)."""
        s = self._stream
        j = s.find(APP_MAGIC, start)
        while j != -1:
            if j + 16 <= len(s) and s[j + 4] == APP_VER and s[j + 5] in _APP_CLASSES and (
                    s[j + 5] not in (C_MEDIA, 0x03) or bytes(s[j + 10:j + 16]) == _DEV_HDR):
                return j
            j = s.find(APP_MAGIC, j + 4)
        return -1

    def take_frames(self) -> list[AppFrame]:
        """Return every complete app-frame currently buffered.

        Lengths are not trusted: each frame is capped at the next genuine app-frame boundary, since
        a media frame can declare a length that overruns into the frames that follow it.
        """
        out: list[AppFrame] = []
        while True:
            self._strip_qtp()
            i = self._next_frame(0)
            if i < 0:
                if len(self._stream) > (1 << 21):
                    del self._stream[:-3]
                break
            if i + 10 > len(self._stream):
                break
            ln = struct.unpack_from(">I", self._stream, i + 6)[0]
            end = i + 10 + ln
            nxt = self._next_frame(i + 16)
            if nxt != -1 and nxt < end:
                end = nxt
            elif end > len(self._stream):
                break                                     # not fully arrived yet
            out.append(AppFrame(self._stream[i + 5], bytes(self._stream[i + 10:end])))
            del self._stream[:end]
        return out

    def drain(self, max_reads: int = 1024) -> list[AppFrame]:
        """Empty the socket's receive queue and return the app-frames it completed.

        Reads until the (non-blocking) socket is drained rather than once per call, so a burst that
        spans many segments — a keyframe is tens of KB — is parsed in the pass that delivered it.
        """
        for _ in range(max_reads):
            try:
                chunk = self.sock.recv(_RECV)
            except (TimeoutError, BlockingIOError):
                break
            except OSError:
                break
            if not chunk:
                break
            self._stream += chunk
            self._detect_framing()
        return self.take_frames()

    def close(self) -> None:
        with contextlib.suppress(OSError):
            self.sock.close()
