"""GodSees P2P-tunnel signalling client (UDP :8080) — the publish trigger.

The trigger is the UDP P2P tunnel:

  1. UDP to p2p_tunnel_servers (from cloud_control).
  2. OPEN  : path=0x03 type=0x01 (first frame carries the uuid + product_id/sn).
  3. CONNECT: path=0x02 type=0x04; server echoes type=0x04.
  4. keepalive path=0x02 type=0x20; direct-register path=0x04 type=0x01.
  5. XMSG  : path=0x02 type=0x30, 0x94-byte header + JSON content; server acks type=0x31 and the
     DEVICE responds with its own type=0x30. Content JSON = the {model,data,sn,...} envelope.

clientUUID is the stable app machineId the device already knows.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import secrets
import socket
import struct
import time
import uuid as _uuid

MAGIC = bytes.fromhex("8009000020160518")

# The app tags every signalling message with two identities: a machineId UUID (``requester_ctx``)
# and an opaque identity hash (``requester_id``). Each install derives its own stable pair from
# ``m2``, the persisted per-install secret, and registers the machineId with the account via
# schedule_2 (see schedule.register_viewer). This keeps every install distinct under its own
# account instead of shipping one captured identity.
#
# OPEN: the device only forwards the live *video* substream (req_relay_res flag:1) to a machineId
# it recognises as the authorised viewer; an unknown one gets audio only (flag:0). schedule_2
# registers our machineId server-side (HTTP 200), but it is not yet confirmed that a self-registered
# machineId is then authorised for video by the device — that needs a capture of a working live-open
# on this account to see the full authorisation the app performs.
_UUID_NS = _uuid.UUID("6ba7b811-9dad-11d1-80b4-00c04fd430c8")  # RFC 4122 URL namespace


def machine_id(m2: str) -> str:
    """Stable per-install machineId UUID (the ``requester_ctx`` identity)."""
    return str(_uuid.uuid5(_UUID_NS, f"botslab-machine-id:{m2}"))


def requester_id(m2: str) -> str:
    """Stable per-install ``requester_id`` (32-hex identity + the app's ``_1`` client tag)."""
    return hashlib.md5(f"botslab-requester:{m2}".encode()).hexdigest() + "_1"  # noqa: S324


def _wrap(path: int, typ: int, conv: int, payload: bytes) -> bytes:
    body = struct.pack(">BBI", path, typ, conv) + payload
    return MAGIC + b"\x00" * 8 + struct.pack(">H", len(body) + 2) + body


def uuid_field(uuid: str, chan: int = 2) -> bytes:
    b = f"{uuid}_{chan}".encode()
    return b + b"\x00" * (40 - len(b))


def route_field(product_id: str, sn: str) -> bytes:
    b = f"{product_id}/{sn}".encode()
    return b + b"\x00" * (40 - len(b))


# Player parameters the app sends verbatim in req_relay (pct/bitrate/os/ver...); no identity here.
# token: the app's live path populates this with the getRelaySign uSign (transfer_token); the
# subscribe path leaves it empty.
DEFAULT_PLAY_TYPE_AUX = (
    "eyJwY3QiOjMsICJiaXRyYXRlIjoxLCAib3MiOiIxIiwgImYiOjAsICJyZmQiOjAsICJzcCI6MCwg"
    "InZmcyI6MCwgIm1jIjoiIiwgInZlciI6IjIyMDgwMiJ9"
)


def build_reqrelay_inner(sn: str, requester_id: str, requester_ctx_uuid: str, *,
                         channel_no: int = 1, play_type: int = 1,
                         play_type_aux: str = DEFAULT_PLAY_TYPE_AUX, cts: int | None = None,
                         token: str = "") -> str:
    """req_relay inner JSON. ``token`` = the getRelaySign uSign (transfer_token path)."""
    if cts is None:
        cts = int(time.time() * 1000)
    return json.dumps({
        "model": "netsdk", "type": "req_relay", "token": token, "channel_no": channel_no,
        "device_sn": sn, "publish_sn": f"{sn}_01_01", "play_type": play_type,
        "play_type_aux": play_type_aux, "requester_id": requester_id,
        "requester_ctx": f"{requester_ctx_uuid}[cts={cts}]",
    }, separators=(",", ":"))


def build_heartbeat_inner(sn: str, requester_id: str, requester_ctx_uuid: str, *,
                          channel_no: int = 1, play_type: int = 1, cts: int | None = None) -> str:
    """req_heartbeat inner JSON — the viewer-presence keep-alive.

    Without it the relay's session (``sid_duration``) lapses and the device stops publishing.
    Carries ``publish_sn`` to re-assert "a viewer is still watching stream X".
    """
    if cts is None:
        cts = int(time.time() * 1000)
    return json.dumps({
        "model": "netsdk", "type": "req_heartbeat", "channel_no": channel_no,
        "device_sn": sn, "publish_sn": f"{sn}_01_01", "play_type": play_type,
        "requester_id": requester_id, "requester_ctx": f"{requester_ctx_uuid}[cts={cts}]",
    }, separators=(",", ":"))


class TunnelSignal:
    """UDP P2P-tunnel signalling channel to the device (via the tunnel servers)."""

    def __init__(self, servers: list[tuple[str, int]], product_id: str, sn: str,
                 uuid: str) -> None:
        self.servers = servers
        self.uuid, self.product_id, self.sn = uuid, product_id, sn
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(2.0)
        # Fresh random per-session conv base (the app picks a new one each session and increments it
        # per message; a captured static base made every HA session look like the same/stale one).
        self._conv = secrets.randbits(32) or 1
        self._uf = uuid_field(uuid)
        self._rf = route_field(product_id, sn)

    def _next(self) -> int:
        c = self._conv
        self._conv += 1
        return c

    def _sendall(self, frame: bytes) -> None:
        for s in self.servers:
            self.sock.sendto(frame, s)

    def open(self) -> None:
        raw = (bytes.fromhex("070000000100002719000107")
               + (self.uuid + "_2").encode() + b"\x00\x00" + bytes.fromhex("0107")
               + f"{self.product_id}/{self.sn}".encode() + b"\x00" * 25)
        self._sendall(_wrap(0x03, 0x01, self._next(), raw))

    def probe(self) -> None:
        self._sendall(_wrap(0x02, 0x03, self._next(), self._uf + b"\x00" * 8))

    def connect(self) -> bool:
        payload = self._uf + self._rf + bytes.fromhex("0000010000000000")
        for s in self.servers:
            self.sock.sendto(_wrap(0x02, 0x04, self._next(), payload), s)
        got = False
        for _ in range(len(self.servers) * 2):
            try:
                data, _ = self.sock.recvfrom(2048)
                if len(data) > 0x18 and data[0x13] == 0x04:
                    got = True
            except TimeoutError:
                break
        return got

    def direct_register(self) -> None:
        """path=0x04 type=0x01 direct-path register (registers the viewer so the tunnel pages
        the device)."""
        self._sendall(_wrap(0x04, 0x01, self._next(), self._uf + self._rf + b"\x00" * 16))

    def keepalive(self) -> None:
        self._sendall(_wrap(0x02, 0x20, self._next(), self._uf))

    def send_signal(self, content: bytes, msg_id: int | None = None) -> None:
        if msg_id is None:
            msg_id = int(time.time() * 1e6) & 0xFFFFFFFFFFFFFFFF
        ct = len(content) + 0xC
        h = bytearray(0x94 - 0x18)  # offsets 0x18..0x93 (after path/type/conv)
        h[0x00:0x28] = self._uf                         # 0x18: uuid_2 (40)
        h[0x28:0x50] = self._rf                         # 0x40: product_id/sn (40)
        struct.pack_into(">Q", h, 0x50, msg_id & 0xFFFFFFFFFFFFFFFF)  # 0x68
        struct.pack_into(">I", h, 0x60, 1)              # 0x78: 00 00 00 01
        struct.pack_into(">I", h, 0x64, ct)             # 0x7c: chunk_total BE32
        struct.pack_into(">H", h, 0x70, 1)              # 0x88: total_chunks
        struct.pack_into(">H", h, 0x72, 0)              # 0x8a: chunk_idx
        struct.pack_into(">Q", h, 0x74, msg_id)         # 0x8c: msg_id
        self._sendall(_wrap(0x02, 0x30, self._next(), bytes(h) + content))

    def close(self) -> None:
        with contextlib.suppress(OSError):
            self.sock.close()
