"""Continuous live-view engine.

A long-running class that runs the pure-Python live handshake and emits decrypted Annex-B
H.264 chunks through a callback until stopped. It re-wakes the battery doorbell only if it
never starts publishing (once it is publishing the unit is awake, so re-waking would just
drain the battery).

Flow:
  login -> get_keys -> getRelaySign(uSign) -> schedule(ukey) -> cloud_control(tunnel servers)
  -> WakeUp -> UDP tunnel register -> base_capacity (FIXED key, double-b64)
  -> transfer_token (secret_keys[index], algo:1, double-b64, token=uSign)
  -> device publishes -> relay :80 over TCP, subscribe <sn>_01_01 -> class 0x02 -> ChaCha -> H.264.

The relay leg is TCP (see :mod:`relay_tcp`), so the kernel provides reliable in-order delivery and
this module never reconnects or re-wakes once media is flowing.

Two encryption regimes:
  * base_capacity uses the HARDCODED key ``a0e^63b2de5eea&a1451@e0c27c54a80`` (algo:0, envelope
    carries ``bc:1``);
  * transfer_token + media use the rotating ``secret_keys[index]`` (algo:1, no ``bc``). ``index``
    is ``sorted(keys)[len//3]`` — the app's key pick.
  Signalling ``data`` is double-base64: ``base64(RC4(base64(inner_json), key))``.
"""

from __future__ import annotations

import base64
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
import json
import logging
import re
import struct
import subprocess
import threading
import time
import uuid as _uuid

from . import cloudcontrol, schedule, tunnel_signal as ts
from ._http import DEFAULT_HTTP, Http
from .cloud import BotslabCloud
from .crypto import raw_decrypt_slice, rc4
from .hub import HubClient
from .relay import C_MEDIA
from .relay_tcp import TcpRelayClient

_LOGGER = logging.getLogger(__name__)

# Setup lookups that do not identify a streaming session, memoised to keep a re-open off the wire.
# The relay sign and schedule are deliberately NOT cached: they mint per-session values, and a stale
# ukey fails the relay login. Those two need the license from get_keys, so a cold cache costs two
# sequential round-trips (~1.6s) against a warm cache's one (~0.8s) — worth a generous TTL. The key
# list rotates on the order of hours and the tunnel-server list is effectively static, so half an
# hour sits well inside both, and a session whose first keyframe fails to decode drops the entry.
_SETUP_CACHE: dict[str, tuple[float, dict]] = {}
_KEYS_TTL = 1800.0

# Relay app-classes that carry video (per-NAL ChaCha20 H.264): 0x02 = I-frames (SPS/PPS/SEI/IDR),
# 0x03 = P-frames (inter slices). 0x0a is audio (G711/AAC) and 0x05 a one-shot config — skipped.
_VIDEO_CLASSES = frozenset({C_MEDIA, 0x03})

# Hardcoded base-capacity key (GodSees QHVCNET_DEVICE_BASE_CAPCITY_KEY, app-wide constant).
_FIXED_KEY = b"a0e^63b2de5eea&a1451@e0c27c54a80"

# Re-wake the doorbell if it never started publishing (battery unit sleeps otherwise). Once media
# flows we never re-wake or reconnect: the single TCP connection carries the whole session.
_STALL_REWAKE_S = 20.0

_START = re.compile(b"\x00\x00\x01")
_AU_START = 0x38  # fixed device/frame-header length before the H.264 access unit in a media body
# The device encrypts each VCL slice from a FIXED 0x100-byte clear prefix (keyframes AND P-frames);
# the 12 bytes at slice[0xf4:0x100] are the self-keyed ChaCha IV, the ciphertext is slice[0x100:].
# The 0x100 offset holds for a 45 KB keyframe and for every ~1-3 KB P-frame.
_DECRYPT_OFFSET = 0x100


def _parse_au(body: bytes) -> tuple[bytes, list[bytes], int]:
    """Split a relay media-frame body into (clear SPS/PPS/SEI config, [VCL slice NALs], type).

    The body is ``[0x38-byte device/frame header][NALs]``. We skip the header and split the payload
    by start code (00 00 01 markers), handing each NAL to the per-NAL decrypt. **A detailed
    keyframe is multi-slice** — several VCL
    NALs (type 5/1), each encrypted separately from its own 0x100/self-keyed IV — so we must return
    them ALL and decrypt each individually; treating them as one slice corrupts every slice after
    the first. SPS/PPS/SEI (6/7/8) are kept cleartext; device-metadata NALs (0/12/31) are dropped.
    ``type`` is 5 if any slice is an IDR (keyframe), else 1. ``(b"", [], 0)`` if no slice."""
    if len(body) <= _AU_START:
        return b"", [], 0
    au = body[_AU_START:]
    starts = [m.start() for m in _START.finditer(au)]
    clear = bytearray()
    slices: list[bytes] = []
    is_key = False
    for i, s in enumerate(starts):
        ns = s + 3
        if ns >= len(au):
            break
        nal_type = au[ns] & 0x1F
        ne = starts[i + 1] if i + 1 < len(starts) else len(au)
        while ne > ns and au[ne - 1] == 0:  # strip trailing zero padding before the next start code
            ne -= 1
        if nal_type in (1, 5):  # VCL slice — one encrypted unit
            slices.append(au[ns:ne])
            is_key = is_key or nal_type == 5
        elif nal_type in (6, 7, 8):  # SEI / SPS / PPS — cleartext, keep for the decoder
            clear += b"\x00\x00\x00\x01" + au[ns:ne]
    return bytes(clear), slices, (5 if is_key else 1)


class LiveEngine:
    """Runs the handshake and streams decrypted H.264 until stopped (blocking; run in a thread)."""

    def __init__(self, *, q: str, t: str, region: str, product_key: str, sn: str,
                 m2: str, on_h264: Callable[[bytes], None], sid: str = "",
                 ffmpeg_bin: str | None = None, http: Http | None = None) -> None:
        """Store credentials and the sink callback. ``on_h264`` receives Annex-B chunks.

        ``sid`` is the coordinator's existing session; the engine reuses it so it never mints a
        competing session on this single-session account (see :class:`.cloud.BotslabCloud`).
        ``ffmpeg_bin`` (when given) auto-detects the correct ChaCha media key on the first
        keyframe: the get_keys index that rotates ~12-hourly is NOT ``kitems[len//3]`` and is not
        derivable client-side, so we pick the one whose keyframe decodes with the fewest errors.
        ``http`` carries every cloud call; ``manager.py`` passes one backed by Home Assistant's
        shared aiohttp session, and the stdlib default keeps the engine runnable on its own.
        """
        self._http = http or DEFAULT_HTTP
        self._q, self._t, self._region = q, t, region
        self._product_key, self._sn, self._m2, self._sid = product_key, sn, m2, sid
        # Per-install signalling identities, derived from the persisted m2. NOTE: on-device testing
        # showed the requester_id VALUE is not the video gate — feeding the app's exact current pair
        # (machineId 1c303304 + its live requester_id) still returned flag:0/audio-only for this
        # (guest) account, while the app on the owner account gets flag:1. So video authorisation is
        # account/viewer-state on the server, not a value we send. Kept derived + publishable.
        self._client_uuid = ts.machine_id(m2)
        self._requester_id = ts.requester_id(m2)
        self._on_h264 = on_h264
        self._ffmpeg_bin = ffmpeg_bin
        self._kf_ok = False        # a keyframe has decoded cleanly (gates P-frame output)
        self._kf_checked = False   # the one-shot first-keyframe validation has run
        self._stop = False
        self._media_count = 0
        self._publishing = False          # device reported res_pub_stream_result
        self._hub_addr: tuple[str, int] | None = None  # hub LAN address from req_relay_res la
        self._hub: HubClient | None = None    # direct-to-hub video transport (the app's real path)
        self._hub_tried = False               # one-shot: don't re-dial the hub every loop pass
        self._relay_classes: dict[int, int] = {}  # histogram of relay app-classes received
        self._t: dict[str, float] = {}    # periodic-send timers (see _due)
        self._cts = 0                     # stable requester_ctx timestamp (ties heartbeat->session)
        self._logged_types: set[str] = set()  # device reply types already logged (once each)
        self._sig: ts.TunnelSignal | None = None
        self._relay: TcpRelayClient | None = None
        # Filled during setup:
        self._cloud: BotslabCloud | None = None
        self._product_id = ""
        self._keys: dict[int, str] = {}
        self._idx = 0
        self._key = b""
        self._usign = ""
        self._sched: dict = {}
        self._servers: list[tuple[str, int]] = []
        self._got_bcres = False

    # ------------------------------------------------------------------ public
    def stop(self) -> None:
        """Signal the run loop to exit (safe to call from another thread)."""
        self._stop = True

    def run(self) -> None:
        """Blocking: perform setup then stream until :meth:`stop` (or setup fails)."""
        # Setup hits several cloud endpoints; a transient hiccup can raise (e.g. a KeyError 'data'
        # when a response comes back without its payload). Retry a few times before giving up so one
        # bad response doesn't fail the whole open.
        for attempt in range(4):
            if self._stop:
                return
            try:
                self._setup()
                break
            except Exception as err:
                if attempt == 3:
                    raise
                _LOGGER.warning("live %s: setup attempt %d failed (%s), retrying",
                                self._sn, attempt + 1, err)
                time.sleep(0.8)
        self._sig = ts.TunnelSignal(self._servers, self._product_id, self._sn,
                                    uuid=self._client_uuid)
        self._relay = self._make_relay()
        try:
            self._stream_loop()
        finally:
            _LOGGER.info("live %s: stopped (media frames decrypted=%d, bcres=%s)",
                         self._sn, self._media_count, self._got_bcres)
            self._sig.close()
            self._relay.close()
            if self._hub is not None:
                self._hub.close()

    def _make_relay(self) -> TcpRelayClient:
        return TcpRelayClient(self._sched["relay"], self._sched["stream_id"], self._sched["ukey"],
                              self._sched["cluster"], self._product_key)

    # ------------------------------------------------------------------ setup
    def _cached(self, key: str, ttl: float, produce):
        """Memoise a per-device cloud lookup for ``ttl`` seconds (see :meth:`_setup`).

        Only applied to results that do not identify a streaming session: the key list and the
        tunnel-server list. The relay sign and schedule mint per-session values and are always
        fetched fresh.
        """
        ck = f"{self._sn}:{key}"
        hit = _SETUP_CACHE.get(ck)
        now = time.time()
        if hit is not None and now - hit[0] < ttl:
            return hit[1]
        value = produce()
        _SETUP_CACHE[ck] = (now, value)
        return value

    def _setup(self) -> None:
        # Reuse the coordinator's sid (self._sid); only fall back to a fresh login if we have
        # none, to avoid kicking the single active session.
        cloud = BotslabCloud(self._q, self._t, self._region, self._m2, sid=self._sid,
                             http=self._http)
        if not self._sid:
            cloud.login()
        # Cold start is a race against Home Assistant's 10s stream_source timeout, and these cloud
        # round-trips used to run back-to-back for ~3s. get_keys and the tunnel-server list are
        # independent, and the relay sign and schedule both only need the license, so each pair runs
        # concurrently. The two stable lookups are also cached briefly so a re-open is instant.
        with ThreadPoolExecutor(max_workers=2) as pool:
            keys_f = pool.submit(self._cached, "keys", _KEYS_TTL,
                                 lambda: cloud.get_keys(self._product_key, self._sn))
            cc_f = pool.submit(self._cached, "servers", _KEYS_TTL,
                               lambda: cloudcontrol.get_servers(self._region, http=self._http))
            ks, cc = keys_f.result(), cc_f.result()
        lic, self._keys = ks["license"], ks["keys"]
        self._product_id = lic["product_id"]
        with ThreadPoolExecutor(max_workers=2) as pool:
            sign_f = pool.submit(schedule.get_relay_sign, self._region, lic, self._sn,
                                 http=self._http)
            sched_f = pool.submit(schedule.schedule_relay, self._region, lic, self._sn,
                                  self._product_key, http=self._http)
            self._usign = sign_f.result().get("sign", "")
            self._sched = sched_f.result()
        self._servers = [(ip, cc["tunnel_port"]) for ip in cc["tunnel_servers"]]
        kitems = sorted(self._keys.items())
        self._idx, key_str = kitems[len(kitems) // 3]  # the app's _pick_key choice
        self._key = key_str.encode()
        self._cts = int(time.time() * 1000)  # stable across req_relay + heartbeats this session
        self._cloud = cloud
        _LOGGER.info("live setup ok for %s: pid=%s enc_index=%s tunnel_servers=%d relay=%s",
                     self._sn, self._product_id, self._idx, len(self._servers),
                     self._sched.get("relay"))
        self._register_viewer()  # schedule_2: authorise our machineId for the video substream

    def _register_viewer(self) -> None:
        """Register our machineId as the live viewer (schedule_2). Re-run periodically to hold the
        slot: another login registering a different machineId would otherwise take video away."""
        ok = schedule.register_viewer(self._region, self._sn, self._product_id,
                                      self._sched["channel"], self._usign, self._client_uuid,
                                      http=self._http)
        _LOGGER.info("live %s: schedule_2 viewer register ok=%s (machineId=%s)",
                     self._sn, ok, self._client_uuid)

    # --------------------------------------------------------------- signalling
    def _encode_signal(self, inner: str, key: bytes, extra: dict) -> bytes:
        """data = base64(RC4(base64(inner), key)); envelope = {model,sn,tm,data, **extra}."""
        s1 = base64.b64encode(inner.encode())
        data = base64.b64encode(rc4(s1, key)).decode()
        env = {"model": "netsdk", "sn": self._sn, "tm": str(int(time.time() * 1000)), "data": data}
        env.update(extra)
        return json.dumps(env, separators=(",", ":")).encode()

    def _base_capacity(self) -> bytes:
        ctx = _uuid.uuid4().hex
        inner = json.dumps({"type": "base_capacity", "ver": 1, "requester_ctx": ctx,
                            "device_sn": self._sn}, separators=(",", ":"))
        return self._encode_signal(inner, _FIXED_KEY, {"bc": 1})

    def _transfer_token(self) -> bytes:
        inner = ts.build_reqrelay_inner(self._sn, self._requester_id, self._client_uuid,
                                        channel_no=1, play_type=1, token=self._usign, cts=self._cts)
        return self._encode_signal(inner, self._key, {"index": self._idx, "algo": 1})

    def _heartbeat(self) -> bytes:
        inner = ts.build_heartbeat_inner(self._sn, self._requester_id, self._client_uuid,
                                         channel_no=1, play_type=1, cts=self._cts)
        return self._encode_signal(inner, self._key, {"index": self._idx, "algo": 1})

    def _decrypt_device(self, env: dict) -> str | None:
        algo, idx = env.get("algo", 0), env.get("index", 0)
        k = _FIXED_KEY if algo == 0 else self._keys.get(idx, "").encode()
        if not k:
            return None
        try:
            plain = rc4(base64.b64decode(env["data"]), k)
            return base64.b64decode(plain).decode("utf-8", "replace")
        except (ValueError, KeyError):
            return None

    @staticmethod
    def _ack_signal(sig: ts.TunnelSignal, frame: bytes) -> None:
        pl = sig._uf + sig._rf + frame[0x68:0x70] + b"\x00" * 12
        sig._sendall(ts._wrap(0x02, 0x31, sig._next(), pl))

    # ------------------------------------------------------------------ loop
    def _wake(self) -> None:
        if self._cloud is None:
            return
        try:
            self._cloud.wake(self._product_key, self._sn)
        except Exception as err:
            _LOGGER.debug("wake failed: %s", err)

    def _open_tunnel(self, sig: ts.TunnelSignal) -> None:
        sig.open()
        time.sleep(0.15)
        sig.connect()
        time.sleep(0.15)
        sig.direct_register()
        time.sleep(0.15)
        sig.probe()
        time.sleep(0.2)
        sig.sock.setblocking(False)

    def _connect_relay(self, rc: TcpRelayClient) -> bool:
        """Connect and log in. The kernel does the handshake; there is no window or ACK to drive."""
        connected = rc.connect()
        logged_in = rc.login() if connected else False
        if logged_in:
            rc.start()
        rc.sock.setblocking(False)  # drained fully each loop pass (see _drain_media)
        _LOGGER.info("live relay %s: connected=%s login=%s", self._sn, connected, logged_in)
        return connected and logged_in

    def _due(self, key: str, interval: float, now: float) -> bool:
        """True (and arms the next tick) if at least ``interval`` s passed since key last fired."""
        if now - self._t.get(key, 0.0) >= interval:
            self._t[key] = now
            return True
        return False

    def _pump_signals(self, now: float) -> None:
        sig, relay_client = self._sig, self._relay
        if self._due("ka", 3.0, now):
            sig.keepalive()
            relay_client.start()
        if self._due("dr", 2.0, now):
            sig.direct_register()
        if not self._got_bcres and self._due("bc", 1.0, now):
            sig.send_signal(self._base_capacity())
        if not self._publishing:
            if self._due("tt", 0.6, now):  # transfer_token to *start* the publish
                sig.send_signal(self._transfer_token())
            return
        # Once publishing, keep the device publishing with req_heartbeat (viewer presence). The
        # relay leg needs nothing to stay alive: TCP carries the whole session on one connection.
        if self._due("hb", 2.0, now):
            sig.send_signal(self._heartbeat())

    def _stream_loop(self) -> None:
        self._t = {}
        if self._stop:
            return
        # These three legs are independent, so run them together rather than back-to-back: the wake
        # is a cloud call, opening the tunnel only registers *us* with the tunnel server, and the
        # relay subscribe needs nothing but the schedule. Overlapping them takes ~1.1s off the cold
        # start, and the tunnel's own step delays double as the settle the wake needs before the
        # loop's first signalling burst.
        with ThreadPoolExecutor(max_workers=2) as pool:
            relay_f = pool.submit(self._connect_relay, self._relay)
            wake_f = pool.submit(self._wake)
            self._open_tunnel(self._sig)
            wake_f.result()
            relay_f.result()
        _LOGGER.info("live %s: woke device, tunnel + relay open", self._sn)
        start = time.time()
        last_progress = time.time()  # last time media_count grew
        self._t["reg"] = start       # _setup already registered; defer the first periodic re-run
        seen_media = 0
        while not self._stop:
            now = time.time()
            self._pump_signals(now)
            # Relay (media) first and drained fully; signalling second and bounded.
            self._drain_media(self._relay)
            # Direct-to-hub video: once req_relay_res gave us the hub's LAN address, open a QTP/UDX
            # connection straight to it (the app's real video path; the relay carries audio only).
            if self._hub_addr and not self._hub_tried:
                self._connect_hub()
            if self._hub is not None:
                self._drain_hub()
            self._drain_signalling(self._sig)

            if self._media_count > seen_media:  # progress since last check
                if seen_media == 0:
                    _LOGGER.info("live %s: first media frame after %.1fs", self._sn, now - start)
                    # Media flowing PROVES the device is publishing — engage the heartbeat sustain
                    # path even if we never parsed res_pub_stream_result.
                    self._publishing = True
                seen_media = self._media_count
                last_progress = now

            if not self._publishing and now - last_progress > _STALL_REWAKE_S \
                    and self._due("wake", _STALL_REWAKE_S, now):
                # Never published — re-wake (the battery unit may have gone back to sleep).
                _LOGGER.info("live %s stalled %.0fs (media=%d, no publish), re-waking",
                             self._sn, now - last_progress, self._media_count)
                self._wake()

            # Re-assert our viewer registration so a competing login can't quietly take video away.
            # Run it off the loop thread — it's a blocking HTTP call and must not stall media drain.
            if self._due("reg", 30.0, now):
                threading.Thread(target=self._register_viewer, daemon=True).start()

            if self._due("hist", 5.0, now):
                _LOGGER.info("live %s relay classes=%s media=%d publishing=%s",
                             self._sn, self._relay_classes, self._media_count, self._publishing)
            time.sleep(0.005)  # yield; avoids a busy-spin when both sockets are idle

    def _drain_signalling(self, sig: ts.TunnelSignal, max_packets: int = 48) -> None:
        # Bounded: the device floods res_pub_stream_result, so cap how many we handle per pass
        # to guarantee the relay read (media) still gets a turn.
        for _ in range(max_packets):
            try:
                d, _ = sig.sock.recvfrom(65535)
            except (TimeoutError, BlockingIOError):
                return
            except OSError:
                return
            if len(d) < 0x94 or d[:8] != ts.MAGIC or d[0x13] != 0x30:
                continue
            self._ack_signal(sig, d)
            b = d[0x18:]
            ji = b.find(b"{")
            if ji < 0:
                continue
            try:
                env = json.loads(b[ji:b.rfind(b"}") + 1])
            except ValueError:
                continue
            dec = self._decrypt_device(env)
            if not (dec and dec.startswith("{")):
                continue
            try:
                dtype = json.loads(dec).get("type")
            except ValueError:
                continue
            self._handle_reply(dtype, dec)

    def _handle_reply(self, dtype: str | None, dec: str) -> None:
        """Act on one decrypted device signalling reply."""
        if dtype == "base_capacity_res" and not self._got_bcres:
            self._got_bcres = True
            _LOGGER.info("live %s: device replied base_capacity_res", self._sn)
        elif dtype == "res_pub_stream_result" and not self._publishing:
            self._publishing = True
            _LOGGER.info("live %s: device is publishing (res_pub_stream_result)", self._sn)
        elif dtype == "req_relay_res" and self._hub_addr is None:
            self._hub_addr = self._parse_la(dec)
            if self._hub_addr:
                _LOGGER.info("live %s: hub LAN address (la) = %s:%d — the direct video path",
                             self._sn, *self._hub_addr)
        # Log the full first reply of each session type once — these may carry a session
        # token / media_key we must echo in the heartbeat to keep the publish alive.
        if dtype and dtype not in self._logged_types:
            self._logged_types.add(dtype)
            _LOGGER.info("live %s: device reply type=%s content=%s", self._sn, dtype, dec[:400])

    def _connect_hub(self) -> None:
        """Open the direct QTP/UDX connection to the hub (one-shot per session)."""
        self._hub_tried = True
        h = HubClient(self._hub_addr, self._sched["stream_id"], self._sched["ukey"],
                      self._sched["cluster"], self._product_key)
        ok = h.connect() and h.handshake() and h.login()
        if ok:
            h.start()
            h.sock.setblocking(False)
            self._hub = h
            _LOGGER.info("live %s: HUB connected (direct video) addr=%s conv=%#x",
                         self._sn, self._hub_addr, h.conv)
        else:
            h.close()
            _LOGGER.warning("live %s: hub connect failed (handshake/login) — staying on relay",
                            self._sn)

    def _drain_hub(self) -> None:
        """Drain the hub's QTP media and feed it through the shared decrypt path."""
        for frame in self._hub.drain():
            self._relay_classes[frame.cls] = self._relay_classes.get(frame.cls, 0) + 1
            if frame.cls in _VIDEO_CLASSES:
                self._handle_media_frame(frame.body)

    @staticmethod
    def _parse_la(req_relay_res_json: str) -> tuple[str, int] | None:
        """Extract the hub's LAN address from a ``req_relay_res``.

        The reply's base64 ``lra`` decodes to JSON carrying ``"la": "<ip_u32>:<port>"``, where the
        IP is a **little-endian** uint32 (e.g. 4227967168 -> 192.168.1.252). This is the always-on
        hub/base-station the app connects to directly over the LAN for the video substream (the
        cloud relay carries audio only once a LAN viewer is active).
        """
        try:
            lra = json.loads(base64.b64decode(json.loads(req_relay_res_json)["lra"]))
            ip_u32, _, port = str(lra["la"]).partition(":")
            ip = ".".join(str(b) for b in struct.pack("<I", int(ip_u32)))
            return (ip, int(port))
        except (ValueError, KeyError, TypeError):
            return None

    def _drain_media(self, relay_client: TcpRelayClient, max_reads: int = 1024) -> None:
        """Read whatever the relay socket has queued this pass and dispatch the completed frames.

        TCP delivers the stream complete and in order, so there is no reassembly or ACKing to do
        here — only bounded non-blocking reads so signalling still gets a turn each loop pass.
        """
        for frame in relay_client.drain(max_reads):
            self._relay_classes[frame.cls] = self._relay_classes.get(frame.cls, 0) + 1
            if frame.cls in _VIDEO_CLASSES:
                self._handle_media_frame(frame.body)

    def _handle_media_frame(self, body: bytes) -> None:
        """Decrypt one reassembled media frame's slice at the fixed 0x100 boundary and emit H.264.

        The ChaCha key index is in the frame header (big-endian at 0x2c). Both keyframes and
        P-frames encrypt from slice[0x100:]. A keyframe is dropped only if it decodes clearly
        corrupt (rare reassembly glitch); P-frames are emitted only once a good keyframe has been
        seen, so a dropped keyframe can't leave the decoder referencing garbage."""
        if len(body) < 0x30:
            return
        index = struct.unpack_from(">I", body, 0x2C)[0]  # byteswap(u32le) == big-endian read
        key = self._keys.get(index) or self._keys.get(self._idx)
        clear, slices, slice_type = _parse_au(body)
        if not key or not slices:
            return
        # Decrypt EACH VCL slice from its own 0x100 boundary (multi-slice keyframes need this).
        parts = [clear]
        for nal in slices:
            parts.append(b"\x00\x00\x00\x01")
            parts.append(raw_decrypt_slice(nal, key, _DECRYPT_OFFSET))
        annexb = b"".join(parts)
        if slice_type == 5:  # keyframe (IDR): gates the P-frames that reference it
            if not self._kf_checked:
                # Validate the session's FIRST keyframe only. It confirms the key index and slice
                # offset are right for this session; once one frame decodes cleanly the rest do too,
                # since TCP delivers them intact. Checking every keyframe would spawn an ffmpeg
                # decode several times a second for no added safety.
                self._kf_checked = True
                errs = self._decode_errors(annexb)
                self._kf_ok = errs is None or errs <= 4
                if not self._kf_ok or index not in self._keys:
                    # The memoised key list is the one thing here that can go stale; drop it so the
                    # next session refetches rather than repeating a session that cannot decrypt.
                    _SETUP_CACHE.pop(f"{self._sn}:keys", None)
                _LOGGER.info(
                    "live %s first keyframe: key_index=%d errs=%s slices=%s body=%dB ok=%s",
                    self._sn, index, errs, [len(s) for s in slices][:8], len(body), self._kf_ok)
            if not self._kf_ok:
                return
        elif not self._kf_ok:  # P-frame with no valid keyframe to reference yet
            return
        self._media_count += 1
        self._on_h264(annexb)

    def _decode_errors(self, annexb: bytes) -> int | None:
        """Decode one keyframe with ffmpeg (downscaled for speed) and count decode errors, so a
        rare corrupt frame is dropped rather than shown. Returns 0 (trust the fixed 0x100 offset)
        if no ffmpeg is available."""
        if not self._ffmpeg_bin:
            return 0
        data = annexb if annexb[:3] == b"\x00\x00\x01" else b"\x00\x00\x00\x01" + annexb
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv, ffmpeg binary from HA
                [self._ffmpeg_bin, "-hide_banner", "-v", "error", "-f", "h264", "-i", "pipe:0",
                 "-frames:v", "1", "-vf", "scale=160:120", "-f", "null", "-"],
                input=data, capture_output=True, timeout=5, check=False)
        except (OSError, subprocess.SubprocessError):
            return None
        return (proc.stderr.count(b"decoding MB") + proc.stderr.count(b"block unavailable")
                + proc.stderr.count(b"concealing") + proc.stderr.count(b"damaged"))
