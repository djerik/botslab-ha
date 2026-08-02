"""Continuous live-view engine.

A long-running class that runs the pure-Python live handshake and emits decrypted Annex-B
H.264 chunks through a callback until stopped. It re-wakes the battery doorbell only if it
never starts publishing (once it is publishing the unit is awake, so re-waking would just
drain the battery).

Flow:
  login -> get_keys -> getRelaySign(uSign) -> schedule(ukey) -> cloud_control(tunnel servers)
  -> WakeUp -> UDP tunnel register -> base_capacity (FIXED key, double-b64)
  -> transfer_token (secret_keys[index], algo:1, double-b64, token=uSign)
  -> device publishes -> subscribe <sn>_01_01 on the media relay -> class 0x02/0x03 -> ChaCha ->
     H.264.

Two media legs connect to the same cloud relay (:80) and both subscribe with the ``_bf`` video
ukey, but they carry different content: the TCP leg (:mod:`relay_tcp`) delivers only audio (class
0x0a), while the QTP/UDP leg (:mod:`hub`) delivers the video (class 0x02/0x03) — so the picture
comes over QTP. Both connect once and neither reconnects or re-wakes once media is flowing.

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
from .crypto import decrypt_annexb, rc4
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

# The QTP/UDP video handshake to the cloud relay can lose its SYN (UDP); a single miss must NOT cost
# the whole session's video (it did — the leg was dialled once, then never retried, leaving only the
# audio TCP leg). Re-dial while unconnected, spaced by _HUB_DIAL_INTERVAL, up to _HUB_MAX_DIALS.
_HUB_MAX_DIALS = 8
_HUB_DIAL_INTERVAL = 2.0

# Re-wake the doorbell if it never started publishing (battery unit sleeps otherwise). Once media
# flows we never re-wake or reconnect: the single TCP connection carries the whole session.
_STALL_REWAKE_S = 20.0

_START = re.compile(b"\x00\x00\x01")
_AU_START = 0x38  # fixed device/frame-header length before the H.264 access unit in a media body
# Each VCL slice is ChaCha20-encrypted from a fixed 0x100-byte clear prefix, with the 12-byte
# self-keyed IV at slice[0xf4:0x100] and a 64-bit block counter (verified against the device's own
# ChaCha20XOR calls). :func:`.crypto.decrypt_annexb` implements exactly this per coded slice.


def _decrypt_au(body: bytes, key: str) -> tuple[bytes, bool]:
    """Decrypt an access unit's VCL slices **in place**, preserving every other byte exactly.

    The body is ``[0x38-byte device/frame header][Annex-B NALs]``. We copy the AU and rewrite only
    the encrypted payload (from the fixed 0x100 boundary) of each coded slice (NAL types 1/5),
    leaving SPS/PPS/SEI and the device's opaque metadata NALs (types 0/4/12/31) byte-for-byte as
    sent — exactly what the reference decoder does.

    The previous version REBUILT the stream from re-extracted NALs, scanning the whole AU for
    ``00 00 01`` start codes. Those markers also occur inside the device's metadata NALs (and in
    slice ciphertext), so it manufactured a garbage "SPS" from that data -> ffmpeg rejected it
    ("sps_id out of range") and the decoder never initialised. Decrypting in place keeps the exact
    NAL layout the device sent (which the decoder accepts) and only touches slice payloads.

    Returns ``(annexb, is_keyframe)``; ``is_keyframe`` is True when a real IDR slice (type 5,
    longer than the 0x100 clear prefix) is present. ``(b"", False)`` if the AU is too short."""
    if len(body) <= _AU_START:
        return b"", False
    au = body[_AU_START:]
    # Keyframe detection from the clear NAL headers (decryption never touches the type byte).
    is_key = any((au[m.start() + 3] & 0x1F) == 5
                 for m in _START.finditer(au) if m.start() + 3 < len(au))
    # Decrypt every coded slice in place. decrypt_annexb maps the 0x100 payload boundary and the
    # 12-byte IV through the RBSP (emulation-prevention 00 00 03 removed), matching the device's
    # encoder: a raw XOR desynchronises at the first 00 00 03 in the encrypted region, decoding the
    # top of the slice then concealing the rest (green bottom).
    return decrypt_annexb(au, key), is_key


class LiveEngine:
    """Runs the handshake and streams decrypted H.264 until stopped (blocking; run in a thread)."""

    def __init__(self, *, q: str, t: str, region: str, product_key: str, sn: str,
                 m2: str, on_h264: Callable[[bytes, int], None], sid: str = "", uid: str = "",
                 ffmpeg_bin: str | None = None, http: Http | None = None) -> None:
        """Store credentials and the sink callback. ``on_h264(annexb, ts_ms)`` receives each Annex-B
        access unit with the device's capture timestamp (ms) so the sink can pace playback.

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
        # Real account userid for the /substream call. A live frida capture of the app's
        # connect_priv ("start_relay") showed userid = the account uid (e.g. 1000100000000014903),
        # not the "10010" placeholder HA sent — the device gates video on the owning account uid.
        self._uid = uid
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
        self._last_flag: int | None = None  # last req_relay_res flag (1 = video authorised)
        self._sched_bf: dict = {}          # the _bf start_relay schedule (video-authorised creds)
        # QTP/UDP leg to the cloud relay — the leg that actually carries video (class 0x02/0x03).
        # Named "hub" historically (the app can also reach an on-LAN hub); here it dials the relay.
        self._hub: HubClient | None = None
        self._hub_dials = 0                   # QTP relay dial attempts (retried on UDP SYN loss)
        self._relay_classes: dict[int, int] = {}  # histogram of TCP-relay app-classes (audio)
        self._hub_classes: dict[int, int] = {}    # histogram of QTP-relay app-classes (video)
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
        s = self._sched_bf or self._sched  # prefer the _bf video-authorised session (from _setup)
        return TcpRelayClient(s["relay"], s["stream_id"], s["ukey"], s["cluster"],
                              self._product_key)

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
                                  self._product_key, userid=self._uid, http=self._http)
            self._usign = sign_f.result().get("sign", "")
            self._sched = sched_f.result()
        self._servers = [(ip, cc["tunnel_port"]) for ip in cc["tunnel_servers"]]
        kitems = sorted(self._keys.items())
        self._idx, key_str = kitems[len(kitems) // 3]  # the app's _pick_key choice
        self._key = key_str.encode()
        self._cts = int(time.time() * 1000)  # stable across req_relay + heartbeats this session
        self._cloud = cloud
        _LOGGER.info("live setup ok for %s: pid=%s enc_index=%s tunnel_servers=%d relay=%s uid=%s",
                     self._sn, self._product_id, self._idx, len(self._servers),
                     self._sched.get("relay"), self._uid or "(empty!)")
        self._register_viewer()  # schedule_2: authorise our machineId for the video substream
        # Fire the _bf start_relay authorisation NOW (before any media connection) so the relay and
        # hub connect once with the video-authorised ukey. Doing it mid-stream would force a hub
        # reconnect that corrupts the decoder (a fresh QTP session starting mid-frame).
        self._start_relay()

    def _register_viewer(self) -> None:
        """Register our machineId as the live viewer (schedule_2). Re-run periodically to hold the
        slot: another login registering a different machineId would otherwise take video away."""
        ok = schedule.register_viewer(self._region, self._sn, self._product_id,
                                      self._sched["channel"], self._usign, self._client_uuid,
                                      userid=self._uid, http=self._http)
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
        # token MUST be empty: a live frida capture of the app's ll_request_device_relay shows the
        # viewer/subscribe path sends token="" and gets video; the non-empty uSign (transfer_token /
        # publish path) is what made the device publish audio-only to us.
        inner = ts.build_reqrelay_inner(self._sn, self._requester_id, self._client_uuid,
                                        channel_no=1, play_type=1, token="", cts=self._cts)
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
        # Keep re-sending req_relay (transfer_token) until the device authorises VIDEO (flag=1),
        # not merely until it starts publishing. The _bf start_relay call authorises video a beat
        # after the first req_relay, so the first reply is often flag:0 (audio); re-requesting picks
        # up flag:1 once the authorisation lands, instead of stalling on an audio-only publish.
        if self._last_flag != 1:
            if self._due("tt", 0.6, now):
                sig.send_signal(self._transfer_token())
            if not self._publishing:
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
            # Video comes over QTP from the cloud relay. Dial it with the _bf video-authorised ukey
            # (minted in _setup); the UDP handshake can drop its SYN, so re-dial while unconnected
            # rather than losing video for the whole session on one lost packet. Once connected we
            # never reconnect (a fresh QTP session mid-stream would corrupt the decoder). Falls back
            # to the base schedule if _bf failed.
            if self._hub is None and self._hub_dials < _HUB_MAX_DIALS \
                    and self._due("hubdial", _HUB_DIAL_INTERVAL, now):
                self._hub_dials += 1
                self._connect_hub(self._sched_bf or None)
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
                _LOGGER.debug("live %s relay=%s hub=%s media=%d publishing=%s", self._sn,
                              self._relay_classes, self._hub_classes, self._media_count,
                              self._publishing)
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
        elif dtype == "req_relay_res":
            flag = self._parse_flag(dec)
            if flag != self._last_flag:
                self._last_flag = flag
                _LOGGER.info("live %s: req_relay_res flag=%s (1 = video authorised)",
                             self._sn, flag)
        # Log the full first reply of each session type once, at DEBUG — verbose (carries session
        # ctx/cts) but the record of which reply might hold a token/media_key is worth keeping.
        if dtype and dtype not in self._logged_types:
            self._logged_types.add(dtype)
            _LOGGER.debug("live %s: device reply type=%s content=%s", self._sn, dtype, dec[:400])

    def _start_relay(self) -> None:
        """Fire the app's ``_bf`` start_relay substream (connect_priv @0x29272c) — the missing
        video-substream authorisation, byte-identical to schedule_1 but with ``sid=<stream_id>_bf``.
        Its response mints a VIDEO-authorised ukey for the same stream, stored in ``_sched_bf`` so
        relay/hub connect with it from the start (that ukey is what makes the relay forward class
        0x02/0x03 video instead of the audio-only class 0x0a). Called once, in :meth:`_setup`."""
        try:
            j = schedule.start_relay(self._region, self._sn, self._sched["channel"], self._usign,
                                     self._sched["stream_id"], userid=self._uid, http=self._http)
        except Exception as err:
            _LOGGER.warning("live %s: _bf start_relay error: %s", self._sn, err)
            return
        errcode, auth_key = j.get("errcode"), j.get("auth_key")
        _LOGGER.info("live %s: _bf start_relay stream_id=%s -> errcode=%s servers=%s auth_key=%s "
                     "sn=%s cluster=%s", self._sn, self._sched["stream_id"], errcode,
                     j.get("servers"), bool(auth_key), j.get("sn"), j.get("cluster_id"))
        if errcode != 0 or not auth_key:
            return
        srv = next((s for s in j.get("servers", []) if s), "")
        host, _, port = srv.partition(":")
        # Normalise into the same shape as schedule_relay's return so _connect_hub can consume it.
        self._sched_bf = {
            "relay": (host, int(port or 80)) if host else self._sched["relay"],
            "ukey": auth_key, "cluster": j.get("cluster_id") or self._sched["cluster"],
            "stream_id": j.get("sn") or self._sched["stream_id"],
            "channel": self._sched["channel"], "product_id": self._product_id,
        }

    def _connect_hub(self, sched: dict | None = None) -> None:
        """Open the QTP/UDX video connection to the cloud relay (the reference RelayClient path).

        ``sched`` defaults to the base (audio) schedule; the ``_bf`` video schedule is passed once
        :meth:`_start_relay` mints it, and its video-authorised ukey is what makes the relay forward
        class 0x02/0x03 instead of the audio-only class 0x0a. Reconnecting closes the prior hub.
        """
        sched = sched or self._sched
        which = "_bf/video" if sched is self._sched_bf else "base/audio"
        target = sched["relay"]  # cloud media relay tuple, e.g. ('18.185.227.156', 80)
        h = HubClient(target, sched["stream_id"], sched["ukey"], sched["cluster"],
                      self._product_key)
        # Track which step fails: connect vs handshake (no reply / wrong SYN) vs login (rejected).
        if not h.connect():
            step = "connect"
        elif not h.handshake():
            step = "handshake"
        elif not h.login():
            step = "login"
        else:
            step = None
        if step is None:
            h.start()
            h.sock.setblocking(False)
            if self._hub is not None:
                self._hub.close()
            self._hub = h
            _LOGGER.info("live %s: QTP relay connected (%s) addr=%s conv=%#x",
                         self._sn, which, target, h.conv)
        else:
            h.close()
            _LOGGER.warning("live %s: QTP relay %s failed (%s, addr=%s conv=%#x)",
                            self._sn, step, which, target, h.conv)

    def _drain_hub(self) -> None:
        """Drain the hub's QTP media and feed it through the shared decrypt path."""
        for frame in self._hub.drain():
            self._hub_classes[frame.cls] = self._hub_classes.get(frame.cls, 0) + 1
            if frame.cls in _VIDEO_CLASSES:
                self._handle_media_frame(frame.body)


    @staticmethod
    def _parse_flag(req_relay_res_json: str) -> int | None:
        """Extract ``flag`` from a ``req_relay_res`` (its base64 ``lra`` JSON). 1 = video authorised
        (the device publishes class 0x02/0x03), 0 = audio-only. This is the gate the ``_bf``
        start_relay call flips; logging it plainly makes the transition visible in the log."""
        try:
            lra = json.loads(base64.b64decode(json.loads(req_relay_res_json)["lra"]))
            return int(lra["flag"])
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
        """Decrypt one reassembled media frame's slices in place and emit Annex-B H.264.

        The ChaCha key index is in the frame header (big-endian at 0x2c). Both keyframes and
        P-frames encrypt each slice from slice[0x100:]. A keyframe is dropped only if it decodes
        clearly corrupt (rare reassembly glitch); P-frames are emitted only once a good keyframe
        has been seen, so a dropped keyframe can't leave the decoder referencing garbage."""
        if len(body) < 0x30:
            return
        index = struct.unpack_from(">I", body, 0x2C)[0]  # byteswap(u32le) == big-endian read
        ts_ms = struct.unpack_from(">I", body, 0x0C)[0]  # device capture timestamp (ms), steady
        key = self._keys.get(index) or self._keys.get(self._idx)
        if not key:
            return
        annexb, is_key = _decrypt_au(body, key)
        if not annexb:
            return
        if is_key:  # keyframe (IDR): gates the P-frames that reference it
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
                _LOGGER.info("live %s first keyframe: key_index=%d errs=%s annexb=%dB ok=%s "
                             "head=%s", self._sn, index, errs, len(annexb), self._kf_ok,
                             annexb[:48].hex())
            if not self._kf_ok:
                return
        elif not self._kf_ok:  # P-frame with no valid keyframe to reference yet
            return
        self._media_count += 1
        self._on_h264(annexb, ts_ms)

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
