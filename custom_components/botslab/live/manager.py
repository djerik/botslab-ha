"""Async bridge from the pure-Python :class:`~.engine.LiveEngine` to a Home Assistant camera.

The engine emits decrypted **Annex-B H.264** from a worker thread. This module:

  1. runs the engine in an executor thread and feeds its output into ``ffmpeg``;
  2. muxes to **MPEG-TS with ``-c copy``** — no re-encode, so it runs on a transcode-less NAS
     (e.g. a Synology DS713+); wall-clock timestamps make it a real-time live source;
  3. serves the MPEG-TS over a local TCP server that Home Assistant's ``stream`` opens as the
     camera ``stream_source`` (``tcp://127.0.0.1:<port>``);
  4. tears the engine down when no client is connected, so the battery doorbell stops
     publishing as soon as nobody is watching.

It also supplies the engine's HTTP transport (:class:`HassHttp`), so the cloud calls made from
the worker thread go out on Home Assistant's shared aiohttp session.

This is the only live module that imports Home Assistant.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
import contextlib
import logging

from aiohttp import ClientError, ClientTimeout
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from yarl import URL

from ._http import TIMEOUT as _HTTP_TIMEOUT, Http
from .engine import LiveEngine

_LOGGER = logging.getLogger(__name__)

# ffmpeg: remux the raw H.264 elementary stream to MPEG-TS, copying the video (no transcode).
# Wall-clock input timestamps turn the live feed into a correctly paced real-time stream.
# Video-only: the doorbell sends no audio over the relay yet. (A synthetic AAC track was tried
# to appease go2rtc but it broke HA's HLS muxer — "Malformed AAC bitstream" — so the camera
# forces the HLS front-end path instead, see camera.py.)
# Low-latency input flags are critical to the cold start: ffmpeg's default analyzeduration probes
# ~5s of stream time before emitting anything, which on a ~5 fps live feed pushes first output
# past Home Assistant's 10s stream_source timeout. Disabling the time-based probe (analyzeduration
# 0, small probesize, nobuffer/low_delay) drops first-MPEG-TS-byte latency ~4.4s -> ~1.0s (measured,
# paced feed) with no downside for a copy remux whose SPS/PPS are in-band on the first keyframe.
#
# The ~1s that still elapses between the first keyframe and the first MPEG-TS byte is NOT worth
# chasing with more input flags. Measured on a paced feed shaped like this one, first-output
# latency was identical (2.04s) across probesize 4k-100k, fpsprobesize 0, an explicit input -r,
# flush_packets and muxdelay/muxpreload 0. It tracks the source GOP, so it is the muxer waiting on
# frame structure, not buffering we can flush away.
_FFMPEG_ARGS = (
    "-hide_banner", "-loglevel", "error",
    "-fflags", "nobuffer", "-flags", "low_delay",
    "-probesize", "100000", "-analyzeduration", "0",
    "-use_wallclock_as_timestamps", "1",
    "-f", "h264", "-i", "pipe:0",
    "-c", "copy", "-f", "mpegts", "pipe:1",
)

_IDLE_GRACE = 25.0  # seconds with no client before tearing the engine down (spares the battery)
# How long stream_source waits for the first MPEG-TS bytes before handing the URL over anyway.
# Long enough that a warm re-open (media already flowing) still returns a proven-live stream, short
# enough that a cold wake reaches the frontend quickly — see async_get_stream_source.
_FIRST_MEDIA_HINT = 2.5
_READ_CHUNK = 65536

_HTTP_CLIENT_TIMEOUT = ClientTimeout(total=_HTTP_TIMEOUT)
# The worker thread waits a little longer than the request itself, so a request that does time out
# surfaces as its own ClientError rather than as an opaque wait timeout here.
_HTTP_WAIT = _HTTP_TIMEOUT + 5


class HassHttp(Http):
    """The live transport's HTTP calls, sent on Home Assistant's shared aiohttp session.

    The engine is synchronous and runs in an executor thread, so each call hands its coroutine to
    the event loop and blocks on the result. That keeps the transport code unchanged while every
    request still uses the session Home Assistant owns — one connection pool, its TLS context,
    torn down with the instance — instead of a private urllib client.

    Failures are re-raised as ``OSError`` (what ``urllib`` raised, and what the callers already
    catch); a bad HTTP status counts as one, matching ``urllib``'s ``HTTPError``.
    """

    def __init__(self, hass: HomeAssistant) -> None:
        """Bind to the running instance; the session is looked up per request."""
        self._hass = hass

    def request(self, method: str, url: str, *, body: bytes | None,
                headers: dict[str, str]) -> bytes:
        """Blocking send from the engine thread; returns the raw response body."""

        async def _run() -> bytes:
            session = async_get_clientsession(self._hass)
            # encoded=True: these URLs are pre-signed (the /substream query is signed verbatim),
            # so yarl must pass them through byte-for-byte rather than re-encode them.
            async with session.request(method, URL(url, encoded=True), data=body, headers=headers,
                                       timeout=_HTTP_CLIENT_TIMEOUT) as resp:
                resp.raise_for_status()
                return await resp.read()

        try:
            return asyncio.run_coroutine_threadsafe(_run(), self._hass.loop).result(_HTTP_WAIT)
        except (ClientError, RuntimeError) as err:  # RuntimeError: loop gone (shutdown mid-session)
            raise OSError(f"{method} {url.split('?', 1)[0]}: {err}") from err


class LiveStreamManager:
    """Owns one live session for a device; started on demand, idle-stopped to spare the battery."""

    def __init__(self, hass: HomeAssistant, ffmpeg_bin: str, *, region: str, product_key: str,
                 sn: str, m2: str, session_provider: Callable[[], tuple[str, str, str]]) -> None:
        """``session_provider`` returns the current ``(Q, T, sid)`` — read at each (re)start so
        relogins are picked up and the engine reuses the coordinator's active session."""
        # Set by the camera entity so it can reflect an active session in its state; the cold start
        # takes several seconds, and without this the entity reads "idle" the whole way through.
        self.on_state: Callable[[bool], None] | None = None
        self._hass = hass
        self._ffmpeg_bin = ffmpeg_bin
        self._region, self._product_key, self._sn = region, product_key, sn
        self._m2, self._session_provider = m2, session_provider
        self._http = HassHttp(hass)

        self._lock = asyncio.Lock()
        self._running = False
        self._engine: LiveEngine | None = None
        self._engine_future: asyncio.Future | None = None
        self._ff: asyncio.subprocess.Process | None = None
        self._pump_task: asyncio.Task | None = None
        self._server: asyncio.Server | None = None
        self._port = 0
        self._clients: set[asyncio.StreamWriter] = set()
        self._idle_handle: asyncio.TimerHandle | None = None
        self._first_media = asyncio.Event()  # set once ffmpeg emits its first MPEG-TS bytes

    # ------------------------------------------------------------------ public
    async def async_get_stream_source(self) -> str:
        """Start the session and return the local MPEG-TS URL, briefly waiting for media first.

        Blocking here until ffmpeg emits bytes is what stopped Home Assistant's ``av.open()``
        timing out during the doorbell's cold wake (the "Immediate exit requested" failures). But
        the frontend cannot draw a player until it has a URL, so blocking for the whole wake left
        the card showing a bare snapshot with no controls for several seconds.

        The wait is therefore capped: a warm re-open still returns a stream that is provably live,
        while a cold wake hands the URL over early and lets the player show its own loading state
        as the stream fills in. The local server accepts the connection immediately either way.

        Safe to block at all because the WebRTC provider is disabled (see camera.py), so nothing
        calls this eagerly at entity setup — only a real viewer does. The engine is torn down
        shortly after the last viewer leaves, so the battery unit publishes only while watched.
        """
        async with self._lock:
            self._cancel_idle()
            if self._server is None:
                self._server = await asyncio.start_server(self._on_client, "127.0.0.1", 0)
                self._port = self._server.sockets[0].getsockname()[1]
            if not self._running:
                await self._start_locked()
        try:
            await asyncio.wait_for(self._first_media.wait(), timeout=_FIRST_MEDIA_HINT)
        except TimeoutError:
            # Still waking. Hand the URL over regardless so the frontend can draw a player; the
            # engine keeps warming and the bytes reach the client as soon as the device publishes.
            _LOGGER.debug("live %s: no media yet after %.1fs, returning URL while it warms",
                          self._sn, _FIRST_MEDIA_HINT)
        except asyncio.CancelledError:
            # Keep the now-warming engine up for the idle grace so a retry returns instantly.
            self._schedule_idle()
            raise
        self._schedule_idle()  # safety: tear down if HA never connects to the URL
        return f"tcp://127.0.0.1:{self._port}"

    async def async_stop(self) -> None:
        """Full teardown (engine + ffmpeg + server) — called on unload."""
        async with self._lock:
            self._cancel_idle()
            await self._stop_engine_locked()
            if self._server is not None:
                self._server.close()
                with contextlib.suppress(Exception):
                    await self._server.wait_closed()
                self._server = None
            for writer in list(self._clients):
                with contextlib.suppress(OSError):
                    writer.close()
            self._clients.clear()

    # ------------------------------------------------------------------ start
    async def _start_locked(self) -> None:
        self._first_media = asyncio.Event()
        self._ff = await asyncio.create_subprocess_exec(
            self._ffmpeg_bin, *_FFMPEG_ARGS,
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL)
        self._pump_task = self._hass.async_create_background_task(
            self._pump_ffmpeg(), name=f"botslab_live_pump_{self._sn}")

        q, t, sid = self._session_provider()
        engine = LiveEngine(
            q=q, t=t, sid=sid, region=self._region, product_key=self._product_key, sn=self._sn,
            m2=self._m2, on_h264=self._sink, ffmpeg_bin=self._ffmpeg_bin, http=self._http)
        self._engine = engine
        self._engine_future = self._hass.loop.run_in_executor(None, self._run_engine, engine)
        self._running = True
        self._notify_state(True)
        _LOGGER.debug("live session started for %s (port %d)", self._sn, self._port)

    def _notify_state(self, streaming: bool) -> None:
        if self.on_state is not None:
            self.on_state(streaming)

    def _run_engine(self, engine: LiveEngine) -> None:
        """Executor-thread body: run the blocking engine, logging any setup failure."""
        try:
            engine.run()
        except Exception as err:  # log whatever went wrong and let the client drop
            _LOGGER.warning("live engine for %s stopped: %s", self._sn, err)

    # --------------------------------------------------------------- data flow
    def _sink(self, chunk: bytes) -> None:
        """Engine-thread callback: hand H.264 to the event loop for ffmpeg's stdin."""
        self._hass.loop.call_soon_threadsafe(self._write_ffmpeg, chunk)

    def _write_ffmpeg(self, chunk: bytes) -> None:
        ff = self._ff
        if ff is not None and ff.stdin is not None and not ff.stdin.is_closing():
            with contextlib.suppress(BrokenPipeError, ConnectionResetError, OSError):
                ff.stdin.write(chunk)

    async def _pump_ffmpeg(self) -> None:
        """Read MPEG-TS from ffmpeg and fan it out to every connected client."""
        ff = self._ff
        if ff is None or ff.stdout is None:
            return
        first = True
        try:
            while True:
                chunk = await ff.stdout.read(_READ_CHUNK)
                if not chunk:
                    break
                if first:
                    _LOGGER.info("live %s: ffmpeg producing MPEG-TS (%d clients)",
                                 self._sn, len(self._clients))
                    first = False
                    self._first_media.set()
                self._broadcast(chunk)
        except asyncio.CancelledError:
            raise
        except Exception as err:
            _LOGGER.debug("live ffmpeg pump ended for %s: %s", self._sn, err)

    def _broadcast(self, chunk: bytes) -> None:
        for writer in list(self._clients):
            try:
                writer.write(chunk)
            except (ConnectionResetError, BrokenPipeError, OSError):
                self._clients.discard(writer)

    async def _on_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._cancel_idle()
        if not self._running:  # reconnect after an idle teardown — bring the engine back up
            async with self._lock:
                if not self._running:
                    await self._start_locked()
        self._clients.add(writer)
        _LOGGER.info("live %s: consumer connected (%d total), engine warming up",
                     self._sn, len(self._clients))
        try:
            while await reader.read(_READ_CHUNK):  # HA only reads; EOF => client gone
                pass
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass
        finally:
            self._clients.discard(writer)
            with contextlib.suppress(OSError):
                writer.close()
            _LOGGER.debug("live %s: consumer disconnected (%d left)", self._sn, len(self._clients))
            if not self._clients:
                self._schedule_idle()

    # ------------------------------------------------------------------ idle
    def _schedule_idle(self) -> None:
        self._cancel_idle()
        self._idle_handle = self._hass.loop.call_later(
            _IDLE_GRACE, lambda: self._hass.async_create_task(self._async_idle_stop()))

    def _cancel_idle(self) -> None:
        if self._idle_handle is not None:
            self._idle_handle.cancel()
            self._idle_handle = None

    async def _async_idle_stop(self) -> None:
        self._idle_handle = None
        async with self._lock:
            if self._clients:  # someone reconnected during the grace window
                return
            _LOGGER.debug("live session idle for %s, stopping engine", self._sn)
            await self._stop_engine_locked()

    async def _stop_engine_locked(self) -> None:
        if self._engine is not None:
            self._engine.stop()
        if self._engine_future is not None:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(asyncio.shield(self._engine_future), timeout=5)
        if self._pump_task is not None:
            self._pump_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._pump_task
        if self._ff is not None:
            with contextlib.suppress(ProcessLookupError, OSError):
                self._ff.terminate()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._ff.wait(), timeout=5)
        self._engine = self._engine_future = self._pump_task = self._ff = None
        self._running = False
        self._notify_state(False)
