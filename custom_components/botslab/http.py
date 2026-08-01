"""Serve a recorded doorbell clip as a browser-playable MP4.

The cloud clip is delivered as HLS (an m3u8 whose .ts segments live on Aliyun OSS) and the
H.264 video inside those segments is ChaCha20-encrypted (``encrypt: "chacha2"``). This view
resolves the clip, downloads and decrypts the segments (see clip_crypto), then lets ffmpeg's
HLS demuxer stitch them into one complete MP4 (stream copy, no re-encode, so it stays cheap on
low-power NAS hardware). Using the HLS demuxer — instead of concatenating the segments into one
raw MPEG-TS — is what keeps the timeline continuous across the per-segment timestamp resets that
otherwise leave the browser with a ~1s clip. The media source hands out a signed URL to this view.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import hashlib
import json
import logging
import os
import shutil
import tempfile
import time

from aiohttp import ClientError, ClientTimeout, web
from homeassistant.components.ffmpeg import get_ffmpeg_manager
from homeassistant.components.http import HomeAssistantView
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .clip_crypto import decrypt_mpegts
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

_REGISTERED = f"{DOMAIN}_clip_view"
_TIMEOUT = ClientTimeout(total=30)
# Keep the frontend service worker from caching (and later re-serving a stale) clip.
_NO_STORE = {"Cache-Control": "no-store"}
# Remuxed clips are cached on disk so the browser's follow-up HTTP Range requests (needed for
# <video> playback and seeking) are served straight from the file instead of re-downloading and
# re-decrypting every time. Entries are evicted after this many seconds.
_CACHE_TTL = 3600


def _read_bytes(path: str) -> bytes:
    with open(path, "rb") as handle:
        return handle.read()


def _cache_path(token: str) -> str:
    digest = hashlib.sha256(token.encode()).hexdigest()[:32]
    return os.path.join(tempfile.gettempdir(), "botslab_clips", f"{digest}.mp4")


def _cache_valid(path: str) -> bool:
    with contextlib.suppress(OSError):
        return os.path.getsize(path) > 0 and os.path.getmtime(path) > time.time() - _CACHE_TTL
    return False


def _write_cache(path: str, data: bytes) -> None:
    cache_dir = os.path.dirname(path)
    os.makedirs(cache_dir, exist_ok=True)
    cutoff = time.time() - _CACHE_TTL
    for name in os.listdir(cache_dir):  # evict stale clips to bound disk use
        stale = os.path.join(cache_dir, name)
        with contextlib.suppress(OSError):
            if os.path.getmtime(stale) < cutoff:
                os.remove(stale)
    tmp = f"{path}.{os.getpid()}.tmp"
    with open(tmp, "wb") as handle:
        handle.write(data)
    os.replace(tmp, path)


def _localize_playlist(text: str, count: int) -> str:
    """Rewrite a media playlist's segment URLs to local ``seg{i}.ts`` names, keeping the
    #EXTINF timing so the HLS demuxer reproduces the original timeline."""
    lines: list[str] = []
    i = 0
    for line in text.splitlines():
        if line.strip() and not line.startswith("#"):
            lines.append(f"seg{i}.ts")
            i += 1
        else:
            lines.append(line)
    if i != count or "#EXT-X-ENDLIST" not in text:
        # Fall back to a minimal VOD playlist if the source was not a normal media playlist.
        lines = ["#EXTM3U", "#EXT-X-VERSION:3", "#EXT-X-TARGETDURATION:10"]
        for j in range(count):
            lines += ["#EXTINF:10.0,", f"seg{j}.ts"]
        lines.append("#EXT-X-ENDLIST")
    return "\n".join(lines) + "\n"


def _mp4_duration(data: bytes) -> float:
    """Best-effort MP4 movie duration in seconds (from the mvhd box), for logging."""
    idx = data.find(b"mvhd")
    if idx < 0:
        return 0.0
    ver = data[idx + 4]
    try:
        if ver == 1:
            timescale = int.from_bytes(data[idx + 24 : idx + 28], "big")
            duration = int.from_bytes(data[idx + 28 : idx + 36], "big")
        else:
            timescale = int.from_bytes(data[idx + 16 : idx + 20], "big")
            duration = int.from_bytes(data[idx + 20 : idx + 24], "big")
    except (IndexError, ValueError):
        return 0.0
    return duration / timescale if timescale else 0.0


def async_register_clip_view(hass: HomeAssistant) -> None:
    """Register the clip view once for the whole integration."""
    if hass.data.get(_REGISTERED):
        return
    hass.http.register_view(BotslabClipView(hass))
    hass.data[_REGISTERED] = True


class BotslabClipView(HomeAssistantView):
    """Serves a doorbell clip as MP4 (decrypted + remuxed from the cloud HLS)."""

    url = "/api/botslab/clip/{entry_id}/{token}"
    name = "api:botslab:clip"
    requires_auth = True

    def __init__(self, hass: HomeAssistant) -> None:
        """Store hass."""
        self.hass = hass

    async def get(
        self, request: web.Request, entry_id: str, token: str
    ) -> web.StreamResponse:
        """Resolve the clip, decrypt it and serve it as a complete, seekable MP4."""
        _LOGGER.debug(
            "botslab clip request: method=%s range=%r", request.method, request.headers.get("Range")
        )
        try:
            clip = json.loads(base64.urlsafe_b64decode(token.encode()).decode())
            aliyun_url = clip["u"]
        except (binascii.Error, UnicodeDecodeError, ValueError, KeyError):
            return web.Response(status=400, text="bad token")

        # A cached remux serves the browser's Range requests without touching the cloud again.
        cache_path = _cache_path(token)
        if await self.hass.async_add_executor_job(_cache_valid, cache_path):
            return web.FileResponse(cache_path, headers=_NO_STORE)

        entry = self.hass.config_entries.async_get_entry(entry_id)
        if entry is None or getattr(entry, "runtime_data", None) is None:
            return web.Response(status=404, text="account not loaded")
        secretkey = clip.get("k")
        encrypt = clip.get("e")

        runtime = entry.runtime_data
        await runtime.coordinator.ensure_session()
        try:
            play_url = await runtime.api.resolve_clip_url(aliyun_url)
            if not play_url:
                raise ValueError("could not resolve clip")
            playlist, segments = await self._fetch_clip(play_url)
        except (TimeoutError, ClientError, ValueError) as err:
            _LOGGER.error("clip fetch failed: %s", err)
            return web.Response(status=502, text="clip fetch failed")

        if encrypt == "chacha2" and secretkey:
            segments = [
                await self.hass.async_add_executor_job(decrypt_mpegts, seg, secretkey)
                for seg in segments
            ]

        data = await self._remux(playlist, segments)
        if data is None:
            return web.Response(status=502, text="clip remux failed")
        _LOGGER.debug(
            "botslab clip: %d segment(s), %d TS bytes -> %d MP4 bytes, duration=%.2fs",
            len(segments),
            sum(len(s) for s in segments),
            len(data),
            _mp4_duration(data),
        )
        await self.hass.async_add_executor_job(_write_cache, cache_path, data)
        return web.FileResponse(cache_path, headers=_NO_STORE)

    async def _fetch_clip(self, play_url: str) -> tuple[str, list[bytes]]:
        """Download the HLS media playlist and its MPEG-TS segments."""
        session = async_get_clientsession(self.hass)
        async with session.get(play_url, timeout=_TIMEOUT) as resp:
            resp.raise_for_status()
            body = await resp.read()
            base = str(resp.url)
        playlist = body.decode("utf-8", "replace")
        segment_urls = [
            (line if line.startswith("http") else base.rsplit("/", 1)[0] + "/" + line)
            for raw in playlist.splitlines()
            if (line := raw.strip()) and not line.startswith("#")
        ]
        if not segment_urls:  # the resolved URL was already a single .ts, not a playlist
            if not body:
                raise ValueError("empty clip")
            return "", [body]
        segments: list[bytes] = []
        for seg_url in segment_urls:
            async with session.get(seg_url, timeout=_TIMEOUT) as resp:
                resp.raise_for_status()
                segments.append(await resp.read())
        if not any(segments):
            raise ValueError("empty clip")
        return playlist, segments

    async def _remux(self, playlist: str, segments: list[bytes]) -> bytes | None:
        """Stitch the decrypted segments into a faststart MP4 via ffmpeg's HLS demuxer."""
        work = await self.hass.async_add_executor_job(
            self._write_work_dir, playlist, segments
        )
        binary = get_ffmpeg_manager(self.hass).binary
        try:
            proc = await asyncio.create_subprocess_exec(
                binary,
                "-hide_banner",
                "-loglevel",
                "error",
                "-nostdin",
                "-protocol_whitelist",
                "file,crypto,data",
                "-allowed_extensions",
                "ALL",
                "-f",
                "hls",
                "-i",
                os.path.join(work, "index.m3u8"),
                "-map",
                "0",
                "-c",
                "copy",
                "-movflags",
                "+faststart",
                "-y",
                os.path.join(work, "out.mp4"),
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
            _, err = await proc.communicate()
            if proc.returncode != 0:
                _LOGGER.error(
                    "ffmpeg clip remux rc=%s: %s",
                    proc.returncode,
                    err.decode("utf-8", "replace")[:1200] or "<no stderr>",
                )
                return None
            return await self.hass.async_add_executor_job(
                _read_bytes, os.path.join(work, "out.mp4")
            )
        finally:
            await self.hass.async_add_executor_job(
                shutil.rmtree, work, True  # ignore_errors
            )

    @staticmethod
    def _write_work_dir(playlist: str, segments: list[bytes]) -> str:
        """Write the segments and a localized playlist to a temp dir; return its path."""
        work = tempfile.mkdtemp(prefix="botslab_clip_")
        for i, seg in enumerate(segments):
            with open(os.path.join(work, f"seg{i}.ts"), "wb") as handle:
                handle.write(seg)
        with open(os.path.join(work, "index.m3u8"), "w", encoding="utf-8") as handle:
            handle.write(_localize_playlist(playlist, len(segments)))
        return work
