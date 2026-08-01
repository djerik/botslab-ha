"""Expose recorded doorbell clips through the Home Assistant media browser.

Each cloud event carries an ``aliyun://`` clip URL (see BotslabEvent). We resolve it on
demand to an HLS (m3u8) URL whose MPEG-TS segments hold ChaCha20-encrypted H.264. Our own
view downloads those segments, decrypts them with the per-event ``secretkey`` and remuxes
the clip to a browser-playable MP4, so the token below carries both the clip URL and its key.
"""

from __future__ import annotations

import base64
import binascii
from datetime import timedelta
import json

from homeassistant.components.media_player import MediaClass, MediaType
from homeassistant.components.media_source import (
    BrowseMediaSource,
    MediaSource,
    MediaSourceItem,
    PlayMedia,
    Unresolvable,
)
from homeassistant.core import HomeAssistant
from homeassistant.util import dt as dt_util

from .const import DOMAIN
from .models import BotslabConfigEntry

# Clips are served by our own view as MP4 (remuxed from the cloud HLS).
_MP4_MIME = "video/mp4"
# The signed clip URL must outlive playback of a short doorbell clip.
_URL_TTL = timedelta(hours=1)


async def async_get_media_source(hass: HomeAssistant) -> BotslabMediaSource:
    """Set up Botslab media source."""
    return BotslabMediaSource(hass)


def _encode_clip(ev) -> str:
    """Pack a clip's URL, key and encryption scheme into a URL-safe token."""
    payload = json.dumps(
        {"u": ev.video_url, "k": ev.clip_secretkey, "e": ev.clip_encrypt},
        separators=(",", ":"),
    )
    return base64.urlsafe_b64encode(payload.encode()).decode()


def _decode_clip(token: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(token.encode()).decode())


class BotslabMediaSource(MediaSource):
    """Browse and resolve recorded Botslab doorbell clips."""

    name = "Botslab Doorbell"

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialise the media source."""
        super().__init__(DOMAIN)
        self.hass = hass

    def _entries(self) -> list[BotslabConfigEntry]:
        return [
            entry
            for entry in self.hass.config_entries.async_loaded_entries(DOMAIN)
            if getattr(entry, "runtime_data", None) is not None
        ]

    async def async_resolve_media(self, item: MediaSourceItem) -> PlayMedia:
        """Resolve a clip item to a signed, HA-served MP4 URL."""
        try:
            entry_id, encoded = item.identifier.split("/", 1)
            _decode_clip(encoded)  # validate it decodes; the view decodes it again
        except (ValueError, binascii.Error, UnicodeDecodeError) as err:
            raise Unresolvable(f"Invalid clip identifier: {item.identifier}") from err

        entry = self.hass.config_entries.async_get_entry(entry_id)
        if entry is None or getattr(entry, "runtime_data", None) is None:
            raise Unresolvable("Botslab account is not loaded")

        # The view resolves + remuxes the clip to MP4 on request; sign the path so the
        # frontend's <video> element can fetch it without a bearer token.
        # Lazy import keeps this platform module light to import in the event loop.
        from homeassistant.components.http.auth import async_sign_path  # noqa: PLC0415

        path = f"/api/botslab/clip/{entry_id}/{encoded}"
        url = async_sign_path(self.hass, path, _URL_TTL)
        return PlayMedia(url, _MP4_MIME)

    async def async_browse_media(self, item: MediaSourceItem) -> BrowseMediaSource:
        """Browse accounts and their recent clips."""
        if not item.identifier:
            return self._browse_root()
        # An account directory: identifier is the entry_id.
        return await self._browse_entry(item.identifier)

    def _browse_root(self) -> BrowseMediaSource:
        children = [
            BrowseMediaSource(
                domain=DOMAIN,
                identifier=entry.entry_id,
                media_class=MediaClass.DIRECTORY,
                media_content_type=MediaType.VIDEO,
                title=entry.title,
                can_play=False,
                can_expand=True,
            )
            for entry in self._entries()
        ]
        return BrowseMediaSource(
            domain=DOMAIN,
            identifier=None,
            media_class=MediaClass.DIRECTORY,
            media_content_type=MediaType.VIDEO,
            title="Botslab Doorbell",
            can_play=False,
            can_expand=True,
            children=children,
            children_media_class=MediaClass.DIRECTORY,
        )

    async def _browse_entry(self, entry_id: str) -> BrowseMediaSource:
        entry = self.hass.config_entries.async_get_entry(entry_id)
        if entry is None or getattr(entry, "runtime_data", None) is None:
            raise Unresolvable("Botslab account is not loaded")

        await entry.runtime_data.coordinator.ensure_session()
        events = await entry.runtime_data.api.message_list(page_size=50)
        clips = [ev for ev in events if ev.has_clip and ev.video_url]
        children = [
            BrowseMediaSource(
                domain=DOMAIN,
                identifier=f"{entry_id}/{_encode_clip(ev)}",
                media_class=MediaClass.VIDEO,
                media_content_type=MediaType.VIDEO,
                title=self._clip_title(ev),
                can_play=True,
                can_expand=False,
                # The event's unencrypted OSS snapshot doubles as the clip thumbnail.
                thumbnail=ev.image_url,
            )
            for ev in clips
        ]
        return BrowseMediaSource(
            domain=DOMAIN,
            identifier=entry_id,
            media_class=MediaClass.DIRECTORY,
            media_content_type=MediaType.VIDEO,
            title=entry.title,
            can_play=False,
            can_expand=True,
            children=children,
            children_media_class=MediaClass.VIDEO,
            thumbnail=next((ev.image_url for ev in clips if ev.image_url), None),
        )

    @staticmethod
    def _clip_title(ev) -> str:
        when = dt_util.utc_from_timestamp(ev.ctime) if ev.ctime else dt_util.utcnow()
        when = dt_util.as_local(when).strftime("%Y-%m-%d %H:%M:%S")
        label = ev.title or ev.ha_event or "Clip"
        return f"{when} — {label}"
