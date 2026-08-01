"""Camera platform: pure-Python live view for the Botslab doorbell.

Each device gets one camera whose ``stream_source`` is a local MPEG-TS feed produced by the
pure-Python live pipeline (see :mod:`.live`). The heavy lifting — handshake, decrypt,
ffmpeg remux (``-c copy``, no transcode) — lives in :class:`.live.manager.LiveStreamManager`;
this module is just the HA entity wiring.

The live session starts only while the stream is being watched and stops shortly after, so the
battery doorbell publishes (and drains) only on demand. ``async_camera_image`` deliberately
returns ``None``: producing a still would wake the doorbell on every thumbnail poll. The
separate image entity already serves the latest event snapshot.
"""

from __future__ import annotations

import logging

from homeassistant.components.camera import Camera, CameraEntityFeature, StreamType
from homeassistant.components.ffmpeg import get_ffmpeg_manager
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .const import CONF_M2, CONF_REGION, DEFAULT_REGION
from .coordinator import BotslabCoordinator
from .entity import BotslabEntity
from .live.manager import LiveStreamManager
from .models import BotslabConfigEntry, BotslabDevice

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: BotslabConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up one live-view camera per device."""
    runtime = entry.runtime_data
    coordinator = runtime.coordinator
    api = runtime.api
    ffmpeg_bin = get_ffmpeg_manager(hass).binary
    region = entry.data.get(CONF_REGION, DEFAULT_REGION)
    m2 = entry.data[CONF_M2]

    entities: list[BotslabCamera] = []
    for device in coordinator.data.values():
        manager = LiveStreamManager(
            hass, ffmpeg_bin, region=region, product_key=device.product_key,
            sn=device.device_name, m2=m2,
            session_provider=lambda: (api.q, api.t, api.sid))
        entry.async_on_unload(manager.async_stop)
        entities.append(BotslabCamera(coordinator, device, manager))
    async_add_entities(entities)


class BotslabCamera(BotslabEntity, Camera):
    """Live-view camera backed by the pure-Python transport."""

    _attr_translation_key = "live"
    _attr_supported_features = CameraEntityFeature.STREAM

    def __init__(self, coordinator: BotslabCoordinator, device: BotslabDevice,
                 manager: LiveStreamManager) -> None:
        """Initialise the camera and bind it to its live-stream manager."""
        BotslabEntity.__init__(self, coordinator, device)
        Camera.__init__(self)
        self._manager = manager
        self._sn = device.device_name
        self._attr_unique_id = f"{device.unique_id}_live"
        manager.on_state = self._handle_stream_state

    def _handle_stream_state(self, streaming: bool) -> None:
        """Reflect an active live session in the entity state (idle -> streaming).

        Waking the doorbell and reaching first frame takes several seconds, and the camera card can
        only show a still until then. Without this the entity reads "idle" for that whole window,
        so there is nothing a dashboard or automation can key off to show the stream is coming.
        """
        self._attr_is_streaming = streaming
        if self.hass is not None:
            self.async_write_ha_state()

    @property
    def frontend_stream_type(self) -> StreamType:
        """Force the HLS front-end path (see async_refresh_providers)."""
        return StreamType.HLS

    async def async_refresh_providers(self, *, write_state: bool = True) -> None:
        """Never attach a WebRTC provider — this camera is HLS-only.

        go2rtc (the default WebRTC provider) is auto-attached to any camera with a stream
        source, and its client then crashes parsing our video-only MPEG-TS stream (the url-less
        consumer producer). By leaving the provider unset, the frontend never offers WebRTC and
        falls back to HLS via Home Assistant's native ``stream`` component, which works with our
        ``-c copy`` feed. HLS itself does not use go2rtc.
        """
        self._webrtc_provider = None
        self._legacy_webrtc_provider = None
        if write_state:
            self.async_write_ha_state()

    async def stream_source(self) -> str | None:
        """Return the local MPEG-TS URL, starting the live session on demand."""
        return await self._manager.async_get_stream_source()

    async def async_camera_image(
        self, width: int | None = None, height: int | None = None
    ) -> bytes | None:
        """Serve the latest cached event snapshot as the still/thumbnail.

        This is the same snapshot the coordinator caches for the image entity, so the camera
        card shows a picture without ever waking the doorbell (a per-thumbnail live wake would
        drain the battery). Returns ``None`` until the first snapshot has been captured.
        """
        return self.coordinator.snapshot_bytes.get(self._sn)
