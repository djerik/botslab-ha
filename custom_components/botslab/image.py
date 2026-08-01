"""Image platform: latest event snapshot per device.

The snapshot bytes are cached in the coordinator at poll time (while the OSS signed URL is
still valid), so the most recent snapshot is available immediately after a restart rather than
only after the next live event. This entity just serves those cached bytes.
"""

from __future__ import annotations

from homeassistant.components.image import ImageEntity
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .const import SIGNAL_SNAPSHOT
from .coordinator import BotslabCoordinator
from .entity import BotslabEntity
from .models import BotslabConfigEntry, BotslabDevice


async def async_setup_entry(
    hass: HomeAssistant,
    entry: BotslabConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up a last-snapshot image entity per device."""
    coordinator = entry.runtime_data.coordinator
    async_add_entities(
        BotslabSnapshot(coordinator, device, hass) for device in coordinator.data.values()
    )


class BotslabSnapshot(BotslabEntity, ImageEntity):
    """Shows the snapshot from the most recent event (ring/motion/…).

    The event snapshot lives on OSS behind a short-lived signed URL. The coordinator downloads
    and caches the bytes as soon as the event is polled (while the URL is valid), so we serve
    those cached bytes — a later fetch of the expired URL would 403.
    """

    _attr_translation_key = "last_snapshot"
    _attr_content_type = "image/jpeg"

    def __init__(
        self, coordinator: BotslabCoordinator, device: BotslabDevice, hass: HomeAssistant
    ) -> None:
        """Initialise the snapshot entity."""
        BotslabEntity.__init__(self, coordinator, device)
        ImageEntity.__init__(self, hass)
        self._attr_unique_id = f"{device.unique_id}_snapshot"
        self._attr_image_url = None  # we serve cached bytes from async_image()
        self._sn = device.device_name

    @property
    def available(self) -> bool:
        """Available once a snapshot has been cached for this device."""
        return self.coordinator.snapshot_bytes.get(self._sn) is not None

    async def async_image(self) -> bytes | None:
        """Return the cached snapshot bytes."""
        return self.coordinator.snapshot_bytes.get(self._sn)

    async def async_added_to_hass(self) -> None:
        """Publish the snapshot already cached at startup, then follow updates."""
        await super().async_added_to_hass()
        if self._sn in self.coordinator.snapshot_updated:
            self._attr_image_last_updated = self.coordinator.snapshot_updated[self._sn]
        self.async_on_remove(
            async_dispatcher_connect(self.hass, SIGNAL_SNAPSHOT, self._handle_snapshot)
        )

    @callback
    def _handle_snapshot(self, device_name: str) -> None:
        if device_name != self._sn:
            return
        self._attr_image_last_updated = self.coordinator.snapshot_updated.get(self._sn)
        self._cached_image = None
        self.async_write_ha_state()
