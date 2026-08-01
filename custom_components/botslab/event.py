"""Event platform: momentary doorbell ring and motion/person events."""

from __future__ import annotations

from homeassistant.components.event import EventDeviceClass, EventEntity
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .const import HA_EVENT_TYPES, SIGNAL_EVENT
from .entity import BotslabEntity
from .models import BotslabConfigEntry, BotslabDevice, BotslabEvent


async def async_setup_entry(
    hass: HomeAssistant,
    entry: BotslabConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up one event entity per device."""
    coordinator = entry.runtime_data.coordinator
    async_add_entities(
        BotslabEventEntity(coordinator, device) for device in coordinator.data.values()
    )


class BotslabEventEntity(BotslabEntity, EventEntity):
    """Fires 'ring' and 'motion' events for a doorbell."""

    _attr_device_class = EventDeviceClass.DOORBELL
    _attr_event_types = HA_EVENT_TYPES
    _attr_translation_key = "doorbell"

    def __init__(self, coordinator, device: BotslabDevice) -> None:
        """Initialise the event entity."""
        super().__init__(coordinator, device)
        self._attr_unique_id = f"{device.unique_id}_event"

    async def async_added_to_hass(self) -> None:
        """Subscribe to dispatched events for this device."""
        await super().async_added_to_hass()
        self.async_on_remove(
            async_dispatcher_connect(self.hass, SIGNAL_EVENT, self._handle_event)
        )

    @callback
    def _handle_event(self, ev: BotslabEvent) -> None:
        if ev.device_name != self._device_id or ev.ha_event is None:
            return
        self._trigger_event(
            ev.ha_event,
            {
                "title": ev.title,
                # not "event_type": that key collides with the entity's own state
                # attribute and would shadow the logical ring/motion/pet value.
                "raw_event_type": ev.event_type,
                "ctime": ev.ctime,
                "snapshot_url": ev.image_url,
                "clip_url": ev.video_url,
                "clip_encrypt": ev.clip_encrypt,
            },
        )
        self.async_write_ha_state()
