"""Binary sensor platform: connectivity, low-power, SD card (from device shadow)."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .entity import BotslabEntity
from .models import BotslabConfigEntry, BotslabDevice


@dataclass(frozen=True, kw_only=True)
class BotslabBinaryDescription(BinarySensorEntityDescription):
    """Describes a device-shadow binary sensor."""

    value_fn: Callable[[BotslabDevice], bool | None]


BINARY_SENSORS: tuple[BotslabBinaryDescription, ...] = (
    BotslabBinaryDescription(
        key="online",
        translation_key="online",
        device_class=BinarySensorDeviceClass.CONNECTIVITY,
        value_fn=lambda d: d.online_state,
    ),
    BotslabBinaryDescription(
        key="low_power",
        translation_key="low_power",
        device_class=BinarySensorDeviceClass.BATTERY,  # on = low
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda d: d.low_power,
    ),
    BotslabBinaryDescription(
        key="sd_card",
        translation_key="sd_card",
        device_class=BinarySensorDeviceClass.PROBLEM,  # on = missing/problem
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda d: (None if d.sd_present is None else not d.sd_present),
    ),
    BotslabBinaryDescription(
        key="battery_pack",
        translation_key="battery_pack",
        device_class=BinarySensorDeviceClass.PLUG,  # on = pack installed
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda d: d.battery_pack_installed,
    ),
    BotslabBinaryDescription(
        key="chime",
        translation_key="chime",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda d: d.existing_chime,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: BotslabConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up binary sensors per device."""
    coordinator = entry.runtime_data.coordinator
    async_add_entities(
        BotslabBinarySensor(coordinator, device, desc)
        for device in coordinator.data.values()
        for desc in BINARY_SENSORS
    )


class BotslabBinarySensor(BotslabEntity, BinarySensorEntity):
    """A binary sensor backed by a device-shadow property."""

    entity_description: BotslabBinaryDescription

    def __init__(
        self, coordinator, device: BotslabDevice, description: BotslabBinaryDescription
    ) -> None:
        """Initialise from the description."""
        super().__init__(coordinator, device)
        self.entity_description = description
        self._attr_unique_id = f"{device.unique_id}_{description.key}"

    @property
    def is_on(self) -> bool | None:
        """Current state from the coordinator's device snapshot."""
        device = self.device
        return self.entity_description.value_fn(device) if device else None

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        """Expose the full device shadow (all settings) on the connectivity sensor."""
        if self.entity_description.key != "online":
            return None
        device = self.device
        return dict(device.props) if device and device.props else None
