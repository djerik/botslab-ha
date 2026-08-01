"""Sensor platform: battery/voltage/SD from the device shadow + last-event info."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import (
    PERCENTAGE,
    EntityCategory,
    UnitOfElectricCurrent,
    UnitOfElectricPotential,
    UnitOfInformation,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.util import dt as dt_util

from .const import SIGNAL_EVENT
from .entity import BotslabEntity
from .models import BotslabConfigEntry, BotslabDevice, BotslabEvent


@dataclass(frozen=True, kw_only=True)
class BotslabSensorDescription(SensorEntityDescription):
    """Describes a device-shadow sensor."""

    value_fn: Callable[[BotslabDevice], float | int | None]


SHADOW_SENSORS: tuple[BotslabSensorDescription, ...] = (
    BotslabSensorDescription(
        key="battery",
        translation_key="battery",
        device_class=SensorDeviceClass.BATTERY,
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda d: d.battery_level,
    ),
    BotslabSensorDescription(
        key="voltage",
        translation_key="voltage",
        device_class=SensorDeviceClass.VOLTAGE,
        native_unit_of_measurement=UnitOfElectricPotential.MILLIVOLT,
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
        value_fn=lambda d: d.voltage_mv,
    ),
    BotslabSensorDescription(
        key="sd_free",
        translation_key="sd_free",
        device_class=SensorDeviceClass.DATA_SIZE,
        native_unit_of_measurement=UnitOfInformation.BYTES,
        suggested_unit_of_measurement=UnitOfInformation.GIBIBYTES,
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda d: d.sd_free_bytes,
    ),
    BotslabSensorDescription(
        key="sd_total",
        translation_key="sd_total",
        device_class=SensorDeviceClass.DATA_SIZE,
        native_unit_of_measurement=UnitOfInformation.BYTES,
        suggested_unit_of_measurement=UnitOfInformation.GIBIBYTES,
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda d: d.sd_total_bytes,
    ),
    BotslabSensorDescription(
        key="sd_used",
        translation_key="sd_used",
        device_class=SensorDeviceClass.DATA_SIZE,
        native_unit_of_measurement=UnitOfInformation.BYTES,
        suggested_unit_of_measurement=UnitOfInformation.GIBIBYTES,
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda d: d.sd_used_bytes,
    ),
    BotslabSensorDescription(
        key="adc_current",
        translation_key="adc_current",
        device_class=SensorDeviceClass.CURRENT,
        native_unit_of_measurement=UnitOfElectricCurrent.MILLIAMPERE,
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda d: d.adc_current_ma,
    ),
    BotslabSensorDescription(
        key="power_supply",
        translation_key="power_supply",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda d: d.power_supply,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: BotslabConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up shadow + diagnostic last-event sensors per device."""
    coordinator = entry.runtime_data.coordinator
    entities: list[SensorEntity] = []
    for device in coordinator.data.values():
        entities.extend(
            BotslabShadowSensor(coordinator, device, desc) for desc in SHADOW_SENSORS
        )
        entities.append(BotslabLastEventSensor(coordinator, device))
        entities.append(BotslabLastEventTimeSensor(coordinator, device))
    async_add_entities(entities)


class BotslabShadowSensor(BotslabEntity, SensorEntity):
    """A sensor backed by a device-shadow property (battery, voltage, SD…)."""

    entity_description: BotslabSensorDescription

    def __init__(
        self, coordinator, device: BotslabDevice, description: BotslabSensorDescription
    ) -> None:
        """Initialise from the description."""
        super().__init__(coordinator, device)
        self.entity_description = description
        self._attr_unique_id = f"{device.unique_id}_{description.key}"

    @property
    def native_value(self) -> float | int | None:
        """Current value from the coordinator's device snapshot."""
        device = self.device
        return self.entity_description.value_fn(device) if device else None


class _BotslabEventTracker(BotslabEntity, SensorEntity):
    """Base for sensors that update on dispatched events for their device."""

    _attr_entity_category = EntityCategory.DIAGNOSTIC

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
        self._store(ev)
        self.async_write_ha_state()

    def _store(self, ev: BotslabEvent) -> None:
        raise NotImplementedError


class BotslabLastEventSensor(_BotslabEventTracker):
    """The type of the most recent event (ring/motion)."""

    _attr_translation_key = "last_event"

    def __init__(self, coordinator, device: BotslabDevice) -> None:
        """Initialise the last-event sensor."""
        super().__init__(coordinator, device)
        self._attr_unique_id = f"{device.unique_id}_last_event"
        self._value: str | None = None

    def _store(self, ev: BotslabEvent) -> None:
        self._value = ev.ha_event

    @property
    def native_value(self) -> str | None:
        """Return the last event name."""
        return self._value


class BotslabLastEventTimeSensor(_BotslabEventTracker):
    """Timestamp of the most recent event."""

    _attr_device_class = SensorDeviceClass.TIMESTAMP
    _attr_translation_key = "last_event_time"

    def __init__(self, coordinator, device: BotslabDevice) -> None:
        """Initialise the last-event-time sensor."""
        super().__init__(coordinator, device)
        self._attr_unique_id = f"{device.unique_id}_last_event_time"
        self._value: datetime | None = None

    def _store(self, ev: BotslabEvent) -> None:
        self._value = dt_util.utc_from_timestamp(ev.ctime) if ev.ctime else dt_util.utcnow()

    @property
    def native_value(self) -> datetime | None:
        """Return the last event timestamp."""
        return self._value
