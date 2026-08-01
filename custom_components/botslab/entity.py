"""Base entity for Botslab devices."""

from __future__ import annotations

from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, MANUFACTURER
from .coordinator import BotslabCoordinator
from .models import BotslabDevice


class BotslabEntity(CoordinatorEntity[BotslabCoordinator]):
    """Common base tying an entity to a Botslab device."""

    _attr_has_entity_name = True

    def __init__(self, coordinator: BotslabCoordinator, device: BotslabDevice) -> None:
        """Initialise with the coordinator and the device it represents."""
        super().__init__(coordinator)
        self._device_id = device.unique_id
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, device.unique_id)},
            manufacturer=MANUFACTURER,
            name=device.device_title,
            model=device.raw.get("product_name") or device.device_title,
            serial_number=device.device_name,
        )

    @property
    def device(self) -> BotslabDevice | None:
        """Current device snapshot from the coordinator, if still present."""
        return self.coordinator.data.get(self._device_id)

    @property
    def available(self) -> bool:
        """Entity is available while the coordinator succeeds and the device exists."""
        return super().available and self.device is not None
