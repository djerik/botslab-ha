"""Device automation triggers: ring / motion / person / pet / package / vehicle."""

from __future__ import annotations

from typing import Any

from homeassistant.components.device_automation import DEVICE_TRIGGER_BASE_SCHEMA
from homeassistant.const import CONF_DEVICE_ID, CONF_DOMAIN, CONF_PLATFORM, CONF_TYPE
from homeassistant.core import CALLBACK_TYPE, HomeAssistant, callback
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.trigger import TriggerActionType, TriggerInfo
from homeassistant.helpers.typing import ConfigType
import voluptuous as vol

from .const import DOMAIN, HA_EVENT_TYPES, SIGNAL_EVENT
from .models import BotslabEvent

TRIGGER_SCHEMA = DEVICE_TRIGGER_BASE_SCHEMA.extend(
    {vol.Required(CONF_TYPE): vol.In(HA_EVENT_TYPES)}
)


def _device_serial(hass: HomeAssistant, device_id: str) -> str | None:
    """Map a HA device id back to the Botslab device serial (unique_id)."""
    device = dr.async_get(hass).async_get(device_id)
    if device is None:
        return None
    for domain, ident in device.identifiers:
        if domain == DOMAIN:
            return ident
    return None


async def async_get_triggers(
    hass: HomeAssistant, device_id: str
) -> list[dict[str, Any]]:
    """List the triggers available for a Botslab device."""
    return [
        {
            CONF_PLATFORM: "device",
            CONF_DOMAIN: DOMAIN,
            CONF_DEVICE_ID: device_id,
            CONF_TYPE: trigger_type,
        }
        for trigger_type in HA_EVENT_TYPES
    ]


async def async_attach_trigger(
    hass: HomeAssistant,
    config: ConfigType,
    action: TriggerActionType,
    trigger_info: TriggerInfo,
) -> CALLBACK_TYPE:
    """Attach a trigger; fire when the matching event arrives for the device."""
    serial = _device_serial(hass, config[CONF_DEVICE_ID])
    trigger_type = config[CONF_TYPE]

    @callback
    def _handle(ev: BotslabEvent) -> None:
        if ev.device_name != serial or ev.ha_event != trigger_type:
            return
        action(
            {
                "trigger": {
                    **config,
                    "description": f"Botslab {trigger_type}",
                    "event": ev.raw,
                }
            }
        )

    return async_dispatcher_connect(hass, SIGNAL_EVENT, _handle)
