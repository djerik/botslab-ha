"""Diagnostics for the Botslab integration (secrets redacted)."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.core import HomeAssistant

from .const import CONF_EMAIL, CONF_M2, CONF_PASSWORD, CONF_Q, CONF_QID, CONF_T
from .models import BotslabConfigEntry

_REDACT = {CONF_PASSWORD, CONF_Q, CONF_T, CONF_QID, CONF_EMAIL, CONF_M2, "push_alias"}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: BotslabConfigEntry
) -> dict[str, Any]:
    """Return redacted diagnostics for a config entry."""
    coordinator = entry.runtime_data.coordinator
    devices = []
    for device in coordinator.data.values():
        data = asdict(device)
        data.pop("raw", None)
        devices.append(data)
    return {
        "entry_data": async_redact_data(dict(entry.data), _REDACT),
        "options": dict(entry.options),
        "push_connected": entry.runtime_data.push is not None,
        "device_count": len(devices),
        "devices": devices,
    }
