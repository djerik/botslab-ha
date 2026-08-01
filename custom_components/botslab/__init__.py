"""The Botslab Doorbell integration."""

from __future__ import annotations

import logging

from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import BotslabApi
from .const import (
    CONF_EMAIL,
    CONF_ENABLE_MQTT,
    CONF_M2,
    CONF_Q,
    CONF_REGION,
    CONF_T,
    DEFAULT_ENABLE_MQTT,
    DEFAULT_REGION,
    PLATFORMS,
)
from .coordinator import BotslabCoordinator, ReloginCallback
from .http import async_register_clip_view
from .models import BotslabConfigEntry, BotslabRuntimeData
from .qpush import BotslabQPush

_LOGGER = logging.getLogger(__name__)


def _build_relogin(hass: HomeAssistant, entry: BotslabConfigEntry) -> ReloginCallback | None:
    """Return an email/password relogin callback if credentials are stored."""
    if CONF_EMAIL not in entry.data:
        return None
    # Local import: quc_login is only needed for the email/password flow (Phase 2).
    from .quc_login import async_relogin_factory  # noqa: PLC0415

    return async_relogin_factory(hass, entry)


async def async_setup_entry(hass: HomeAssistant, entry: BotslabConfigEntry) -> bool:
    """Set up Botslab from a config entry."""
    session = async_get_clientsession(hass)
    api = BotslabApi(
        session=session,
        region=entry.data.get(CONF_REGION, DEFAULT_REGION),
        m2=entry.data[CONF_M2],
        q=entry.data.get(CONF_Q, ""),
        t=entry.data.get(CONF_T, ""),
    )

    coordinator = BotslabCoordinator(hass, entry, api, relogin=_build_relogin(hass, entry))
    await coordinator.async_config_entry_first_refresh()

    runtime = BotslabRuntimeData(api=api, coordinator=coordinator)
    entry.runtime_data = runtime

    # Serves recorded clips as MP4 (remuxed from the cloud HLS) for the media browser.
    async_register_clip_view(hass)

    # Realtime doorbell events via QPush (persistent TCP push) — no polling for rings.
    if entry.options.get(CONF_ENABLE_MQTT, DEFAULT_ENABLE_MQTT):
        push = BotslabQPush(api, coordinator.handle_push, coordinator.ensure_session)
        runtime.push = push
        entry.async_create_background_task(hass, push.run(), name="botslab_qpush")
        entry.async_on_unload(push.stop)

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    entry.async_on_unload(entry.add_update_listener(_async_reload_entry))
    return True


async def async_unload_entry(hass: HomeAssistant, entry: BotslabConfigEntry) -> bool:
    """Unload a config entry."""
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)


async def _async_reload_entry(hass: HomeAssistant, entry: BotslabConfigEntry) -> None:
    """Reload the entry when options change."""
    await hass.config_entries.async_reload(entry.entry_id)
