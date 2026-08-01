"""Tests for integration setup, entity creation, and unload."""

from __future__ import annotations

from contextlib import contextmanager
from unittest.mock import AsyncMock, patch

from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.botslab.models import BotslabDevice, BotslabEvent

from .const import DEVICE_SN, load_fixture_json


def _device() -> BotslabDevice:
    return BotslabDevice.from_api(load_fixture_json("device_list.json")["data"]["devices"][0])


def _events() -> list[BotslabEvent]:
    return [
        BotslabEvent.from_message(m)
        for m in load_fixture_json("message_list.json")["data"]["items"]
    ]


@contextmanager
def _patch_api():
    prefix = "custom_components.botslab.api.BotslabApi"
    with (
        patch(f"{prefix}.app_login", new=AsyncMock(return_value="SID")),
        patch(f"{prefix}.device_list", new=AsyncMock(return_value=[_device()])),
        patch(f"{prefix}.device_property", new=AsyncMock(return_value={"BatteryLevel": 87})),
        patch(f"{prefix}.message_list", new=AsyncMock(return_value=_events())),
        # The clip HTTP view needs hass.http; not relevant to this test.
        patch("custom_components.botslab.async_register_clip_view"),
    ):
        yield


async def test_setup_and_unload(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry
) -> None:
    """A full setup loads the platforms, builds runtime_data, and unloads cleanly."""
    mock_config_entry.add_to_hass(hass)
    with _patch_api():
        assert await hass.config_entries.async_setup(mock_config_entry.entry_id)
        await hass.async_block_till_done()

    assert mock_config_entry.state is ConfigEntryState.LOADED
    runtime = mock_config_entry.runtime_data
    assert DEVICE_SN in runtime.coordinator.data
    # Realtime push disabled in the fixture options -> no push client.
    assert runtime.push is None

    registry = er.async_get(hass)
    unique_ids = {e.unique_id for e in registry.entities.values()}
    assert f"{DEVICE_SN}_event" in unique_ids
    assert f"{DEVICE_SN}_online" in unique_ids
    assert f"{DEVICE_SN}_battery" in unique_ids

    assert await hass.config_entries.async_unload(mock_config_entry.entry_id)
    await hass.async_block_till_done()
    assert mock_config_entry.state is ConfigEntryState.NOT_LOADED


async def test_event_entity_fires_on_dispatch(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry
) -> None:
    """A dispatched ring updates the event entity state."""
    mock_config_entry.add_to_hass(hass)
    with _patch_api():
        assert await hass.config_entries.async_setup(mock_config_entry.entry_id)
        await hass.async_block_till_done()

    registry = er.async_get(hass)
    entity_id = registry.async_get_entity_id("event", "botslab", f"{DEVICE_SN}_event")
    assert entity_id is not None

    coordinator = mock_config_entry.runtime_data.coordinator
    coordinator._primed = True
    # The setup poll already primed msg-1003 into the seen-set; clear it so the ring
    # dispatches as a newly-arriving event instead of being deduped.
    coordinator._seen.clear()
    coordinator.dispatch_event(_events()[0])  # the ring
    await hass.async_block_till_done()

    state = hass.states.get(entity_id)
    assert state is not None
    assert state.attributes["event_type"] == "ring"
