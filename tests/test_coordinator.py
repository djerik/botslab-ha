"""Tests for the coordinator: priming, dedup, event dispatch, session ladder."""

from __future__ import annotations

from collections.abc import Callable
from unittest.mock import AsyncMock

from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.dispatcher import async_dispatcher_connect
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.botslab.api import BotslabAuthError, BotslabSessionError
from custom_components.botslab.const import SIGNAL_EVENT
from custom_components.botslab.coordinator import BotslabCoordinator
from custom_components.botslab.models import BotslabDevice, BotslabEvent

from .const import DEVICE_SN, load_fixture_json


def _device() -> BotslabDevice:
    data = load_fixture_json("device_list.json")["data"]["devices"][0]
    return BotslabDevice.from_api(data)


def _events() -> list[BotslabEvent]:
    items = load_fixture_json("message_list.json")["data"]["items"]
    return [BotslabEvent.from_message(m) for m in items]


class FakeApi:
    """Minimal async stand-in for BotslabApi."""

    def __init__(self, events: list[BotslabEvent]) -> None:
        self.sid = "SID"
        self.q = "Q"
        self.t = "T"
        self._events = events
        self.app_login = AsyncMock(return_value="SID")
        self.device_list = AsyncMock(return_value=[_device()])
        self.device_property = AsyncMock(return_value={"BatteryLevel": 87})

    async def message_list(self, page_size: int = 20) -> list[BotslabEvent]:
        return list(self._events)

    def set_tokens(self, q: str, t: str) -> None:
        self.q, self.t, self.sid = q, t, ""


def _capture(hass: HomeAssistant) -> tuple[list[BotslabEvent], Callable[[], None]]:
    received: list[BotslabEvent] = []

    @callback
    def _on(ev: BotslabEvent) -> None:
        received.append(ev)

    unsub = async_dispatcher_connect(hass, SIGNAL_EVENT, _on)
    return received, unsub


def _coordinator(
    hass: HomeAssistant, entry: MockConfigEntry, api: FakeApi, relogin=None
) -> BotslabCoordinator:
    entry.add_to_hass(hass)
    return BotslabCoordinator(hass, entry, api, relogin=relogin)


async def test_first_refresh_primes_without_dispatch(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry
) -> None:
    """The first poll marks existing events seen and dispatches nothing."""
    received, unsub = _capture(hass)
    coord = _coordinator(hass, mock_config_entry, FakeApi(_events()))
    # async_refresh (not async_config_entry_first_refresh, which HA now guards to the
    # SETUP_IN_PROGRESS state) — the first update primes the seen-set either way.
    await coord.async_refresh()
    assert received == []
    assert DEVICE_SN in coord.data
    unsub()


async def test_new_event_after_prime_dispatches_once(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry
) -> None:
    """After priming, only genuinely new mapped events are dispatched."""
    events = _events()
    api = FakeApi(events[1:])  # start primed with the older two
    received, unsub = _capture(hass)
    coord = _coordinator(hass, mock_config_entry, api)
    await coord.async_refresh()  # first update primes; see note above
    assert received == []

    api._events = events  # a new ring (msg-1003) appears
    await coord.async_refresh()
    await hass.async_block_till_done()
    assert [e.message_id for e in received] == ["msg-1003"]
    assert received[0].ha_event == "ring"
    unsub()


async def test_dispatch_dedup(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry
) -> None:
    """The same event id is dispatched at most once (bounded LRU)."""
    received, unsub = _capture(hass)
    coord = _coordinator(hass, mock_config_entry, FakeApi([]))
    coord._primed = True
    ring = _events()[0]
    coord.dispatch_event(ring)
    coord.dispatch_event(ring)
    await hass.async_block_till_done()
    assert len(received) == 1
    unsub()


async def test_unmapped_event_not_dispatched(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry
) -> None:
    """Events with no logical HA mapping are seen but never dispatched."""
    received, unsub = _capture(hass)
    coord = _coordinator(hass, mock_config_entry, FakeApi([]))
    coord._primed = True
    coord.dispatch_event(_events()[2])  # unknown type
    await hass.async_block_till_done()
    assert received == []
    unsub()


async def test_ensure_session_logs_in_when_no_sid(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry
) -> None:
    """ensure_session performs app_login when there is no sid yet."""
    api = FakeApi([])
    api.sid = ""
    coord = _coordinator(hass, mock_config_entry, api)
    await coord.ensure_session()
    api.app_login.assert_awaited_once()


async def test_ensure_session_relogins_on_auth_error(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry
) -> None:
    """A Q/T auth error triggers the relogin callback, then app_login."""
    api = FakeApi([])
    api.sid = ""
    api.app_login = AsyncMock(side_effect=[BotslabAuthError("expired"), "SID"])
    relogin = AsyncMock(return_value=("Q2", "T2"))
    coord = _coordinator(hass, mock_config_entry, api, relogin=relogin)
    await coord.ensure_session()
    relogin.assert_awaited_once()


async def test_auth_error_without_relogin_raises_reauth(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry
) -> None:
    """No relogin callback + Q/T expiry -> ConfigEntryAuthFailed (drives reauth)."""
    api = FakeApi([])
    api.sid = ""
    api.app_login = AsyncMock(side_effect=BotslabAuthError("expired"))
    coord = _coordinator(hass, mock_config_entry, api, relogin=None)
    with pytest.raises(ConfigEntryAuthFailed):
        await coord.ensure_session()


async def test_session_error_retries_app_login(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry
) -> None:
    """A bare sid-expiry (1015) is healed by a re-login without reauth."""
    api = FakeApi([])
    api.sid = ""
    api.app_login = AsyncMock(side_effect=[BotslabSessionError("sid"), "SID"])
    coord = _coordinator(hass, mock_config_entry, api)
    await coord.ensure_session()
    assert api.app_login.await_count == 2
