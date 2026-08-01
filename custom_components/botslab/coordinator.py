"""DataUpdateCoordinator for Botslab: device state polling + event dispatch."""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta
import logging

from aiohttp import ClientTimeout
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.dispatcher import async_dispatcher_send
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.util import dt as dt_util

from .api import BotslabApi, BotslabAuthError, BotslabError, BotslabSessionError
from .const import (
    CONF_DEVICE_SN_FILTER,
    CONF_POLL_INTERVAL,
    DEFAULT_POLL_INTERVAL,
    DOMAIN,
    REQUEST_TIMEOUT,
    SIGNAL_EVENT,
    SIGNAL_SNAPSHOT,
)
from .models import BotslabConfigEntry, BotslabDevice, BotslabEvent

_LOGGER = logging.getLogger(__name__)

_SEEN_MAX = 512

# Optional callable that mints fresh Q/T (email/password login). Phase 2 provides it.
ReloginCallback = Callable[[], Awaitable[tuple[str, str]]]


class BotslabCoordinator(DataUpdateCoordinator[dict[str, BotslabDevice]]):
    """Polls device state and dispatches new events (poll fallback for MQTT)."""

    config_entry: BotslabConfigEntry

    def __init__(
        self,
        hass: HomeAssistant,
        entry: BotslabConfigEntry,
        api: BotslabApi,
        relogin: ReloginCallback | None = None,
    ) -> None:
        """Set up the coordinator."""
        interval = entry.options.get(CONF_POLL_INTERVAL, DEFAULT_POLL_INTERVAL)
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            config_entry=entry,
            update_interval=timedelta(seconds=interval),
        )
        self.api = api
        self._relogin = relogin
        self._sn_filter = entry.options.get(CONF_DEVICE_SN_FILTER, "") or ""
        self._seen: OrderedDict[str, None] = OrderedDict()
        self._primed = False  # after first poll, react to new events only
        # Latest event snapshot per device (device_name -> JPEG bytes). Downloaded at poll time
        # while the OSS signed URL is fresh, so it is available immediately after a restart —
        # shared by the image entity and the camera thumbnail.
        self.snapshot_bytes: dict[str, bytes] = {}
        self.snapshot_updated: dict[str, datetime] = {}
        self._snapshot_ctime: dict[str, int] = {}  # newest event ctime cached per device

    async def ensure_session(self) -> None:
        """Make sure we have a valid app session sid, refreshing/relogging as needed."""
        try:
            if not self.api.sid:
                await self.api.app_login()
        except BotslabSessionError:
            await self.api.app_login()
        except BotslabAuthError as err:
            await self._full_relogin(err)

    async def _full_relogin(self, err: Exception) -> None:
        """Q/T expired: mint fresh tokens via email/password, or trigger reauth."""
        if self._relogin is None:
            raise ConfigEntryAuthFailed("Q/T expired and no login credentials") from err
        try:
            q, t = await self._relogin()
        except BotslabAuthError as auth_err:
            # Credentials no longer valid (e.g. password changed) -> reauth.
            raise ConfigEntryAuthFailed(str(auth_err)) from auth_err
        self.api.set_tokens(q, t)
        await self.api.app_login()

    async def _async_update_data(self) -> dict[str, BotslabDevice]:
        """Poll devices and (as MQTT fallback) recent events."""
        try:
            await self.ensure_session()
            devices = await self.api.device_list()
            # Merge the device shadow (battery, voltage, SD, settings) into each device.
            for device in devices:
                try:
                    device.props = await self.api.device_property(
                        device.product_key, device.device_name
                    )
                except BotslabError as err:  # non-fatal: keep basic device info
                    _LOGGER.debug("device_property failed for %s: %s", device.device_name, err)
            try:
                events = await self.api.message_list(page_size=20)
            except BotslabSessionError:
                await self.api.app_login()
                events = await self.api.message_list(page_size=20)
            self._process_poll_events(events)
        except ConfigEntryAuthFailed:
            raise
        except BotslabAuthError as err:
            await self._full_relogin(err)
            raise UpdateFailed("re-logged in; will retry") from err
        except BotslabError as err:
            raise UpdateFailed(str(err)) from err
        return {d.unique_id: d for d in devices}

    def _process_poll_events(self, events: list[BotslabEvent]) -> None:
        """Dispatch new events seen via polling (first poll only primes the seen-set)."""
        first_poll = not self._primed
        # events are newest-first; process oldest-first so ordering is natural.
        for ev in reversed(events):
            self.dispatch_event(ev, prime_only=not self._primed)
        self._primed = True
        # On startup, prime the snapshot once from the newest event (the dispatch path above is
        # prime-only, so it does not fetch). After that, snapshots refresh only when a *new*
        # event is dispatched (see _maybe_cache_snapshot), i.e. on the ring/motion itself.
        if first_poll:
            newest = next((ev for ev in events if ev.image_url), None)
            if newest is not None:
                self._maybe_cache_snapshot(newest)

    def _maybe_cache_snapshot(self, ev: BotslabEvent) -> None:
        """Download this event's snapshot if it is newer than what we have for the device."""
        if not ev.image_url or ev.ctime <= self._snapshot_ctime.get(ev.device_name, 0):
            return
        self._snapshot_ctime[ev.device_name] = ev.ctime
        self.config_entry.async_create_background_task(
            self.hass, self._cache_snapshot(ev), name="botslab_snapshot")

    @callback
    def handle_push(self, payload: dict) -> None:
        """QPush delivered a realtime event: fetch the new message(s) instantly."""
        self.config_entry.async_create_background_task(
            self.hass, self._on_push(payload), name="botslab_push"
        )

    async def _on_push(self, payload: dict) -> None:
        """On a push, do a lightweight message poll and dispatch new events at once."""
        try:
            await self.ensure_session()
            events = await self.api.message_list(page_size=5)
        except BotslabError as err:
            _LOGGER.debug("push-triggered message poll failed: %s", err)
            return
        self._process_poll_events(events)

    def dispatch_event(self, ev: BotslabEvent, *, prime_only: bool = False) -> None:
        """Dedup and dispatch an event (shared by poll and MQTT paths)."""
        if ev.message_id in self._seen:
            return
        self._seen[ev.message_id] = None
        while len(self._seen) > _SEEN_MAX:
            self._seen.popitem(last=False)
        if prime_only or ev.ha_event is None:
            return
        if self._sn_filter and self._sn_filter not in ev.device_name:
            return
        _LOGGER.debug("Botslab event: %s on %s", ev.event_type, ev.device_name)
        self._maybe_cache_snapshot(ev)  # refresh the snapshot on the new event
        async_dispatcher_send(self.hass, SIGNAL_EVENT, ev)

    async def _cache_snapshot(self, ev: BotslabEvent) -> None:
        """Download the event snapshot now (before its signed URL expires) and cache the bytes."""
        try:
            session = async_get_clientsession(self.hass)
            resp = await session.get(ev.image_url, timeout=ClientTimeout(total=REQUEST_TIMEOUT))
            resp.raise_for_status()
            data = await resp.read()
        except Exception as err:  # snapshot is best-effort
            _LOGGER.debug("snapshot download failed for %s: %s", ev.device_name, err)
            return
        # Downloads may finish out of order; keep only the newest that was requested.
        if ev.ctime < self._snapshot_ctime.get(ev.device_name, 0):
            return
        self.snapshot_bytes[ev.device_name] = data
        self.snapshot_updated[ev.device_name] = dt_util.utcnow()
        async_dispatcher_send(self.hass, SIGNAL_SNAPSHOT, ev.device_name)
