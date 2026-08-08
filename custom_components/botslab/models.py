"""Typed data models for the Botslab integration."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from homeassistant.config_entries import ConfigEntry

from .const import (
    EVENT_TYPE_MAP,
    PROP_ADC_CURRENT,
    PROP_BATTERY,
    PROP_BATTERY_PACK_INSTALLED,
    PROP_EXISTING_CHIME,
    PROP_LOW_POWER,
    PROP_ONLINE,
    PROP_POWER_SUPPLY,
    PROP_SD_STATE,
    PROP_SD_STORAGE,
    PROP_VOLTAGE,
)

if TYPE_CHECKING:
    from .api import BotslabApi
    from .coordinator import BotslabCoordinator
    from .qpush import BotslabQPush


@dataclass(slots=True)
class BotslabDevice:
    """A doorbell/camera device from /v1/iot/device/list + device shadow."""

    product_key: str
    device_name: str  # serial number
    device_title: str
    online: bool
    category_key: str
    roles: str
    online_status: str = ""  # raw device-list online_status string ("online"/"offline"/"")
    raw: dict[str, Any] = field(default_factory=dict)
    props: dict[str, Any] = field(default_factory=dict)  # device shadow (battery, settings...)

    def _int(self, key: str) -> int | None:
        val = self.props.get(key)
        try:
            return int(val)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return None

    @property
    def battery_level(self) -> int | None:
        """Battery percentage."""
        return self._int(PROP_BATTERY)

    @property
    def voltage_mv(self) -> int | None:
        """Doorbell voltage in millivolts."""
        return self._int(PROP_VOLTAGE)

    @property
    def low_power(self) -> bool | None:
        """Low-power mode flag."""
        val = self.props.get(PROP_LOW_POWER)
        return bool(val) if val is not None else None

    @property
    def sd_present(self) -> bool | None:
        """Whether an SD card is present (SdState == 1)."""
        state = self._int(PROP_SD_STATE)
        return state == 1 if state is not None else None

    def _sd_part(self, idx: int) -> int | None:
        """One field of the ``SdStorage`` 'total,used,free' byte triple.

        Confirmed against the app's Storage screen: Total / Used / Available == fields 0 / 1 / 2.
        """
        raw = self.props.get(PROP_SD_STORAGE)
        if isinstance(raw, str) and "," in raw:
            try:
                return int(raw.split(",")[idx])
            except (IndexError, ValueError):
                return None
        return None

    @property
    def sd_total_bytes(self) -> int | None:
        """Total SD capacity in bytes."""
        return self._sd_part(0)

    @property
    def sd_used_bytes(self) -> int | None:
        """Used SD bytes."""
        return self._sd_part(1)

    @property
    def sd_free_bytes(self) -> int | None:
        """Free (available) SD bytes."""
        return self._sd_part(2)

    @property
    def adc_current_ma(self) -> int | None:
        """Doorbell charge/draw current in milliamps."""
        return self._int(PROP_ADC_CURRENT)

    @property
    def power_supply(self) -> int | None:
        """Power-supply mode (0 = battery)."""
        return self._int(PROP_POWER_SUPPLY)

    @property
    def battery_pack_installed(self) -> bool | None:
        """Whether the removable battery pack is installed."""
        val = self.props.get(PROP_BATTERY_PACK_INSTALLED)
        return bool(val) if val is not None else None

    @property
    def existing_chime(self) -> bool | None:
        """Whether a physical mechanical chime is present."""
        val = self.props.get(PROP_EXISTING_CHIME)
        return bool(val) if val is not None else None

    @property
    def online_state(self) -> bool:
        """Device connectivity, matched to the app's signal icon = cloud reachability via the hub.

        The device-list ``online_status`` is that signal. The shadow's ``DoorbellOnlineState`` does
        NOT track connectivity and must not be used for it: it stays ``true`` when the hub drops
        (the device's own stale self-report, so it can't say "I'm offline") and flips ``false`` when
        the battery unit merely sleeps — giving both false "connected" and false "disconnected". Use
        it only as a last resort when the device list carries no status string at all.
        """
        if self.online_status:
            return self.online
        val = self.props.get(PROP_ONLINE)
        return bool(val) if val is not None else True

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> BotslabDevice:
        """Build from a device_list entry."""
        return cls(
            product_key=str(data.get("product_key", "")),
            device_name=str(data.get("device_name", "")),
            device_title=str(data.get("device_title") or data.get("product_name") or "Botslab"),
            online=str(data.get("online_status", "")).lower() == "online",
            online_status=str(data.get("online_status", "")),
            category_key=str(data.get("category_key", "")),
            roles=str(data.get("roles", "")),
            raw=data,
        )

    @property
    def unique_id(self) -> str:
        """Stable unique id for this device."""
        return self.device_name or self.product_key


@dataclass(slots=True)
class BotslabEvent:
    """A parsed message/event from /v2/message/list or MQTT push."""

    message_id: str
    device_name: str
    event_type: str  # raw, e.g. app.event.post.Answer
    title: str
    ctime: int
    image_url: str | None = None  # event snapshot (JPEG, unencrypted)
    # Event clip. The URL uses a custom "aliyun://" scheme and points to an m3u8 on
    # Aliyun OSS; the media is encrypted (clip_encrypt, e.g. "chacha2") with a
    # per-event clip_secretkey. Resolving aliyun:// to a signed OSS URL and the
    # decryption are handled by the app.
    video_url: str | None = None
    clip_secretkey: str | None = None
    clip_encrypt: str | None = None  # "none" | "chacha2" | ...
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_message(cls, msg: dict[str, Any]) -> BotslabEvent:
        """Build from a message list item (id + tdata{image, video, ...})."""
        td = msg.get("tdata") or {}
        mid = str(
            msg.get("id") or msg.get("msg_id") or msg.get("message_id") or id(msg)
        )
        image = td.get("image") or {}
        video = td.get("video") or {}
        return cls(
            message_id=mid,
            device_name=str(td.get("device_name") or msg.get("sn") or ""),
            event_type=str(td.get("event_type") or msg.get("event_type") or msg.get("type") or ""),
            title=str(td.get("title") or ""),
            ctime=int(td.get("ctime") or 0),
            image_url=(image.get("url") if image.get("encrypt", "none") == "none" else None),
            video_url=video.get("url") or None,
            clip_secretkey=video.get("secretkey") or None,
            clip_encrypt=video.get("encrypt") or None,
            raw=msg,
        )

    @property
    def ha_event(self) -> str | None:
        """Logical HA event name (ring/motion) or None if not mapped."""
        return EVENT_TYPE_MAP.get(self.event_type)

    @property
    def has_clip(self) -> bool:
        """True if this event carries a cloud clip (encrypted m3u8 on OSS)."""
        return bool(self.video_url)


@dataclass(slots=True)
class BotslabRuntimeData:
    """Objects shared across the config entry lifetime (entry.runtime_data)."""

    api: BotslabApi
    coordinator: BotslabCoordinator
    push: BotslabQPush | None = None


type BotslabConfigEntry = ConfigEntry[BotslabRuntimeData]
