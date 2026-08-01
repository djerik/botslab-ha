"""Tests for the typed data models (device + event parsing)."""

from __future__ import annotations

from custom_components.botslab.models import BotslabDevice, BotslabEvent

from .const import DEVICE_SN, PRODUCT_KEY, load_fixture_json


def _devices() -> list[BotslabDevice]:
    data = load_fixture_json("device_list.json")["data"]["devices"]
    return [BotslabDevice.from_api(d) for d in data]


def _events() -> list[BotslabEvent]:
    items = load_fixture_json("message_list.json")["data"]["items"]
    return [BotslabEvent.from_message(m) for m in items]


def test_device_from_api() -> None:
    """A device_list entry maps onto the typed device."""
    device = _devices()[0]
    assert device.product_key == PRODUCT_KEY
    assert device.device_name == DEVICE_SN
    assert device.device_title == "Front Door"
    assert device.online is True
    assert device.unique_id == DEVICE_SN


def test_device_shadow_properties() -> None:
    """The device shadow is parsed into typed helpers."""
    device = _devices()[0]
    device.props = {
        "BatteryLevel": 87,
        "DoorbellVoltage": 4120,
        "LowPowerMode": False,
        "DoorbellOnlineState": True,
        "SdState": 1,
        "SdStorage": "31914983424,20000000000,11914983424",
    }
    assert device.battery_level == 87
    assert device.voltage_mv == 4120
    assert device.low_power is False
    assert device.sd_present is True
    # SdStorage is "total,used,free" -> free is field 2 (used=20000000000 is field 1).
    assert device.sd_used_bytes == 20000000000
    assert device.sd_free_bytes == 11914983424
    assert device.online_state is True


def test_device_shadow_missing_values() -> None:
    """Absent shadow values return None, not raise."""
    device = _devices()[0]
    device.props = {}
    assert device.battery_level is None
    assert device.sd_free_bytes is None
    # Falls back to the device-list online flag when the shadow lacks it.
    assert device.online_state is True


def test_event_ring_mapping() -> None:
    """The Answer event maps to the logical 'ring' HA event and keeps its clip."""
    ring = _events()[0]
    assert ring.message_id == "msg-1003"
    assert ring.event_type == "app.event.post.Answer"
    assert ring.ha_event == "ring"
    assert ring.device_name == DEVICE_SN
    assert ring.image_url == "https://oss.example/snap-1003.jpg"
    assert ring.has_clip is True
    assert ring.clip_encrypt == "chacha2"


def test_event_person_mapping() -> None:
    """HumanPass maps to 'person'."""
    person = _events()[1]
    assert person.ha_event == "person"
    assert person.has_clip is False


def test_event_unmapped_and_encrypted_image() -> None:
    """An unknown event type yields ha_event=None; encrypted images are dropped."""
    unknown = _events()[2]
    assert unknown.ha_event is None
    # image encrypt != none -> not exposed as a plain URL
    assert unknown.image_url is None
