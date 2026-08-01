"""Tests for the async sapp-api client (request shaping + response parsing)."""

from __future__ import annotations

import base64
import hashlib
import json

from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
import pytest
from pytest_homeassistant_custom_component.test_util.aiohttp import AiohttpClientMocker

from custom_components.botslab.api import (
    BotslabApi,
    BotslabApiError,
    BotslabAuthError,
    BotslabSessionError,
    BotslabSignError,
    common_params,
    sign,
)
from custom_components.botslab.const import APP_KEY, APP_SECRET

from .const import API_HOST, DEVICE_SN, PRODUCT_KEY, REGION, load_fixture_json


def _api(hass: HomeAssistant, q: str = "Q-token", t: str = "T-token") -> BotslabApi:
    return BotslabApi(
        session=async_get_clientsession(hass),
        region=REGION,
        m2="m2-fixed",
        q=q,
        t=t,
    )


def test_sign_is_the_verified_scheme() -> None:
    """sign = MD5(appkey + m2 + sign_ts + sign_no + secret).lower(), fixed order."""
    expected = hashlib.md5(
        (APP_KEY + "m2" + "1700000000" + "no" + APP_SECRET).encode()
    ).hexdigest()
    assert sign(APP_KEY, "m2", "1700000000", "no") == expected


def test_common_params_shape() -> None:
    """common_params carries the signed ci_* block with a seconds timestamp."""
    params = common_params("m2-fixed")
    assert params["appkey"] == APP_KEY
    assert params["m2"] == "m2-fixed"
    assert params["sign"] == sign(APP_KEY, "m2-fixed", params["sign_ts"], params["sign_no"])
    assert params["sign_ts"].isdigit() and len(params["sign_ts"]) == 10  # seconds, not ms


async def test_auth_header_shape(hass: HomeAssistant) -> None:
    """Authorization is 'jws ' + base64(json{Q,T[,sid]})."""
    api = _api(hass)
    header = api._auth_header()
    payload = json.loads(base64.b64decode(header["Authorization"].removeprefix("jws ")))
    assert payload == {"Q": "Q-token", "T": "T-token"}
    api.sid = "SID"
    payload = json.loads(base64.b64decode(api._auth_header()["Authorization"].removeprefix("jws ")))
    assert payload["sid"] == "SID"


async def test_auth_header_empty_without_tokens(hass: HomeAssistant) -> None:
    """No Q/T -> no Authorization header at all."""
    assert _api(hass, q="", t="")._auth_header() == {}


async def test_app_login(hass: HomeAssistant, aioclient_mock: AiohttpClientMocker) -> None:
    """app_login stores the sid and push_alias from the response."""
    aioclient_mock.post(f"{API_HOST}/v1/app/login", json=load_fixture_json("app_login.json"))
    api = _api(hass)
    sid = await api.app_login()
    assert sid == "app-session-sid-abcdef"
    assert api.sid == sid
    assert api.push_alias == "alias-000111222"


async def test_device_list(hass: HomeAssistant, aioclient_mock: AiohttpClientMocker) -> None:
    """device_list parses the devices array into typed devices."""
    aioclient_mock.get(
        f"{API_HOST}/v1/iot/device/list", json=load_fixture_json("device_list.json")
    )
    devices = await _api(hass).device_list()
    assert len(devices) == 1
    assert devices[0].device_name == DEVICE_SN
    assert devices[0].online is True


async def test_device_property_merges_report(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker
) -> None:
    """device_property flattens report+desired into {identifier: value}."""
    aioclient_mock.get(
        f"{API_HOST}/v1/iot/device/get_desired_property",
        json=load_fixture_json("get_property.json"),
    )
    props = await _api(hass).device_property(PRODUCT_KEY, DEVICE_SN)
    assert props["BatteryLevel"] == 87
    assert props["SdState"] == 1


async def test_message_list(hass: HomeAssistant, aioclient_mock: AiohttpClientMocker) -> None:
    """message_list parses items newest-first into typed events."""
    aioclient_mock.get(
        f"{API_HOST}/v2/message/list", json=load_fixture_json("message_list.json")
    )
    events = await _api(hass).message_list()
    assert [e.ha_event for e in events] == ["ring", "person", None]


@pytest.mark.parametrize(
    ("code", "error"),
    [
        (100003, BotslabAuthError),
        (102003, BotslabAuthError),
        (1015, BotslabSessionError),
        (1001, BotslabSignError),
        (300260, BotslabApiError),
    ],
)
async def test_error_codes_map_to_exceptions(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    code: int,
    error: type[Exception],
) -> None:
    """Each documented API code raises its typed exception."""
    aioclient_mock.get(
        f"{API_HOST}/v1/iot/device/list", json={"code": code, "msg": "nope"}
    )
    with pytest.raises(error):
        await _api(hass).device_list()


async def test_app_login_requires_tokens(hass: HomeAssistant) -> None:
    """Without Q/T, app_login raises an auth error before any request."""
    with pytest.raises(BotslabAuthError):
        await _api(hass, q="", t="").app_login()
