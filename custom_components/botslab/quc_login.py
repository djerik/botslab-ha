"""Pure-Python QUC email/password login (mints Q/T)."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
import json
import logging
import time

from aiohttp import ClientError
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import BotslabApiError, BotslabAuthError
from .const import (
    CONF_EMAIL,
    CONF_M2,
    CONF_PASSWORD,
    CONF_REGION,
    EP_QUC_REQUEST,
    QUC_FROM,
    QUC_METHOD,
    QUC_MSIGKEY,
    QUC_RSA_PUBKEY_B64,
    REGIONS,
    REQUEST_TIMEOUT,
    USER_AGENT,
)
from .crypto import (
    compute_sig,
    decrypt_response,
    encrypt_key_material,
    encrypt_params,
    gen_key_material,
    md5_hex,
)
from .models import BotslabConfigEntry

_LOGGER = logging.getLogger(__name__)

# QUC error numbers worth distinguishing.
_ERR_BAD_PASSWORD = {220, 222, 5000}  # wrong password / account issues


def build_login_params(email: str, password: str, m2: str) -> dict[str, str]:
    """Assemble the QUC login param map (device fields + credentials + sig).

    The device identifiers are derived deterministically from ``m2`` (the install's persisted
    device id) so every login from one install presents the SAME device, and two installs
    present DIFFERENT devices — instead of a fresh random id per login (one device that appears
    to keep changing) or one identity shared by every install.
    """
    now_ms = str(int(time.time() * 1000))
    # Stable per-install identifiers, seeded from m2 rather than random per call. Same shapes
    # as before: mid = 32 hex chars, androidid = 16 hex chars.
    mid = md5_hex(f"mid:{m2}")
    androidid = md5_hex(f"androidid:{m2}")[:16]
    params: dict[str, str] = {
        "loginType": "801",
        "os_sdk_version": "android_30",
        "mid": mid,
        "quc_sdk_version": "v3.2.7",
        "mname": "Galaxy Tab Active Pro",
        "ua": "Dalvik/2.1.0 (Linux; U; Android 11; SM-T545 Build/RP1A.200720.012)",
        "os_manufacturer": "samsung",
        "mSystemVersion": "android 11",
        "head_type": "q",
        "os_board": "sdm710",
        "os_model": "SM-T545",
        "password": md5_hex(password),
        "quc_lang": "en",
        "sh": "1920.0",
        "vt_guid": now_ms,
        "is_keep_alive": "1",
        "from": QUC_FROM,
        "needDeviceCheck": "1",
        "oaid": "",
        "app": "Botslab",
        "trace_id": f"src_and_1217_{now_ms}",
        "ui_ver": "4.4.6-alert-ui",
        "method": QUC_METHOD,
        "res_mode": "1",
        "sw": "1200.0",
        "format": "json",
        "qh_id": "",
        "device_os": "android",
        "device_lang": "zh-CN",
        "sec_type": "bool",
        "v": "2.28.5",
        "fields": "qid,username,nickname,loginemail,head_pic,mobile",
        "androidid": androidid,
        "username": email,
        "sdpi": "1.5",
    }
    params["sig"] = compute_sig(params, QUC_MSIGKEY)
    return params


async def async_login(
    hass: HomeAssistant, region: str, email: str, password: str, m2: str
) -> dict[str, str]:
    """Perform the full login and return {'qid','q','t'}. Raises on failure."""
    params = build_login_params(email, password, m2)
    a117 = gen_key_material()
    body = {
        "method": QUC_METHOD,
        "from": QUC_FROM,
        "device_lang": params["device_lang"],
        "quc_lang": params["quc_lang"],
        "trace_id": params["trace_id"],
        "parad": encrypt_params(params, a117),
        "key": encrypt_key_material(a117, QUC_RSA_PUBKEY_B64),
    }
    url = f"https://{REGIONS[region]['login']}{EP_QUC_REQUEST}"
    session = async_get_clientsession(hass)
    try:
        resp = await session.post(
            url, data=body, headers={"User-Agent": USER_AGENT}, timeout=REQUEST_TIMEOUT
        )
        outer = await resp.json(content_type=None)
    except ClientError as err:
        raise BotslabApiError(-1, f"login transport: {err}") from err

    errno = int(outer.get("errno", -1))
    if errno != 0 or not outer.get("ret"):
        if errno in _ERR_BAD_PASSWORD:
            raise BotslabAuthError(outer.get("errmsg", "invalid credentials"))
        raise BotslabApiError(errno, str(outer.get("errmsg", "login failed")))

    user = json.loads(decrypt_response(outer["ret"], a117).decode("utf-8")).get("user", {})
    q, t, qid = user.get("q"), user.get("t"), user.get("qid")
    if not (q and t):
        raise BotslabApiError(0, "login ok but no Q/T in response")
    return {"qid": str(qid or ""), "q": q, "t": t}


def async_relogin_factory(
    hass: HomeAssistant, entry: BotslabConfigEntry
) -> Callable[[], Awaitable[tuple[str, str]]]:
    """Return a coordinator relogin callback that mints fresh (Q, T)."""

    async def _relogin() -> tuple[str, str]:
        tokens = await async_login(
            hass,
            entry.data[CONF_REGION],
            entry.data[CONF_EMAIL],
            entry.data[CONF_PASSWORD],
            entry.data[CONF_M2],
        )
        # Persist the refreshed tokens so a restart resumes without a full login.
        hass.config_entries.async_update_entry(
            entry, data={**entry.data, "q": tokens["q"], "t": tokens["t"], "qid": tokens["qid"]}
        )
        return tokens["q"], tokens["t"]

    return _relogin
