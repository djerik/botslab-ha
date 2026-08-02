"""Async client for the Botslab (360) sapp-api cloud.

Ported from the verified sync poller. All request shapes confirmed live:
  sign = MD5(appkey + m2 + sign_ts + sign_no + APP_SECRET).lower()   (fixed order, ts seconds)
  common params (incl. sign) go in the QUERY STRING, even for POST
  Authorization: jws base64(json{"Q","T","sid"})   (no sid -> 1015, no Q/T -> 100003)
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import secrets
import string
import time
from typing import Any

from aiohttp import ClientError, ClientSession

from .const import (
    APP_KEY,
    APP_SECRET,
    APP_VER,
    CODE_ACCOUNT_TIMEOUT,
    CODE_BAD_REQUEST,
    CODE_LOGIN_FAILED,
    CODE_OK,
    CODE_SESSION_STOLEN,
    CODE_SIGN_ERROR,
    EP_APP_LOGIN,
    EP_CONFIG_EVENT_TYPE_V2,
    EP_DEVICE_LIST,
    EP_DEVICE_PROPERTY,
    EP_MESSAGE_LIST,
    EP_OSS_GET_PLAY_URL,
    REGIONS,
    REQUEST_TIMEOUT,
    USER_AGENT,
)
from .models import BotslabDevice, BotslabEvent

_LOGGER = logging.getLogger(__name__)

_ALPHANUM = string.ascii_letters + string.digits


class BotslabError(Exception):
    """Base error."""


class BotslabAuthError(BotslabError):
    """Q/T missing or expired (code 100003) — needs full re-login."""


class BotslabSessionError(BotslabError):
    """App session sid missing or expired (code 1015) — needs app_login()."""


class BotslabSignError(BotslabError):
    """Signing rejected (code 1001) — wrong appkey/secret/clock."""


class BotslabApiError(BotslabError):
    """Other non-zero API code."""

    def __init__(self, code: int, msg: str) -> None:
        """Store the API code and message."""
        super().__init__(f"code={code} msg={msg}")
        self.code = code
        self.msg = msg


def _rand(n: int) -> str:
    return "".join(secrets.choice(_ALPHANUM) for _ in range(n))


def new_device_id() -> str:
    """Generate a stable device id (m2). Persist it — signing depends on it."""
    return hashlib.md5(_rand(16).encode()).hexdigest()  # noqa: S324 - matches app scheme


def sign(appkey: str, m2: str, sign_ts: str, sign_no: str) -> str:
    """Compute the sapp-api request signature (verified scheme)."""
    base = appkey + m2 + sign_ts + sign_no + APP_SECRET
    return hashlib.md5(base.encode("utf-8")).hexdigest().lower()  # noqa: S324


def common_params(m2: str) -> dict[str, str]:
    """Build the common ci_*/sign params attached to every request."""
    ts = str(int(time.time()))  # seconds, not ms
    no = _rand(20)
    return {
        "m2": m2,
        "appkey": APP_KEY,
        "appver": APP_VER,
        "sign": sign(APP_KEY, m2, ts, no),
        "sign_ts": ts,
        "sign_no": no,
        "ci_brand": "Google",
        "ci_model": "Pixel 7",
        "ci_net": "wifi",
        "ci_osver": "33",
        "appch": "botslabadr",
        "ci_lang": "en--US",
        "ci_tz": "UTC+2",
        "app_type_id": "1",
        "ci_cy": "DK",
        "appflag": "beta",
    }


class BotslabApi:
    """Async sapp-api client for one account/region."""

    def __init__(
        self,
        session: ClientSession,
        region: str,
        m2: str,
        q: str,
        t: str,
        sid: str = "",
    ) -> None:
        """Initialise with a shared aiohttp session and auth state."""
        self._session = session
        self._region = region
        self._api = f"https://{REGIONS[region]['api']}"
        self.m2 = m2
        self.q = q
        self.t = t
        self.sid = sid
        self.push_alias = ""  # QPush routing key, from app_login
        self.uid = ""  # account user id (from app_login) — the live substream's real userid

    @property
    def session(self) -> ClientSession:
        """The shared aiohttp session (used by the QPush dispatcher call)."""
        return self._session

    def set_tokens(self, q: str, t: str) -> None:
        """Replace the QUC tokens after a re-login."""
        self.q = q
        self.t = t
        self.sid = ""

    def _auth_header(self) -> dict[str, str]:
        if not (self.q and self.t):
            return {}
        payload: dict[str, str] = {"Q": self.q, "T": self.t}
        if self.sid:
            payload["sid"] = self.sid
        blob = base64.b64encode(json.dumps(payload).encode()).decode()
        return {"Authorization": "jws " + blob}

    async def _call(
        self, path: str, params: dict[str, Any] | None = None, method: str = "GET"
    ) -> dict[str, Any]:
        p = common_params(self.m2)
        p.update(params or {})
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json", **self._auth_header()}
        url = self._api + path
        try:
            # Common params live in the query string for both GET and POST.
            resp = await self._session.request(
                method, url, params=p, headers=headers, timeout=REQUEST_TIMEOUT
            )
            data: dict[str, Any] = await resp.json(content_type=None)
        except ClientError as err:
            raise BotslabApiError(-1, f"transport: {err}") from err
        except (ValueError, TypeError) as err:
            raise BotslabApiError(-1, f"bad json: {err}") from err

        code = int(data.get("code", -1))
        if code == CODE_OK:
            return data
        if code in (CODE_LOGIN_FAILED, CODE_SESSION_STOLEN, CODE_ACCOUNT_TIMEOUT):
            # Q/T invalid, the account was re-logged in on another device (one active session
            # per account), or the session timed out — re-login to reclaim it.
            raise BotslabAuthError(data.get("msg", "login verification failed"))
        if code == CODE_BAD_REQUEST:
            raise BotslabSessionError(data.get("msg", "bad request / sid expired"))
        if code == CODE_SIGN_ERROR:
            raise BotslabSignError(data.get("msg", "sign error"))
        raise BotslabApiError(code, str(data.get("msg", "")))

    async def app_login(self) -> str:
        """Exchange Q/T for an app session sid (required by device/message calls)."""
        if not (self.q and self.t):
            raise BotslabAuthError("missing Q/T")
        data = (await self._call(EP_APP_LOGIN, {}, method="POST")).get("data", {})
        self.sid = str(data.get("sid") or data.get("home_sid") or "")
        self.push_alias = str(data.get("push_alias") or self.push_alias)
        raw_uid = str(data.get("uid") or data.get("userid") or data.get("user_id")
                      or data.get("qid") or self.uid)
        # The app's connect_priv/substream sends the BARE numeric account uid (e.g.
        # 1000100000000014903); app_login returns it prefixed ("botslab_<digits>"). Strip the
        # prefix so /substream's userid matches the app byte-for-byte.
        self.uid = raw_uid.split("_", 1)[-1] if raw_uid.startswith("botslab_") else raw_uid
        if not self.sid:
            raise BotslabSessionError("app_login returned no sid")
        return self.sid

    async def device_list(self) -> list[BotslabDevice]:
        """Return the account's devices."""
        data = (await self._call(EP_DEVICE_LIST, {"page": 1, "page_size": 50})).get("data", {})
        return [BotslabDevice.from_api(d) for d in data.get("devices", [])]

    async def device_property(self, product_key: str, device_name: str) -> dict[str, Any]:
        """Return the device shadow (battery, voltage, SD, settings) as {identifier: value}."""
        data = (
            await self._call(
                EP_DEVICE_PROPERTY,
                {"product_key": product_key, "device_name": device_name},
            )
        ).get("data", {})
        props: dict[str, Any] = {}
        for entry in (data.get("report") or []) + (data.get("desired") or []):
            ident = entry.get("identifier")
            if ident is not None:
                props[str(ident)] = entry.get("value")
        return props

    async def message_list(self, page_size: int = 20) -> list[BotslabEvent]:
        """Return recent events (newest first) with snapshot/clip URLs."""
        data = (
            await self._call(EP_MESSAGE_LIST, {"page": 1, "page_size": page_size})
        ).get("data", {})
        return [BotslabEvent.from_message(m) for m in data.get("items", [])]

    async def event_type(self) -> dict[str, Any]:
        """Return the event-type catalogue (for discovering ring types)."""
        return (await self._call(EP_CONFIG_EVENT_TYPE_V2, {})).get("data", {})

    async def resolve_clip_url(self, aliyun_url: str) -> str:
        """Resolve a message clip's aliyun:// URL to a public, playable HLS URL.

        The returned URL is an m3u8 whose OSS-signed .ts segments are plaintext
        MPEG-TS — playable directly with no auth header and no decryption.
        """
        data = (
            await self._call(EP_OSS_GET_PLAY_URL, {"url": aliyun_url}, method="GET")
        ).get("data", {})
        return str(data.get("url") or "")
