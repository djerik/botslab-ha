"""Cloud auth + live ChaCha key fetch — the sapp-api half of the live transport.

Uses the same
``sign = md5(appkey + m2 + sign_ts + sign_no + appsecret)`` / ``jws`` scheme as the async
``api.py``, but synchronously (this runs in the transport worker thread). App constants are
duplicated here on purpose so the ``live`` package imports no Home Assistant code and stays
unit-testable.

Flow: ``POST /v1/app/login`` -> sid, then ``GET /v1/iot/camera/get_keys`` -> rotating indexed
ChaCha keys + license (media is decrypted with the indexed key from get_keys). ``WakeUp``
nudges the sleeping battery doorbell so it will publish to the relay.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import string
import time

from ._http import DEFAULT_HTTP, Http

APP_KEY = "botslabadr"
APP_SECRET = "qihu_adr_3afg139513ksgnlah1951365saa351a9z_360"  # app signing secret
APP_VER = "2.28.5"
_AN = string.ascii_letters + string.digits


def _md5(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()  # noqa: S324 - app signing scheme, not security


def _rnd(n: int) -> str:
    return "".join(secrets.choice(_AN) for _ in range(n))


class BotslabCloud:
    """Synchronous sapp-api client for the live-view transport (login/get_keys/wake)."""

    def __init__(self, q: str, t: str, region: str = "eu1", m2: str | None = None,
                 sid: str = "", http: Http | None = None) -> None:
        """Store credentials; ``m2`` must be the account's stable signing salt.

        Pass ``sid`` to reuse an already-authenticated session. The account allows only one
        active session, so calling :meth:`login` here would mint a competing sid and kick the
        coordinator's polling session — the live transport borrows the existing sid instead.
        ``http`` is the blocking transport to send on (Home Assistant's shared session in
        production; stdlib urllib by default).
        """
        self._q, self._t = q, t
        self._api = f"https://{region}-sapp-api.botslab.com"
        self._m2 = m2 or _md5(_rnd(16))
        self._sid = sid
        self._http = http or DEFAULT_HTTP

    def _common(self) -> dict[str, str]:
        ts, no = str(int(time.time())), _rnd(20)
        return {
            "m2": self._m2, "appkey": APP_KEY, "appver": APP_VER,
            "sign": _md5(APP_KEY + self._m2 + ts + no + APP_SECRET), "sign_ts": ts, "sign_no": no,
            "ci_brand": "Google", "ci_model": "Pixel 7", "ci_net": "wifi", "ci_osver": "33",
            "appch": APP_KEY, "ci_lang": "en--US", "ci_tz": "UTC+2", "app_type_id": "1",
            "ci_cy": "DK", "appflag": "beta",
        }

    def _auth(self) -> dict[str, str]:
        p = {"Q": self._q, "T": self._t}
        if self._sid:
            p["sid"] = self._sid
        return {"Authorization": "jws " + base64.b64encode(json.dumps(p).encode()).decode(),
                "User-Agent": "Botslab/2.28.5 (Android)"}

    def login(self) -> str:
        """Exchange Q/T for a session id (sid)."""
        r = self._http.post_json(self._api + "/v1/app/login", params=self._common(),
                                 headers=self._auth())
        self._sid = str(r.get("data", {}).get("sid") or "")
        if not self._sid:
            raise RuntimeError(f"live login failed: {json.dumps(r)[:200]}")
        return self._sid

    def _get(self, path: str, extra: dict[str, str]) -> dict:
        if not self._sid:
            self.login()
        return self._http.get_json(self._api + path, params={**self._common(), **extra},
                                   headers=self._auth())

    def get_keys(self, product_key: str, sn: str) -> dict:
        """Return the rotating media keys plus the relay license.

        ``{'license': {product_id, authorization, auth_time, rand_num}, 'secret_interval': int,
        'keys': {index(int): key(str)}}``. The license feeds :func:`.schedule.get_relay_sign`;
        ``secret_interval`` is passed through unvalidated and has no consumer yet.
        """
        d = self._get("/v1/iot/camera/get_keys",
                      {"product_key": product_key, "device_name": sn, "sn": sn})["data"]
        keys = {int(next(iter(k))): next(iter(k.values())) for k in d["secret_keys"]}
        return {"license": d["license"], "secret_interval": d["secret_interval"], "keys": keys}

    def wake(self, product_key: str, sn: str, identifier: str = "WakeUp",
             inp: dict | None = None) -> dict:
        """Wake the sleeping battery doorbell so it publishes to the relay.

        ``POST /v1/iot/device/invoke_service``, body FORM-URLENCODED (not JSON), fields
        ``{product_key, device_name, identifier='WakeUp', input=<json string>}``.
        Returns ``{'data': {'result': '{"ErrorNO":0}'}}``.
        """
        form = {"product_key": product_key, "device_name": sn,
                "identifier": identifier, "input": json.dumps(inp or {})}
        if not self._sid:
            self.login()
        return self._http.post_json(self._api + "/v1/iot/device/invoke_service",
                                    params=self._common(), data=form, headers=self._auth())
