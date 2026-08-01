"""Relay-session scheduler (the ukey minter) — the botslab ``/substream`` path.

  1. get_keys -> license {product_id, authorization, auth_time, rand_num}   [cloud.py]
  2. POST {region}-video-licenseext.botslab.com/Device/getRelaySign -> uSign (serviceSign)
  3. GET {region}-video-schedule.botslab.com/substream?...&_usign=<uSign>&_sign=<md5>
     -> {servers:[...], auth_key(=ukey), cluster_id, sn(=stream_id)}
  4. use auth_key as the relay-login ukey (relay.py -> media -> decrypt).

The signing secrets are app-wide constants shared by all installs.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import time

from ._http import DEFAULT_HTTP, Http

_LOGGER = logging.getLogger(__name__)

# QHVCRelaySign.SECRET_KEY, used for the getRelaySign urlsign.
URLSIGN_SECRET = "116c46e0b026742bf177b200d31670c3"
SCHEDULE_PATH = "/substream"


def _md5(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()  # noqa: S324 - request signing, not security


def get_relay_sign(region: str, license_: dict, sn: str, *, http: Http = DEFAULT_HTTP) -> dict:
    """POST ``/Device/getRelaySign`` with the license -> ``{'sign': uSign, 'sname': ...}``."""
    host = f"https://{region}-video-licenseext.botslab.com"
    reg_time = str(int(time.time()))
    params = {"product_id": license_["product_id"], "sn": sn, "reg_time": reg_time}
    urlsign = _md5("".join(f"{k}={params[k]}" for k in sorted(params)) + URLSIGN_SECRET)
    headers = {"auth-time": str(license_["auth_time"]), "rand-num": str(license_["rand_num"]),
               "authorization": license_["authorization"], "User-Agent": "netsdk"}
    r = http.post_json(f"{host}/Device/getRelaySign", params={"urlsign": urlsign},
                       data=params, headers=headers)
    return r.get("data", {})


def relay_sign(params: dict[str, str]) -> str:
    """``/substream`` ``_sign = md5(sorted key__value)`` — no secret (connect_priv, verified)."""
    return _md5("".join(f"{k}__{v}" for k, v in sorted(params.items())))


def _decode_substream(body: str) -> dict:
    """Response = base64(JSON) with a 3-char nonce inserted at [3:6]; strip it, then decode."""
    clean = body[:3] + body[6:]
    return json.loads(base64.b64decode(clean + "=" * (-len(clean) % 4)))


def build_substream_url(region: str, sn: str, product_id: str, sname: str, usign: str,
                        *, seq: int = 1, stream_suffix: str = "01") -> str:
    """Build a signed ``/substream`` request. userid is the literal '10010'.

    ``seq``/``stream_suffix`` select the two variants the app sends per live-open: ``seq=1``,
    suffix ``01`` mints the relay ukey (the media session); ``seq=2`` with the machineId as the
    suffix (``<sn>_01_<machineId>``) registers this viewer's machineId server-side — the step that
    authorises the machineId for the device's live *video* substream (see :func:`register_viewer`).
    """
    tms = int(time.time() * 1000)
    sid = f"shedule_{seq}_{product_id}_{sn}_{tms}_1"
    core = {"channel": sname, "dtype": "non", "sid": sid, "sn": f"{sn}_01_{stream_suffix}",
            "stype": "auto", "ts": str(tms), "userid": "10010"}
    q = {**core, "_deviceid": sn, "_ostype": "2", "_ver": "2", "_streamtype": "all",
         "_sdk_ver": "2", "_delay": "0", "_usign": usign, "_sign": relay_sign(core)}
    host = f"https://{region}-video-schedule.botslab.com"
    return f"{host}{SCHEDULE_PATH}?" + "&".join(f"{k}={v}" for k, v in q.items())


def schedule_relay(region: str, license_: dict, sn: str, product_key: str, *,
                   http: Http = DEFAULT_HTTP) -> dict:
    """Full ukey mint: getRelaySign -> uSign -> GET /substream -> relay session dict."""
    rs = get_relay_sign(region, license_, sn, http=http)
    usign, sname = rs["sign"], rs.get("sname", product_key)
    body = http.get_text(build_substream_url(region, sn, license_["product_id"], sname, usign),
                         headers={"User-Agent": "netsdk"})
    j = _decode_substream(body)
    if j.get("errcode") != 0 or not j.get("auth_key"):
        raise RuntimeError(f"substream failed: {j.get('errcode')}")
    srv = next((s for s in j.get("servers", []) if s), "")
    host, _, port = srv.partition(":")
    return {"relay": (host, int(port or 80)), "ukey": j["auth_key"], "cluster": j.get("cluster_id"),
            "stream_id": j.get("sn"), "channel": sname, "usign": usign,
            "product_id": license_["product_id"]}


def register_viewer(region: str, sn: str, product_id: str, sname: str, usign: str,
                    machine_id: str, *, http: Http = DEFAULT_HTTP) -> bool:
    """Fire the ``schedule_2`` ``/substream`` call that registers ``machine_id`` as the viewer.

    The app sends this alongside the ukey mint on every live-open; skipping it leaves the device
    publishing audio only (its ``req_relay_res`` returns ``flag:0`` and no video substream arrives).
    Registering our machineId makes the device authorise it for video. True on ``errcode 0``.
    """
    url = build_substream_url(region, sn, product_id, sname, usign, seq=2, stream_suffix=machine_id)
    try:
        j = _decode_substream(http.get_text(url, headers={"User-Agent": "netsdk"}))
    except (ValueError, OSError) as err:
        _LOGGER.debug("schedule_2 register failed for %s: %s", sn, err)
        return False
    return j.get("errcode") == 0
