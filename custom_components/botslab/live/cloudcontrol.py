"""GodSees/QHVC "cloud_control" config — the source of the real P2P tunnel servers.

    POST https://{region}-video-iotext.botslab.com/sdk   (form: app_name/version/platform)
      -> {"errno":0,"data":{"encrypt":"1","ccdata":"<base64>"}}

``ccdata`` = base64 -> AES-128-ECB(key='livecloud0123456', no IV) -> strip PKCS7 -> JSON. The
AES key is an app-wide constant. The ``net`` block gives the real routing endpoints (tunnel
servers/port, tracker, dispatchers).
"""

from __future__ import annotations

import base64
import json

from Crypto.Cipher import AES

from ._http import DEFAULT_HTTP, Http

CC_AES_KEY = b"livecloud0123456"  # AES-128-ECB, PKCS7 (app-wide constant)


def fetch_ccdata(region: str = "eu1", *, http: Http = DEFAULT_HTTP) -> bytes:
    """POST ``/sdk`` and return the raw (base64-decoded) ccdata ciphertext."""
    host = f"https://{region}-video-iotext.botslab.com/sdk"
    j = http.post_json(
        host,
        data="app_name=super_app&version=1.0.1&platform=android",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; SM-T545 Build/RP1A.200720.012)",
        },
    )
    if j.get("errno") != 0:
        raise RuntimeError(f"/sdk errno={j.get('errno')} {j.get('errmsg')}")
    return base64.b64decode(j["data"]["ccdata"])


def decrypt_ccdata(ciphertext: bytes) -> dict:
    """AES-128-ECB(key='livecloud0123456') + PKCS7 strip -> cloud_control JSON."""
    pt = AES.new(CC_AES_KEY, AES.MODE_ECB).decrypt(ciphertext)
    pad = pt[-1]
    if 1 <= pad <= 16:
        pt = pt[:-pad]
    return json.loads(pt)


def get_servers(region: str = "eu1", *, http: Http = DEFAULT_HTTP) -> dict:
    """Return the routing endpoints from the cloud_control ``net`` block."""
    net = decrypt_ccdata(fetch_ccdata(region, http=http)).get("net", {})
    th, _, tp = net.get("tcp_tracker_dispatch_server", "").partition(":")
    return {
        "tcp_tracker": (th, int(tp or 80)),
        "tunnel_servers": [s for s in net.get("p2p_tunnel_servers", "").split(",") if s],
        "tunnel_port": int(net.get("p2p_tunnel_port", 8080)),
        "use_p2p": net.get("enable_p2p") == "1",
    }
