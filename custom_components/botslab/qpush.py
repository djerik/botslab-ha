"""QPush realtime client (Qihoo push) — instant doorbell events over plaintext TCP.

Wire protocol (big-endian, length-prefixed, no TLS/crypto):
  dispatcher HTTPS GET -> {ip,port} list -> raw TCP -> op2 bind (u=deviceId@appId)
  -> op6 bind-ACK -> op17 alias (sa=push_alias) -> heartbeat op0 / recv op3 push, ack op4.
The push routing is bound to the account via `push_alias` (from /v1/app/login).
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
import json
import logging
import struct
import time
from typing import Any

from aiohttp import ClientError

from .api import BotslabApi
from .const import (
    QPUSH_APPID,
    QPUSH_DISPATCHER,
    QPUSH_HEARTBEAT,
    QPUSH_OP_ACK,
    QPUSH_OP_ALIAS,
    QPUSH_OP_BIND,
    QPUSH_OP_BIND_ACK,
    QPUSH_OP_PING,
    QPUSH_OP_PUSH,
    QPUSH_PROTO_VERSION,
    QPUSH_SDK_VERSION,
    REQUEST_TIMEOUT,
)

_LOGGER = logging.getLogger(__name__)

_RECONNECT_MIN = 5
_RECONNECT_MAX = 300


def _encode(op: int, header: dict[str, str] | None = None) -> bytes:
    """Encode a QPush frame (client only ever sends header-only messages)."""
    frame = struct.pack(">hh", QPUSH_PROTO_VERSION, op)
    if op == QPUSH_OP_PING:
        return frame
    hb = "\n".join(f"{k}:{v}" for k, v in (header or {}).items()).encode("utf-8")
    return frame + struct.pack(">H", len(hb)) + hb


def _parse_header(raw: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in raw.split("\n"):
        if ":" in line:
            key, val = line.split(":", 1)
            out[key] = val
    return out


class BotslabQPush:
    """Maintains a QPush connection and delivers pushes to a callback."""

    def __init__(
        self,
        api: BotslabApi,
        on_push: Callable[[dict[str, Any]], None],
        ensure_session: Callable[[], Awaitable[None]],
    ) -> None:
        """Set up the client with the API (tokens/alias/device id) and a push callback."""
        self._api = api
        self._on_push = on_push
        self._ensure_session = ensure_session
        self._writer: asyncio.StreamWriter | None = None
        self._closing = False

    async def stop(self) -> None:
        """Stop the client and close the socket (the task is cancelled by the entry)."""
        self._closing = True
        self._close_writer()

    def _close_writer(self) -> None:
        if self._writer:
            self._writer.close()
            self._writer = None

    async def run(self) -> None:
        """Background loop: connect, bind, listen; reconnect with backoff."""
        backoff = _RECONNECT_MIN
        while not self._closing:
            try:
                await self._session_once()
                backoff = _RECONNECT_MIN  # clean reconnect resets backoff
            except asyncio.CancelledError:
                raise
            except Exception as err:
                _LOGGER.debug("QPush connection error: %s (retry in %ss)", err, backoff)
            finally:
                self._close_writer()
            if self._closing:
                break
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, _RECONNECT_MAX)

    async def _get_server(self) -> tuple[str, int]:
        """Ask the dispatcher for a push gateway (ip, port)."""
        params = {
            "appId": QPUSH_APPID,
            "source": "",
            "user": "",
            "version": QPUSH_SDK_VERSION,
            "retry": "0",
            "device_id": self._api.m2,
        }
        try:
            resp = await self._api.session.get(
                QPUSH_DISPATCHER, params=params, timeout=REQUEST_TIMEOUT
            )
            data = await resp.json(content_type=None)
        except ClientError as err:
            raise ConnectionError(f"dispatcher: {err}") from err
        servers = data.get("data") or []
        if not servers:
            raise ConnectionError("dispatcher returned no servers")
        first = servers[0]
        return first["ip"], int(first.get("p") or 80)

    async def _session_once(self) -> None:
        """One full connection lifecycle: connect, bind, alias, then read loop."""
        await self._ensure_session()  # make sure push_alias/sid are fresh
        if not self._api.push_alias:
            raise ConnectionError("no push_alias yet")

        ip, port = await self._get_server()
        _LOGGER.debug("QPush connecting to %s:%s", ip, port)
        reader, writer = await asyncio.open_connection(ip, port)
        self._writer = writer

        device_id = self._api.m2
        writer.write(
            _encode(
                QPUSH_OP_BIND,
                {
                    "u": f"{device_id}@{QPUSH_APPID}",
                    "ts": str(int(time.time() * 1000)),
                    "t": "180",
                    "di": "home-assistant",
                    "db": "GOOGLE",
                    "net": "1",
                },
            )
        )
        await writer.drain()

        hb_task: asyncio.Task | None = None
        try:
            while not self._closing:
                op, header, body = await self._read_msg(reader)
                if op == QPUSH_OP_BIND_ACK:
                    if header.get("r") != "0":
                        raise ConnectionError(f"bind rejected: {header}")
                    writer.write(_encode(QPUSH_OP_ALIAS, {"sa": self._api.push_alias}))
                    await writer.drain()
                    hb_task = asyncio.ensure_future(self._heartbeat(writer))
                elif op == QPUSH_OP_ALIAS:
                    _LOGGER.info("QPush connected and bound to account")
                elif op == QPUSH_OP_PUSH:
                    self._handle_push(header, body, writer)
        finally:
            if hb_task:
                hb_task.cancel()

    async def _heartbeat(self, writer: asyncio.StreamWriter) -> None:
        while True:
            await asyncio.sleep(QPUSH_HEARTBEAT)
            writer.write(_encode(QPUSH_OP_PING))
            await writer.drain()

    async def _read_msg(
        self, reader: asyncio.StreamReader
    ) -> tuple[int, dict[str, str], bytes]:
        head = await reader.readexactly(4)
        _ver, op = struct.unpack(">hh", head)
        hlen = struct.unpack(">H", await reader.readexactly(2))[0]
        header = _parse_header((await reader.readexactly(hlen)).decode("utf-8", "replace"))
        body = b""
        if op == QPUSH_OP_PUSH:
            blen = struct.unpack(">I", await reader.readexactly(4))[0]
            if blen:
                body = await reader.readexactly(blen)
        return op, header, body

    def _handle_push(
        self, header: dict[str, str], body: bytes, writer: asyncio.StreamWriter
    ) -> None:
        """Parse a push body and forward it; ack it so the server doesn't resend."""
        text = body.decode("utf-8", "replace")
        _LOGGER.debug("QPush push: %s", text)
        try:
            payload = json.loads(text)
        except ValueError:
            payload = {"raw": text}
        try:
            self._on_push(payload)
        except Exception:
            _LOGGER.exception("QPush push handler failed")
        ack = header.get("ack")
        if ack:
            writer.write(_encode(QPUSH_OP_ACK, {"ack": ack}))
