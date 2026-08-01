"""Decrypt Botslab / 360 cloud doorbell clips (``encrypt: "chacha2"``).

The cloud stores event clips as HLS whose ``.ts`` segments carry ChaCha20-encrypted H.264.
Only the slice-payload bytes are encrypted; the MPEG-TS container, PES headers, SPS/PPS and
AAC audio are in the clear. Decryption is length-preserving, so we decrypt the H.264 in place
inside the transport stream and keep the original timing and audio intact.

The clip cipher, per H.264 slice NAL, on its RBSP (emulation-prevention bytes removed):

* key    = the 32-character ``secretkey`` used directly as 32 ASCII bytes,
* IV      = ``rbsp[0xF4:0x100]`` (12 bytes),
* payload = ``rbsp[0x100:]`` (only slices whose RBSP is longer than 0x100),
* ChaCha20 state words 12 == 15 = IV[4:8], 13 = IV[8:12], 14 = IV[0:4]; the block counter
  increments word 12 (carry into 13) per 64-byte block.
"""

from __future__ import annotations

import re
import struct

try:  # optional C-accelerated ChaCha20; falls back to the pure-Python core below
    from Crypto.Cipher import ChaCha20 as _ChaCha20
except ImportError:  # pragma: no cover
    _ChaCha20 = None

_SIGMA = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)
_MASK = 0xFFFFFFFF
_KEY_LEN = 32
_IV_LEN = 12
_PAYLOAD_OFF = 0x100
_EPB = 3  # emulation_prevention_three_byte value in 00 00 03
_NAL_SLICE_TYPES = (1, 5)  # coded slice (non-IDR) and IDR
_TS_PKT = 188
_TS_SYNC = 0x47
_PES_VIDEO_MIN = 0xE0  # video stream_id range 0xE0-0xEF
_PES_VIDEO_MAX = 0xEF
_PES_AUDIO_MIN = 0xC0  # audio stream_id range 0xC0-0xDF
_PES_AUDIO_MAX = 0xDF
_ADTS_HDR = 7  # ADTS header length without CRC (9 with CRC)
_ADTS_SYNC0 = 0xFF  # ADTS syncword: 0xFF followed by 0xF0-0xF6
_ADTS_SYNC1_MASK = 0xF6
_ADTS_SYNC1 = 0xF0
_AUDIO_IV_OFF = 0x14  # IV offset within the AAC payload (after the ADTS header)
_AUDIO_PAYLOAD_OFF = 0x20


_QUARTER_ROUNDS = (
    (0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
    (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14),
)


def _rotl(v: int, c: int) -> int:
    return ((v << c) | (v >> (32 - c))) & _MASK


def _quarter_round(x: list[int], a: int, b: int, c: int, d: int) -> None:
    x[a] = (x[a] + x[b]) & _MASK
    x[d] = _rotl(x[d] ^ x[a], 16)
    x[c] = (x[c] + x[d]) & _MASK
    x[b] = _rotl(x[b] ^ x[c], 12)
    x[a] = (x[a] + x[b]) & _MASK
    x[d] = _rotl(x[d] ^ x[a], 8)
    x[c] = (x[c] + x[d]) & _MASK
    x[b] = _rotl(x[b] ^ x[c], 7)


def _chacha_block(state: list[int]) -> bytes:
    x = list(state)
    for _ in range(10):
        for a, b, c, d in _QUARTER_ROUNDS:
            _quarter_round(x, a, b, c, d)
    return struct.pack("<16I", *[(x[i] + state[i]) & _MASK for i in range(16)])


def _chacha_xor(key32: bytes, iv12: bytes, data: bytes) -> bytes:
    """XOR ``data`` with the device's ChaCha20 keystream. The device seeds the state as
    w12 == w15 = IV[4:8], w13 = IV[8:12], w14 = IV[0:4]; this maps onto standard ChaCha20 with
    an 8-byte nonce (IV[0:8]) and an initial 64-bit block counter of (IV[8:12] << 32 | IV[4:8])."""
    w12, w13 = struct.unpack("<II", iv12[4:12])
    if _ChaCha20 is not None:
        cipher = _ChaCha20.new(key=key32, nonce=iv12[0:8])
        cipher.seek(((w13 << 32) | w12) * 64)
        return cipher.decrypt(data)
    state = [*_SIGMA, *struct.unpack("<8I", key32), w12, w13,
             struct.unpack("<I", iv12[0:4])[0], w12]
    keystream = bytearray()
    for _ in range((len(data) + 63) // 64):
        keystream += _chacha_block(state)
        state[12] = (state[12] + 1) & _MASK
        if state[12] == 0:
            state[13] = (state[13] + 1) & _MASK
    ks = bytes(keystream[:len(data)])
    return (int.from_bytes(data, "big") ^ int.from_bytes(ks, "big")).to_bytes(len(data), "big")


def _rbsp_map(nal: bytes) -> tuple[bytes, list[int]]:
    """Return (rbsp, index_map): rbsp with emulation-prevention 03 bytes removed, and a map
    from each RBSP byte to its position in ``nal`` (so we can write results back in place)."""
    rbsp = bytearray()
    idx: list[int] = []
    i = 0
    n = len(nal)
    while i < n:
        if i + 2 < n and nal[i] == 0 and nal[i + 1] == 0 and nal[i + 2] == _EPB:
            rbsp.append(nal[i])
            rbsp.append(nal[i + 1])
            idx.append(i)
            idx.append(i + 1)
            i += 3  # drop the 03 emulation-prevention byte
        else:
            rbsp.append(nal[i])
            idx.append(i)
            i += 1
    return bytes(rbsp), idx


def _key_bytes(secretkey: str) -> bytes:
    key32 = secretkey.encode("ascii", "ignore")
    if len(key32) != _KEY_LEN:
        key32 = (key32 + b"\x00" * _KEY_LEN)[:_KEY_LEN]
    return key32


def decrypt_annexb(data: bytes, secretkey: str) -> bytes:
    """Decrypt an Annex-B H.264 elementary stream. Length-preserving and in place: the
    emulation-prevention bytes stay put and only slice-payload bytes are rewritten, exactly
    like the native decoder. Non-slice NALs (incl. PES headers) pass through untouched."""
    key32 = _key_bytes(secretkey)
    out = bytearray(data)
    starts = [m.start() for m in re.finditer(b"\x00\x00\x01", data)]
    for i, start in enumerate(starts):
        nal_start = start + 3
        nal_end = starts[i + 1] if i + 1 < len(starts) else len(data)
        if nal_end - 1 > nal_start and data[nal_end - 1] == 0:
            nal_end -= 1  # trailing zero belongs to the next 4-byte start code
        nal = data[nal_start:nal_end]
        if not nal or (nal[0] & 0x1F) not in _NAL_SLICE_TYPES:
            continue
        rbsp, idx = _rbsp_map(nal)
        # The payload offset is measured in the raw NAL (emulation-prevention bytes included),
        # so map raw offset 0x100 back to the first RBSP byte at or past it.
        payload = next((j for j, raw in enumerate(idx) if raw >= _PAYLOAD_OFF), None)
        if payload is None or payload < _IV_LEN or payload >= len(rbsp):
            continue
        iv = rbsp[payload - _IV_LEN:payload]
        dec = _chacha_xor(key32, iv, rbsp[payload:])
        base = idx[payload]
        if idx[-1] - base == len(dec) - 1:  # payload has no emulation-prevention bytes
            out[nal_start + base:nal_start + base + len(dec)] = dec
        else:
            for j, byte in enumerate(dec):
                out[nal_start + idx[payload + j]] = byte
    return bytes(out)


def _video_pid(ts: bytes) -> int | None:
    """Find the PID that carries an H.264 video PES (stream_id 0xE0-0xEF)."""
    for off in range(0, len(ts) - _TS_PKT, _TS_PKT):
        if ts[off] != _TS_SYNC or not (ts[off + 1] & 0x40):  # payload_unit_start
            continue
        pid = ((ts[off + 1] & 0x1F) << 8) | ts[off + 2]
        afc = (ts[off + 3] >> 4) & 3
        p = off + 4
        if afc & 2:
            p += 1 + ts[off + 4]
        if (
            afc & 1
            and p + 4 <= off + _TS_PKT
            and ts[p:p + 3] == b"\x00\x00\x01"
            and _PES_VIDEO_MIN <= ts[p + 3] <= _PES_VIDEO_MAX
        ):
            return pid
    return None


def _audio_pid(ts: bytes) -> int | None:
    """Find the PID that carries an AAC audio PES (stream_id 0xC0-0xDF)."""
    for off in range(0, len(ts) - _TS_PKT, _TS_PKT):
        if ts[off] != _TS_SYNC or not (ts[off + 1] & 0x40):  # payload_unit_start
            continue
        pid = ((ts[off + 1] & 0x1F) << 8) | ts[off + 2]
        afc = (ts[off + 3] >> 4) & 3
        p = off + 4
        if afc & 2:
            p += 1 + ts[off + 4]
        if (
            afc & 1
            and p + 4 <= off + _TS_PKT
            and ts[p:p + 3] == b"\x00\x00\x01"
            and _PES_AUDIO_MIN <= ts[p + 3] <= _PES_AUDIO_MAX
        ):
            return pid
    return None


def _pid_payload(ts: bytes, pid: int, strip_pes: bool) -> tuple[bytearray, list[int]]:
    """Concatenate a PID's TS payload bytes and map each back to its index in ``ts``. With
    ``strip_pes`` the leading PES header of each PES packet is dropped, yielding a clean
    elementary stream (used for ADTS audio, whose frames may span PES boundaries)."""
    buf = bytearray()
    positions: list[int] = []
    for off in range(0, len(ts) - _TS_PKT + 1, _TS_PKT):
        if ts[off] != _TS_SYNC:
            continue
        if (((ts[off + 1] & 0x1F) << 8) | ts[off + 2]) != pid:
            continue
        afc = (ts[off + 3] >> 4) & 3
        if not afc & 1:
            continue
        p = off + 4
        if afc & 2:
            p += 1 + ts[off + 4]
        if (
            strip_pes
            and ts[off + 1] & 0x40  # payload_unit_start
            and p + 9 <= off + _TS_PKT
            and ts[p:p + 3] == b"\x00\x00\x01"
        ):
            p += 9 + ts[p + 8]  # skip the PES header
        for q in range(p, off + _TS_PKT):
            buf.append(ts[q])
            positions.append(q)
    return buf, positions


def _decrypt_adts(buf: bytes, key32: bytes) -> bytes:
    """Decrypt the AAC frames in a clean ADTS elementary stream in place: per frame the IV is
    at payload offset 0x14 and the ciphertext runs from 0x20 (after the ADTS header)."""
    out = bytearray(buf)
    i = 0
    n = len(out)
    while i + _ADTS_HDR <= n:
        if out[i] != _ADTS_SYNC0 or (out[i + 1] & _ADTS_SYNC1_MASK) != _ADTS_SYNC1:
            i += 1
            continue
        frame_len = ((out[i + 3] & 3) << 11) | (out[i + 4] << 3) | (out[i + 5] >> 5)
        if frame_len < _ADTS_HDR or i + frame_len > n:
            i += 1
            continue
        header = _ADTS_HDR if out[i + 1] & 1 else _ADTS_HDR + 2  # +2 CRC bytes when present
        start = i + header + _AUDIO_PAYLOAD_OFF
        if frame_len > header + _AUDIO_PAYLOAD_OFF:
            iv = bytes(out[i + header + _AUDIO_IV_OFF:start])
            out[start:i + frame_len] = _chacha_xor(key32, iv, bytes(out[start:i + frame_len]))
        i += frame_len
    return bytes(out)


def decrypt_mpegts(ts: bytes, secretkey: str) -> bytes:
    """Decrypt the H.264 video and AAC audio inside an MPEG-TS clip in place, preserving the
    container and PES timing. Returns the original bytes unchanged if nothing encrypted is
    found."""
    key32 = _key_bytes(secretkey)
    out = bytearray(ts)
    vpid = _video_pid(ts)
    if vpid is not None:
        buf, positions = _pid_payload(ts, vpid, strip_pes=False)
        if buf:
            dec = decrypt_annexb(bytes(buf), secretkey)
            for i, byte in enumerate(dec):
                out[positions[i]] = byte
    apid = _audio_pid(ts)
    if apid is not None:
        buf, positions = _pid_payload(ts, apid, strip_pes=True)
        if buf:
            dec = _decrypt_adts(bytes(buf), key32)
            for i, byte in enumerate(dec):
                out[positions[i]] = byte
    return bytes(out)


# --------------------------------------------------------------------------------------
# GodSees signalling cipher (RC4) — used by the live-view transport (see live/).
#
# The GodSees signalling payload (base_capacity / req_relay / transfer_token) is encrypted
# with standard (textbook) RC4: keystream index
# ``t = (S[i] + S[j]) & 0xff``. The key is either the hardcoded base-capacity key or one of
# the ``get_keys`` ``secret_keys`` (32 ASCII bytes) selected by index; plaintext is UTF-8.
# --------------------------------------------------------------------------------------
def rc4(data: bytes, key: bytes) -> bytes:
    """Standard (textbook) RC4."""
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    out = bytearray(len(data))
    i = j = 0
    for n, b in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out[n] = b ^ s[(s[i] + s[j]) & 0xFF]
    return bytes(out)
