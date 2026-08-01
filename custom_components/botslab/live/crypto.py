"""Crypto used by the live transport, re-exported from the shared clip crypto.

``rc4`` (GodSees signalling cipher) is the shared primitive. Live media, however, uses a
DIFFERENT decrypt from clips: the same ChaCha20-256 cipher and self-keyed 12-byte IV, but on
the **raw** slice NAL bytes with NO emulation-prevention handling. Clips
(``decrypt_annexb``) strip and re-insert emulation-prevention (00 00 03) around the RBSP;
live must NOT — its ciphertext contains real 00 00 03 bytes that stripping would corrupt.
The live media decrypt, per VCL slice: ``nonce = nal[off-0x0c:off-0x04]``,
``counter = u64le(nal[off-0x08:off])``,
decrypt ``nal[off:]``; ``off`` is the (content-dependent) encryption boundary in the NAL.
"""

from __future__ import annotations

from ..clip_crypto import _chacha_xor, _key_bytes, decrypt_annexb, rc4

__all__ = ["decrypt_annexb", "raw_decrypt_slice", "rc4"]


def raw_decrypt_slice(nal: bytes, secretkey: str, off: int) -> bytes:
    """Decrypt a live VCL slice NAL in place from ``off`` (raw bytes, no emulation handling).
    The 12 bytes at ``nal[off-0x0c:off]`` are the self-keyed IV (nonce + block counter)."""
    if off < 0x0C or off >= len(nal):
        return nal
    return nal[:off] + _chacha_xor(_key_bytes(secretkey), nal[off - 0x0C:off], nal[off:])
