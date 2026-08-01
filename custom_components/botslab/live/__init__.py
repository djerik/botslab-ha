"""Pure-Python live-view transport for the Botslab doorbell.

Self-contained (no Home Assistant imports) so it stays unit-testable.
:class:`~.engine.LiveEngine` performs the handshake
and emits decrypted H.264; :class:`~.manager.LiveStreamManager` (the one HA-aware module here)
wraps it into an ffmpeg-fronted MPEG-TS source for the camera platform.
"""

from __future__ import annotations

from .engine import LiveEngine

__all__ = ["LiveEngine"]
