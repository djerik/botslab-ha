"""Shared constants + fixture loaders for the Botslab tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from custom_components.botslab.const import (
    CONF_EMAIL,
    CONF_M2,
    CONF_PASSWORD,
    CONF_Q,
    CONF_QID,
    CONF_REGION,
    CONF_T,
)

_FIXTURES = Path(__file__).parent / "fixtures"

REGION = "eu1"
API_HOST = "https://eu1-sapp-api.botslab.com"
LOGIN_HOST = "https://eu1-sapp-login.botslab.com"

DEVICE_SN = "SN0123456789ABCDEF"
PRODUCT_KEY = "a1B2c3D4e5"
QID = "1234567890"

# What a fully-configured (post email/password login) entry stores.
ENTRY_DATA: dict[str, Any] = {
    CONF_REGION: REGION,
    CONF_EMAIL: "user@example.com",
    CONF_PASSWORD: "hunter2",
    CONF_M2: "0123456789abcdef0123456789abcdef",
    CONF_Q: "Q-token",
    CONF_T: "T-token",
    CONF_QID: QID,
}


def load_fixture_json(name: str) -> dict[str, Any]:
    """Load a JSON fixture file from tests/fixtures."""
    return json.loads((_FIXTURES / name).read_text(encoding="utf-8"))
