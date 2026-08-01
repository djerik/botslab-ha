"""Pytest fixtures for the Botslab integration tests."""

from __future__ import annotations

from collections.abc import Generator

import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.botslab.const import CONF_ENABLE_MQTT, DOMAIN

from .const import ENTRY_DATA, QID


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(
    enable_custom_integrations: None,
) -> Generator[None]:
    """Enable loading the botslab custom component in every test."""
    yield


@pytest.fixture
def mock_config_entry() -> MockConfigEntry:
    """A configured Botslab entry (realtime push disabled so tests stay offline)."""
    return MockConfigEntry(
        domain=DOMAIN,
        title="user@example.com",
        data=ENTRY_DATA,
        options={CONF_ENABLE_MQTT: False},
        unique_id=QID,
        entry_id="botslab_test_entry",
    )
