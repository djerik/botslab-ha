"""Tests for the config and reauth flows."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

from homeassistant.config_entries import SOURCE_USER
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.botslab.api import BotslabAuthError, BotslabError
from custom_components.botslab.const import (
    CONF_EMAIL,
    CONF_PASSWORD,
    CONF_Q,
    CONF_QID,
    CONF_REGION,
    CONF_T,
    DOMAIN,
)

from .const import QID, REGION

_TOKENS = {"qid": QID, "q": "Q-token", "t": "T-token"}
_USER_INPUT = {CONF_EMAIL: "user@example.com", CONF_PASSWORD: "hunter2", CONF_REGION: REGION}


def _patch_login(**kwargs):
    return patch("custom_components.botslab.config_flow.async_login", **kwargs)


def _patch_app_login(**kwargs):
    return patch("custom_components.botslab.api.BotslabApi.app_login", **kwargs)


async def test_user_flow_success(hass: HomeAssistant) -> None:
    """A valid login creates an entry keyed by qid, storing fresh Q/T."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )
    assert result["type"] is FlowResultType.FORM

    with (
        _patch_login(new=AsyncMock(return_value=_TOKENS)),
        _patch_app_login(new=AsyncMock(return_value="SID")),
        patch(
            "custom_components.botslab.async_setup_entry",
            new=AsyncMock(return_value=True),
        ),
    ):
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], _USER_INPUT
        )
        await hass.async_block_till_done()

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["title"] == "user@example.com"
    assert result["result"].unique_id == QID
    assert result["data"][CONF_Q] == "Q-token"
    assert result["data"][CONF_T] == "T-token"
    assert result["data"][CONF_QID] == QID


async def test_user_flow_invalid_auth(hass: HomeAssistant) -> None:
    """Bad credentials surface an invalid_auth error and re-show the form."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )
    with _patch_login(new=AsyncMock(side_effect=BotslabAuthError("bad"))):
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], _USER_INPUT
        )
    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "invalid_auth"}


async def test_user_flow_cannot_connect(hass: HomeAssistant) -> None:
    """A transport/API error surfaces cannot_connect."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )
    with _patch_login(new=AsyncMock(side_effect=BotslabError("boom"))):
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], _USER_INPUT
        )
    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "cannot_connect"}


async def test_user_flow_already_configured(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry
) -> None:
    """A second entry for the same qid is aborted."""
    mock_config_entry.add_to_hass(hass)
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )
    with (
        _patch_login(new=AsyncMock(return_value=_TOKENS)),
        _patch_app_login(new=AsyncMock(return_value="SID")),
    ):
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], _USER_INPUT
        )
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "already_configured"


async def test_reauth_flow(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry
) -> None:
    """Reauth re-validates the password and refreshes the stored tokens."""
    mock_config_entry.add_to_hass(hass)
    result = await mock_config_entry.start_reauth_flow(hass)
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "reauth_confirm"

    with (
        _patch_login(new=AsyncMock(return_value={**_TOKENS, "q": "Q-new", "t": "T-new"})),
        _patch_app_login(new=AsyncMock(return_value="SID")),
        patch(
            "custom_components.botslab.async_setup_entry",
            new=AsyncMock(return_value=True),
        ),
    ):
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], {CONF_PASSWORD: "new-password"}
        )
        await hass.async_block_till_done()

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reauth_successful"
    assert mock_config_entry.data[CONF_Q] == "Q-new"
