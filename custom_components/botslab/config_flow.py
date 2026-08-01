"""Config and options flow for Botslab (email/password login)."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult, OptionsFlow
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.selector import (
    BooleanSelector,
    NumberSelector,
    NumberSelectorConfig,
    NumberSelectorMode,
    SelectSelector,
    SelectSelectorConfig,
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)
import voluptuous as vol

from .api import BotslabApi, BotslabAuthError, BotslabError, new_device_id
from .const import (
    CONF_DEVICE_SN_FILTER,
    CONF_EMAIL,
    CONF_ENABLE_MQTT,
    CONF_M2,
    CONF_PASSWORD,
    CONF_POLL_INTERVAL,
    CONF_Q,
    CONF_QID,
    CONF_REGION,
    CONF_T,
    DEFAULT_ENABLE_MQTT,
    DEFAULT_POLL_INTERVAL,
    DEFAULT_REGION,
    DOMAIN,
    REGIONS,
)
from .models import BotslabConfigEntry
from .quc_login import async_login

_PASSWORD_SELECTOR = TextSelector(TextSelectorConfig(type=TextSelectorType.PASSWORD))


def _user_schema(defaults: Mapping[str, Any]) -> vol.Schema:
    return vol.Schema(
        {
            vol.Required(CONF_EMAIL, default=defaults.get(CONF_EMAIL, "")): TextSelector(
                TextSelectorConfig(type=TextSelectorType.EMAIL)
            ),
            vol.Required(CONF_PASSWORD): _PASSWORD_SELECTOR,
            vol.Required(
                CONF_REGION, default=defaults.get(CONF_REGION, DEFAULT_REGION)
            ): SelectSelector(
                SelectSelectorConfig(options=list(REGIONS), translation_key="region")
            ),
        }
    )


class BotslabConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle the Botslab config flow."""

    VERSION = 1

    async def _validate(
        self, region: str, email: str, password: str, m2: str
    ) -> dict[str, str]:
        """Log in and confirm an app session; return the data to persist."""
        tokens = await async_login(self.hass, region, email, password, m2)
        api = BotslabApi(
            session=async_get_clientsession(self.hass),
            region=region,
            m2=m2,
            q=tokens["q"],
            t=tokens["t"],
        )
        await api.app_login()  # proves Q/T + signing/routing
        return {
            CONF_REGION: region,
            CONF_EMAIL: email,
            CONF_PASSWORD: password,
            CONF_M2: m2,
            CONF_Q: tokens["q"],
            CONF_T: tokens["t"],
            CONF_QID: tokens["qid"],
        }

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the initial email/password step."""
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                data = await self._validate(
                    user_input[CONF_REGION],
                    user_input[CONF_EMAIL],
                    user_input[CONF_PASSWORD],
                    new_device_id(),
                )
            except BotslabAuthError:
                errors["base"] = "invalid_auth"
            except BotslabError:
                errors["base"] = "cannot_connect"
            else:
                await self.async_set_unique_id(data[CONF_QID] or data[CONF_EMAIL])
                self._abort_if_unique_id_configured()
                return self.async_create_entry(title=user_input[CONF_EMAIL], data=data)
        return self.async_show_form(
            step_id="user", data_schema=_user_schema(user_input or {}), errors=errors
        )

    async def async_step_reauth(
        self, entry_data: Mapping[str, Any]
    ) -> ConfigFlowResult:
        """Handle re-authentication when the stored credentials stop working."""
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Ask for the password again and refresh tokens."""
        entry = self._get_reauth_entry()
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                data = await self._validate(
                    entry.data[CONF_REGION],
                    entry.data[CONF_EMAIL],
                    user_input[CONF_PASSWORD],
                    entry.data[CONF_M2],
                )
            except BotslabAuthError:
                errors["base"] = "invalid_auth"
            except BotslabError:
                errors["base"] = "cannot_connect"
            else:
                return self.async_update_reload_and_abort(entry, data=data)
        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema({vol.Required(CONF_PASSWORD): _PASSWORD_SELECTOR}),
            description_placeholders={CONF_EMAIL: entry.data[CONF_EMAIL]},
            errors=errors,
        )

    @staticmethod
    def async_get_options_flow(entry: BotslabConfigEntry) -> BotslabOptionsFlow:
        """Return the options flow."""
        return BotslabOptionsFlow()


class BotslabOptionsFlow(OptionsFlow):
    """Handle Botslab options."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Manage poll interval, MQTT toggle and device filter."""
        if user_input is not None:
            return self.async_create_entry(data=user_input)

        opts = self.config_entry.options
        schema = vol.Schema(
            {
                vol.Required(
                    CONF_POLL_INTERVAL,
                    default=opts.get(CONF_POLL_INTERVAL, DEFAULT_POLL_INTERVAL),
                ): NumberSelector(
                    NumberSelectorConfig(min=10, max=600, mode=NumberSelectorMode.BOX)
                ),
                vol.Required(
                    CONF_ENABLE_MQTT,
                    default=opts.get(CONF_ENABLE_MQTT, DEFAULT_ENABLE_MQTT),
                ): BooleanSelector(),
                vol.Optional(
                    CONF_DEVICE_SN_FILTER,
                    default=opts.get(CONF_DEVICE_SN_FILTER, ""),
                ): TextSelector(),
            }
        )
        return self.async_show_form(step_id="init", data_schema=schema)
