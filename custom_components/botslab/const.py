"""Constants for the Botslab doorbell integration.

Signing keys, hosts and event types for the Botslab (360) cloud API.
"""

from __future__ import annotations

from typing import Final

from homeassistant.const import Platform

DOMAIN: Final = "botslab"

PLATFORMS: Final = [
    Platform.BINARY_SENSOR,
    Platform.CAMERA,
    Platform.EVENT,
    Platform.IMAGE,
    Platform.SENSOR,
]

# --- sapp-api signing keys (app-wide constants) ---
APP_KEY: Final = "botslabadr"
APP_SECRET: Final = "qihu_adr_3afg139513ksgnlah1951365saa351a9z_360"  # noqa: S105 - app signing secret
APP_VER: Final = "2.28.5"

USER_AGENT: Final = "Botslab/2.28.5 (Android)"

# --- QUC login (email/password) — pure-Python implementation ---
# The app encrypts login params with DES/CBC/PKCS5 (key=iv=last 8 bytes of a random
# 117-char string), RSA/PKCS1-encrypts that string with the server key, MD5-signs the
# params with QUC_MSIGKEY, and POSTs to https://{login}/request.php. See quc_login.py.
QUC_METHOD: Final = "UserIntf.login"
QUC_FROM: Final = "mpl_cloudsmartoem_and"
QUC_MSIGKEY: Final = "73e5dba4"
QUC_RSA_PUBKEY_B64: Final = (
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC9oNZHDXyGxNNfBhfk/+WAtjVE"
    "T1sLWQraDBLHd0821Ow4yp6p+zvHB6yXSUEt2/lLVW7Q0/RVHuxnwtg6cKYdDIn"
    "qMznSLIKjXPkd6Dfft8nz8vkOdSUlzQtE3T4dvaagbH76lBGB2wuLNOV0D2UcUy"
    "vRu2puKtYjgDNm/O0apQIDAQAB"
)
EP_QUC_REQUEST: Final = "/request.php"

# --- Regional hosts. api = sapp-api gateway; login = QUC (request.php). ---
REGIONS: Final[dict[str, dict[str, str]]] = {
    "eu1": {
        "api": "eu1-sapp-api.botslab.com",
        "login": "eu1-sapp-login.botslab.com",
        "iot": "eu1-iot-deviceapi.botslab.com",
    },
    "eu2": {
        "api": "eu2-sapp-api.botslab.com",
        "login": "eu2-sapp-login.botslab.com",
        "iot": "eu2-iot-deviceapi.botslab.com",
    },
    "na1": {
        "api": "na1-sapp-api.botslab.com",
        "login": "na1-sapp-login.botslab.com",
        "iot": "na1-iot-deviceapi.botslab.com",
    },
    "ap1": {
        # NB: reference constants.py had a typo (api pointed at the iot host).
        "api": "ap1-sapp-api.botslab.com",
        "login": "ap1-sapp-login.botslab.com",
        "iot": "ap1-iot-deviceapi.botslab.com",
    },
}
DEFAULT_REGION: Final = "eu1"

# --- REST endpoints ---
EP_APP_LOGIN: Final = "/v1/app/login"  # POST, Q/T -> sid
EP_DEVICE_LIST: Final = "/v1/iot/device/list"
# device shadow: battery, voltage, SD, settings
EP_DEVICE_PROPERTY: Final = "/v1/iot/device/get_desired_property"
EP_MESSAGE_LIST: Final = "/v2/message/list"  # rich: per-event image/video URLs
EP_CONFIG_EVENT_TYPE_V2: Final = "/v2/config/event_type"
# Resolves a clip's "aliyun://" video URL to a public, playable HLS proxy URL.
# GET only (POST -> code 300260). Returns {expire_time, url}; the returned m3u8 and
# its OSS-signed .ts segments are plaintext MPEG-TS and need no auth or decryption.
EP_OSS_GET_PLAY_URL: Final = "/v1/oss/get_play_url"

# --- API result codes ---
CODE_OK: Final = 0
CODE_SIGN_ERROR: Final = 1001
CODE_BAD_REQUEST: Final = 1015  # missing/expired sid
CODE_LOGIN_FAILED: Final = 100003  # missing/expired Q/T
CODE_SESSION_STOLEN: Final = 102003  # account logged in on another device (one-session limit)
CODE_ACCOUNT_TIMEOUT: Final = 102008  # account/session timed out — "please log in again"

# --- Event types (raw API `event_type` values, from the app's event catalogue) ---
# Logical event names surfaced on the HA `event` entity. The device distinguishes
# generic motion (pixel/frame change) from AI-classified person/pet/vehicle/package.
HA_EVENT_RING: Final = "ring"
HA_EVENT_MOTION: Final = "motion"  # generic motion (no AI classification)
HA_EVENT_PERSON: Final = "person"  # human detected (HumanPass/Motion/Stay)
HA_EVENT_PET: Final = "pet"
HA_EVENT_PACKAGE: Final = "package"
HA_EVENT_VEHICLE: Final = "vehicle"
HA_EVENT_TYPES: Final = [
    HA_EVENT_RING,
    HA_EVENT_MOTION,
    HA_EVENT_PERSON,
    HA_EVENT_PET,
    HA_EVENT_PACKAGE,
    HA_EVENT_VEHICLE,
]
EVENT_TYPE_MAP: Final = {
    "app.event.post.Answer": HA_EVENT_RING,
    "dsl.event.post.DoorbellRing": HA_EVENT_RING,
    "dsl.event.post.FrameChange": HA_EVENT_MOTION,
    "dsl.event.post.PictureChange": HA_EVENT_MOTION,
    "dsl.event.post.Pass": HA_EVENT_MOTION,
    "dsl.event.post.HumanPass": HA_EVENT_PERSON,
    "dsl.event.post.HumanMotion": HA_EVENT_PERSON,
    "dsl.event.post.HumanStay": HA_EVENT_PERSON,
    "dsl.event.post.Pet": HA_EVENT_PET,
    "dsl.event.post.Parcel": HA_EVENT_PACKAGE,
    "dsl.event.post.VehicleDetect": HA_EVENT_VEHICLE,
    "dsl.event.post.CarPlate": HA_EVENT_VEHICLE,
}

# --- Config entry keys ---
CONF_REGION: Final = "region"
CONF_EMAIL: Final = "email"
CONF_PASSWORD: Final = "password"  # noqa: S105 - config key name, not a secret value
CONF_M2: Final = "m2"
CONF_QID: Final = "qid"
CONF_Q: Final = "q"
CONF_T: Final = "t"
CONF_POLL_INTERVAL: Final = "poll_interval"
CONF_ENABLE_MQTT: Final = "enable_mqtt"
CONF_DEVICE_SN_FILTER: Final = "device_sn_filter"

# --- Defaults ---
# Slow poll: only device state (battery/SD/settings/online) + event fallback. QPush
# carries ring/motion in realtime, so this doesn't need to be aggressive.
DEFAULT_POLL_INTERVAL: Final = 300  # seconds (5 min)
DEFAULT_ENABLE_MQTT: Final = True
REQUEST_TIMEOUT: Final = 15  # seconds

# --- Dispatcher signals (source-agnostic: MQTT or poll both emit these) ---
SIGNAL_EVENT: Final = f"{DOMAIN}_event"  # payload: BotslabEvent
SIGNAL_SNAPSHOT: Final = f"{DOMAIN}_snapshot"  # payload: device_name (str) — snapshot bytes updated

# --- QPush realtime (Qihoo push) — plaintext TCP protocol ---
QPUSH_APPID: Final = "venqoyon9hcc"  # push application id
QPUSH_DISPATCHER: Final = "https://dp.push.dc.360.cn/v1/list/ip"
QPUSH_SDK_VERSION: Final = "2.5.24"
QPUSH_PROTO_VERSION: Final = 5
QPUSH_HEARTBEAT: Final = 60  # seconds between ping (op 0)
# op codes
QPUSH_OP_PING: Final = 0
QPUSH_OP_BIND: Final = 2
QPUSH_OP_PUSH: Final = 3
QPUSH_OP_ACK: Final = 4
QPUSH_OP_BIND_ACK: Final = 6
QPUSH_OP_ALIAS: Final = 17

# --- Device metadata ---
MANUFACTURER: Final = "Botslab"

# --- Device-shadow property identifiers (from get_desired_property "report") ---
PROP_BATTERY: Final = "BatteryLevel"  # percent
PROP_VOLTAGE: Final = "DoorbellVoltage"  # millivolts
PROP_LOW_POWER: Final = "LowPowerMode"  # bool
PROP_ONLINE: Final = "DoorbellOnlineState"  # bool
PROP_SD_STORAGE: Final = "SdStorage"  # "total,used,free" bytes (confirmed vs app Storage screen)
PROP_SD_STATE: Final = "SdState"  # 1 = present
PROP_ADC_CURRENT: Final = "DoorbellAdcCurrent"  # milliamps (charge/draw)
PROP_POWER_SUPPLY: Final = "Power_Supply"  # 0 = battery, else wired/other
PROP_BATTERY_PACK_INSTALLED: Final = "BatteryPack_Install_Status"  # bool
PROP_EXISTING_CHIME: Final = "ExistingChime"  # bool — physical mechanical chime present
