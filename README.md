# Botslab Doorbell — Home Assistant integration

Custom integration for the **Botslab / 360 Video Doorbell** (e.g. X3). Surfaces the doorbell
as a Home Assistant device with instant **ring** and **motion/person** events, battery, and an
online status sensor.

See [Live view & recordings](#live-view--recordings) for the live-stream `camera` entity and
where recorded-clip playback stands.

> Status: in development. Email/password login and cloud polling are functional.
> Realtime push (sub-second ring) and a pure-Python live-view camera are included.

## Features

- Sign in with your Botslab **email + password** — no token capture, no app hacking.
- **Realtime push** (QPush): instant `ring` / `motion` / `pet` events over a persistent
  connection — no aggressive polling, no rate-limit risk.
- `event` entity + **device triggers** ("Someone rang the doorbell", "Motion detected", "Pet").
- **Battery** level (%), **voltage**, and **low-power** mode from the device shadow.
- **SD card** presence + free space.
- **Connectivity** (online) `binary_sensor`; full device settings exposed as attributes.
- **Last-event snapshot** image entity.
- **Recorded event clips** in the HA **media browser** — browse and play each event's cloud
  clip (resolved on demand to a plain HLS stream; no subscription, no decryption).
- Automatic token refresh + re-login (self-healing sessions).

> Note: Botslab enforces one active session per account. Running this alongside heavy use of the
> phone app may cause you to be signed out of one or the other. For 24/7 use, consider sharing the
> doorbell to a **second Botslab account** dedicated to Home Assistant.

## Installation (HACS)

1. Add this repository as a custom repository in HACS (category: *Integration*).
2. Install **Botslab Doorbell** and restart Home Assistant.
3. Settings → Devices & Services → **Add Integration** → *Botslab Doorbell*.

## Configuration

Add the integration and enter your Botslab **email**, **password**, and **region** (eu1/eu2/na1/ap1).
The integration logs in directly against the Botslab cloud (the same QUC login the app uses,
re-implemented in Python) and stores the resulting session. Tokens are refreshed automatically;
if your password changes, Home Assistant will prompt you to re-authenticate.

## Automations

Use the doorbell **event** entity or the device triggers ("Someone rang the doorbell",
"Person detected") to drive notifications, lights, TTS, etc.

```yaml
automation:
  - alias: Doorbell ring notification
    triggers:
      - trigger: state
        entity_id: event.doorbell_doorbell
        attribute: event_type
        to: ring
    actions:
      - action: notify.mobile_app_my_phone
        data:
          title: "Doorbell"
          message: "Someone is at the door 🔔"
```

## Live view & recordings

The doorbell's video path is implemented in pure Python. Details:

- **Live view works** via a `camera` entity, implemented entirely in pure Python (no app, no
  native libraries). The doorbell uses Qihoo's proprietary **GodSees** transport — a UDP P2P
  tunnel that triggers the battery unit to publish, then a QTP relay carrying per-frame
  **ChaCha20**-encrypted H.264; there is no RTSP/RTMP/WebRTC endpoint to consume directly. The
  full handshake, signalling (double-base64 RC4) and media decryption are implemented in
  `custom_components/botslab/live/`. The decrypted H.264 is remuxed to a local
  MPEG-TS feed with `ffmpeg -c copy` (**no transcoding** — runs on a transcode-less NAS such as a
  Synology DS713+) and served to Home Assistant's `stream` component. The session starts only
  while you are watching and stops shortly after, so the battery unit publishes on demand.

  Opening the stream wakes the doorbell over the cloud, so first frame takes a few seconds.
  Requires the `ffmpeg` and `stream` integrations (declared as dependencies).

- **Recorded event clips work** (see Features). Each cloud event's `aliyun://` clip URL is
  resolved on demand via `GET /v1/oss/get_play_url` to a public HLS playlist whose MPEG-TS
  segments are plaintext — so playback is plain HTTP, no subscription, no decryption. Exposed
  in the media browser under **Botslab Doorbell**.

## Development

```bash
pip install -r requirements_test.txt   # HA + pytest-homeassistant-custom-component (needs Python 3.13)
ruff check custom_components tests      # lint
pytest                                  # unit tests (api, coordinator, config flow, crypto, models, setup)
```

Tests live in `tests/` with sanitized cloud responses in `tests/fixtures/`. CI runs
[hassfest](https://developers.home-assistant.io/) + the HACS action on every push, plus the
pytest suite. The pure-Python login crypto and the sapp-api signing scheme are covered by
`test_crypto.py` / `test_api.py`; the event dedup/priming and session-refresh ladder by
`test_coordinator.py`.

## Disclaimer

Unofficial integration for personal interoperability with hardware you own. Not affiliated with
or endorsed by Botslab / Qihoo 360. Use at your own risk.

## License

MIT — see [LICENSE](LICENSE).