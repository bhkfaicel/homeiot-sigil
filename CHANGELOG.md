# Changelog

All notable changes to this project will be documented in this file.

The format is inspired by [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to semantic versioning.

## [0.5.3] - 2026-08-04

- Test workflow

## [0.5.2] - 2026-08-04

- Update workflow.

## [0.5.1] - 2026-08-04

### Changed

- `log` dependency updated to **`0.4.33`**.
- `heapless` dependency updated to **`0.9.3`**.

## [0.5.0] - 2026-08-04

### Changed

- CI publish flow aligned with lis2dh12: `Cargo.toml` stays at stable `X.Y.Z`; `dev` tags `vX.Y.Z-rc` → forgejorc; `staging` is merge gate only; `main` tags `vX.Y.Z` → forgejo and creates `release/X.Y` for hotfixes.
- Add: `check-on-feature-branch.yml`, `create-tag-on-dev.yml`, `create-tag-on-main.yml`; rewrite `publish-on-tag.yml` (shared `central_ci` checks, `enable_tag_check: false` on tag publish).
- Add: `scripts/check-version-sync.sh`, `resolve-cargo-registry.sh`, `release-branch-name.sh` (+ unit tests).
- Docs: `.forgejo/README.md` documents the release / maintenance-branch model.
- Remove: legacy `publish-on-dev.yml` / `publish-on-main.yml` (PAT-in-URL + Cargo.toml `-rc` bump on main).
- Add: `validate-branch-flow.yml` calls shared `faicel/central_ci` → `validate_flow.yml` (`* → dev`, `dev → staging`, `staging → main`); remove local `enforce-branch-flow.yml`.

## [0.4.0-rc.0] 2026-07-14

### Added

- **Session resume** (`com::handshake::resume`): `resume_session()` (sensor) and
  `handle_resume_request()` (gateway) for already-enrolled sensors that lost the session key.
  Clear-text `SessionResumeRequest` → `SessionResumeChallenge` → `SessionResumeConfirm` —
  ECDSA identity proof + ephemeral-to-ephemeral ECDH, **without** rebroadcast install or the
  previous session key (unlike renew).
- New `MessageType` values: `SessionResumeRequest`, `SessionResumeChallenge`,
  `SessionResumeConfirm`.
- Sequence diagram: `diagramme/session_resume.mermaid`.

### Changed

- **Breaking (install wire + API):** install now uses **ephemeral-to-ephemeral ECDH** instead of
  ECIES eph→static. `HandshakeChallenge` is a structured clear-text message
  `{gw_eph_pubkey, sig_sensor_nonce, gateway_pubkey, gateway_nonce, key_expire_at}` (replaces the
  194-byte ECIES blob). `HandshakeConfirm` adds `sensor_eph_pubkey_compressed` (33 bytes).
- **Breaking (install API):** `install_session()` / `initiate_handshake()` callback renamed to
  `ecdh_ephemeral_with_peer`: `FnMut(&gw_eph_pubkey) -> Result<(sensor_eph_pubkey, shared_secret), ()>`.
- **Breaking (install API):** `handle_install_request()` / `handle_handshake_request()` replace
  `ecies_encrypt` with `generate_gateway_ephemeral()` and `ecdh_with_sensor_ephemeral()`.
- **Breaking (renew wire + API):** renew now uses **ephemeral-to-ephemeral ECDH** instead of
  ephemeral-to-static. `KeyRenewAck` carries `sensor_eph_pubkey_compressed` (33 bytes) instead of
  being an empty unit struct.
- **Breaking (renew API):** `renew_session()` callback renamed to `ecdh_ephemeral_with_peer`:
  `FnMut(&gw_eph_pubkey) -> Result<(sensor_eph_pubkey, shared_secret), ()>`.
- **Breaking (renew API):** `handle_renew_request()` takes two callbacks:
  `generate_gateway_ephemeral() -> gw_eph_pubkey` and
  `ecdh_with_sensor_ephemeral(&sensor_eph_pubkey) -> shared_secret` (replacing the single
  `ecdh_ephemeral(&sensor_long_term_pubkey)` callback).

### Migration

- Deploy **sensor and gateway firmware together** when upgrading to 0.4.0-rc.0: install and renew
  wire formats are not backward-compatible with 0.3.x (ECIES install challenge, empty `KeyRenewAck`).

---

## [0.3.0-rc.1] 2026-07-13

### Updated

- Fix lint

## [0.3.0-rc.0] 2026-07-10

### Added

- **Lightweight session key renew** (`com::handshake::renew`): `renew_session()` (sensor) and
  `handle_renew_request()` (gateway) using encrypted `KeyRenewRequest` → `KeyRenewChallenge` →
  `KeyRenewAck` — **ECDH only**, no ECDSA signatures and no ECIES 194B challenge on the renew path.
- New `MessageType` values: `KeyRenewRequest`, `KeyRenewChallenge`, `KeyRenewAck`.
- `ValidatedKey` expiry helpers (`is_valid`, `should_renew`) with unit tests.
- Handshake module layout: `primitives/`, `lora_helpers/`, `install_core/`, `renew_core/`.
- Sequence diagrams: `diagramme/install.mermaid`, `diagramme/renew.mermaid`.

### Changed

- **Breaking (renew API):** `renew_session()` no longer accepts ECDSA callbacks
  (`verify_sig_sensor_nonce`, `sign_gateway_nonce`). Only `ecdh_shared_secret` is required.
- **Breaking (renew API):** `handle_renew_request()` no longer accepts `ecies_encrypt`,
  `verify_sig_gateway_nonce`, or gateway identity fields for signing. It takes
  `session_key`, `chacha_nonce`, and `ecdh_ephemeral` instead.
- Install flow unchanged: `initiate_handshake()` / `handle_handshake_request()` still use
  ECIES + ECDSA for first-time pairing.

### Migration

- Deploy **sensor and gateway firmware together** when upgrading renew: the lightweight renew
  protocol is not wire-compatible with re-running the full install handshake for renewal.

---

## [0.2.2-rc.0] - 2026-07-02

### Changed

- `lora` dependency updated to **`0.3.0-rc.0`** (registry `forgejorc`).

## [0.2.1-rc.7] - 2026-06-29

### Added

- `LORA_USER_PAYLOAD_MAX` (`254`) in `models::common`: maximum user bytes for `lora::Controller::send` (one FIFO byte reserved for the compression flag).
- `MessageSchema::serialize_with_len` and `serialize_clear_with_len`: return `(buffer, wire_len)` so callers send only `&buffer[..wire_len]` on LoRa.
- `HandshakeSession` (sensor): wraps `Keys` plus `gateway_mac` from the `HandshakeChallenge` header (`src`).
- `GATEWAY_CONFIRM_RX_TIMEOUT` (`180`) and `GATEWAY_CHALLENGE_RESEND_PERIOD` (`10`) exported from `com::handshake` with documentation.

### Changed

- **Breaking:** `initiate_handshake` returns `HandshakeSession` instead of `Keys` (use `.keys` for the session key and expiry metadata).
- `lora` dependency updated to **`0.2.0-rc.7`** (registry `forgejorc`).
- `HANDSHAKE_MESSAGE_MAX` set to **250** bytes for handshake wire buffers.
- All LoRa TX paths (handshake, events, `Sigil::read` fallback ACK) send the **encoded length** only, not a zero-padded full buffer.
- Gateway handshake: confirm listen window **60 → 180** attempts (~**36 s** at ~200 ms per `NoPacket` retry) so slow sensor ECDH (ATECC608A) can uplink `HandshakeConfirm` without the gateway timing out and starting a new ephemeral session.
- Sensor handshake: challenge listen **`rx_timeout` 80 → 800**; `HandshakeRequest` rebroadcast delayed (first at attempt **50**, then every **50**) to reduce half-duplex collision with the gateway challenge.
- `HandshakeConfirm` remains **clear-text** on the wire (`serialize_clear_with_len`); session key is derived locally after verify + confirm send.

### Fixed

- `ComError::MessageTooLong` when an encoded handshake or event payload exceeds `LORA_USER_PAYLOAD_MAX` before TX.
- Gateway aborts before sending a challenge when `ecies_encrypt` fails (zero shared secret or zero ephemeral pubkey prefix in the ciphertext).
- Trailing zeros in oversized LoRa TX buffers no longer break `deserialize_clear` on the receiver.
- Handshake tests updated for wire-length sends and realistic ECIES test ciphertext layout (non-zero compressed ephemeral pubkey).

## [0.2.1-rc.6] - 2026-03-08

### Changed

- `lora` mis à jour sur `0.2.0-rc.3` (compilation locale via `path` pendant la préparation/reproductibilité).
- Ajustement de la taille de sérialisation des messages `Event` de `serialize::<256>` vers `serialize::<255>` pour respecter la contrainte `lora` (1 octet réservé au flag de compression).
- Alignement des tests de handshake avec la logique réelle de retransmission/rebroadcast (confirm retries, périodes de renvoi).

### Fixed

- Corrections des attentes `embedded-hal-mock` (mode SPI et séquences d’accès) liées aux changements de comportement induits par `lora 0.2.0-rc.3`.
- Vérification que `cargo test -p sigil --offline` passe pour la suite de tests du crate.

---

## [0.2.1-rc.5]

### Added

CHANGELOG.md

### Changed

- Added Forgejo workflows:
  - `.forgejo/workflows/publish-on-main.yml`
  - `.forgejo/workflows/publish-on-tag.yml`
- Cleaned documentation formatting according to Clippy.

### Fixed

- Resolved proc-macro ABI mismatch issues by cleaning and rebuilding.
- Corrected `bincode` dependency to a 2.x version (`2.0.0`) with `derive` feature.
- Removed unused `lzss` dependency from `Cargo.toml`.

---

## [0.1.0] - 2026-03-12

Initial release of `sigil` as an internal / non-commercial crate.

- First public API for LoRa communication, initialization, and key management.
- Basic tests and doctests for crypto, events, init flows, and models.
