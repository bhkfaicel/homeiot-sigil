# Changelog

All notable changes to this project will be documented in this file.

The format is inspired by [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to semantic versioning.

## [Unreleased]

- Version the footprint measurement report in the documentation tree
  (`docs/footprint-report.md`) instead of the untracked working-notes
  directory, and rename its companion example binary to match
  (`examples/footprint_report.rs`, previously `examples/footprint_scratch.rs`).
  The report records measured bytes per type per feature configuration plus
  the host-firmware stack high-water procedure; no production code changes.

- Consolidate gateway install admission into a two-phase flow so an accepted
  install request performs at most one full-table cooldown scan instead of
  three: `AdmissionStore` now exposes a single-purge decide phase
  (`admit_install`, which reclaims expired entries once and then applies the
  cooldown and capacity guards in the documented order) plus a scan-free
  post-authentication stamp (`stamp_install_request`). The stamp still
  happens only after both ECDSA verifications bind the claimed identity and
  strictly before ECDH/signing, unauthenticated senders can still never stamp
  or poison cooldown state, and every error variant and guard ordering is
  unchanged (`PendingAlreadyExists` → `SessionTableFull` →
  `PendingTableFull` → `RateLimited` → `AdmissionTableFull`). Internal
  optimization only: no wire format, public API, or security-property change.

- Deliver received Events without a second payload copy: the authenticated
  ingress primitive now moves the decrypted `DATA`-capacity plaintext buffer
  into the Event delivery handler, which strips the 8-byte event id in place
  (`rotate_left` + `truncate`) after the durable-delivery stamp. Exactly one
  `DATA`-sized buffer is alive on the Event receive path, matching the Data
  path. Wire format, public API, replay/duplicate semantics, and the
  fail-closed ordering are unchanged: every rejection still happens strictly
  before the delivery stamp, and the former post-stamp buffer-overflow
  failure is structurally impossible because the authenticated plaintext
  already fits `DATA`. Internal optimization only; no behavioral change.

- Add dev-only footprint reporting tooling alongside the performance
  measurement suite: a test-only breakdown of every `PendingState` variant's
  nominal byte cost (`src/core/pending/tests/footprint_report.rs`) and an
  example binary (`examples/footprint_report.rs`) printing `size_of` for the
  public manager/session/pending/event/action types per feature
  configuration. All numbers are host-target measurements for planning only;
  final flash, RAM, and stack budgets remain host-firmware responsibilities,
  measured on optimized target artifacts.

- Add a dev-only host-side performance measurement suite (test files under
  `src/core/aead/tests/`, `src/core/pipeline/tests/`,
  `src/core/manager/tests/`, and `src/core/install/tests/`, all named with the
  `perf_measurements_` prefix and printed with `--nocapture`). It records the
  first timing/copy baseline for the Data AEAD primitives at representative
  payload lengths, the Event receive path (including the structural second
  payload copy), clear-text handshake frame classification, `tick` at
  empty/half/full pending occupancy, install admission helpers and the full
  request handler at empty/half/full cooldown occupancy with source-level
  purge-scan counts, and FNV-indexed session lookups at 1/64/128 keys. All
  measurement code is test-only (`cfg(test)`), adds no dependency, and leaves
  every production feature configuration byte-identical; host wall-clock
  numbers are informational only and are not target metrics.

- Reconcile the host-facing documentation with the shipped code: the README now
  states that `sensor` is the default feature and describes every supported
  configuration (`wire`, `sensor`, `gateway`, `sensor,gateway`) together with
  the exact compile-time diagnostic emitted for an unsupported empty feature
  set; protocol-version wording is unified on the `0x03` outer header; renew
  guidance matches the P-256 ephemeral ECDH implementation; French passages are
  translated to English and broken list formatting repaired; documentation no
  longer links files removed from the git index (the specs tree) and instead
  points integrators at this document plus the crate rustdoc. Error guidance
  references the refined capacity variants, and footprint budgeting stays a
  generic host responsibility. Documentation-only change.

- Refine the host-visible error taxonomy: new `SigilError` variants distinguish
  fixed caller-buffer sizing (`OutputBufferTooSmall`), session-table saturation
  (`SessionTableFull`), pending-handshake-table saturation (`PendingTableFull`),
  gateway admission/cooldown-table saturation (`AdmissionTableFull`), malformed
  wire input (`MalformedFrame`), session-role mismatches (`WrongRole { peer }`),
  and internally unrepresentable states (`InvariantViolation`). Every variant
  documents exactly one deterministic host policy category — reject input, fix
  integration, back off / reclaim capacity, or report invariant failure — and an
  exhaustive test pins every variant to its documented category while keeping
  `Display` output free of key material, MAC tags, PSKs, and shared secrets. The
  former coarse capacity/parsing/handshake-state variants are removed outright
  instead of being retained as deprecated aliases: a conscious breaking change
  approved by the crate owner before any production use of this crate, with
  version-bump discipline left to the owner's choice at release time. Hosts that
  match exhaustively on `SigilError` must drop the removed arms.
  `InvalidStep { peer }` stays the canonical transition-mismatch error. No
  payload, `Display`, or wire behavior changed beyond the variant set itself.

- Split the internal packet pipeline into cohesive semantic handlers: Data
  plus the shared authenticated egress AEAD primitive live in a data module,
  the Event/EventAck durable-delivery transaction in an event module, and
  TimeSync/TimeSyncRequest handling with its per-session request cooldown in
  a timesync module. The single authenticated, replay-checked ingress
  primitive keeps session lookup, direction checks, expiry, AEAD open, RX
  counter advance, and commit release in one place; handlers receive only
  already-authenticated context. Every counter/state mutation point is
  documented, and isolated handler-level tests now cover the Event delivery
  transitions and the TimeSync cooldown independently of full radio
  scenarios. Internal refactor only: no wire format or public API change.
- Refactor the internal pending-handshake representation into a tagged
  `PendingState` enum whose twelve role-gated variants (install, renew, and
  resume across sensor and gateway roles) carry only the fields valid for that
  phase, role, and step, replacing the former independent phase/role/step
  product. Handshake transitions are now checked against the tagged state,
  commit-criticality and cached-retransmission capability are derived in one
  place, and secret-bearing stashes keep their zeroizing types. The
  gateway-exclusive P-256 context stash is compiled only for gateway builds,
  keeping sensor-only builds free of dead code. Internal refactor only: no
  wire format or public API change.
- Repair the baseline quality gates: `scripts/test.sh` now delegates the test
  matrix to the authoritative `scripts/test-feature-matrix.sh` gate (approved
  empty-feature diagnostic plus `wire`, `sensor`, `gateway`, `sensor,gateway`,
  and all-features locked suites) and its remaining cargo invocations are
  locked; CI format and lint steps run the same locked commands as local
  validation.
- Fix the pre-existing import-order formatting drift in `src/core/mod.rs` so
  `cargo fmt --all -- --check` passes again without unrelated reformatting.
- Pin `lychee` 0.24.2 as the offline markdown link checker for local and CI
  use, installed with `cargo install --locked --version 0.24.2 lychee` and
  provisioned identically in the CI workflow.
- Add library-owned `size_of` regression bounds for `Session`,
  `PendingHandshake`, `SessionManager<2>`, `SessionManager<128>`,
  `SigilEvent<200, 256>`, and `SigilAction<256>`, with per-feature-configuration
  measured sizes and documented crate-owner approval path for raising a bound.
- Document the generic footprint contract at crate level: final flash, static
  RAM, and stack budgeting is the host firmware's responsibility on its final
  linked image; the library bounds are planning inputs only.
- Reject the empty feature configuration at compile time with an explicit
  diagnostic directing integrators to `wire`, `sensor`, or `gateway`.
- Fix the wire-only test target: shared session test support no longer
  compiles without the `session` feature, so the manufacturing (factory
  certificate) tests run again under `cargo test --no-default-features
  --features wire`.
- Document the supported feature matrix (`wire`, `sensor`, `gateway`, and the
  explicit `sensor,gateway` composition) and add
  `scripts/test-feature-matrix.sh` as the authoritative locked feature-matrix
  gate covering every supported configuration and asserting the approved
  empty-feature diagnostic.
- Protect enrollment PSKs with a redacted, zeroizing `ResumePskSecret`; actions
  and decrypted events no longer derive `Clone`, and event debug output redacts
  payload/frame bytes.
- Validate restored enrollment material and factory-root key encodings at API
  boundaries. `Session::new_enrolled` and `SessionManager::new` now return
  `Result`; enrolled shells no longer accept or retain a meaningless expiry.
- Make `sensor` the safe, smallest default role, declare Rust 1.85 as the MSRV,
  and execute role-specific protocol smoke tests in each mono-role
  configuration.
- Extract the session manager's inline storage into crate-private, cohesive
  components: a session table keyed by remote peer MAC, an independent pending
  table for in-progress handshakes and post-commit loss recovery, and a
  gateway-only per-peer install-cooldown table. The manager facade now lends a
  narrow multi-store view to the encrypted pipeline and the install, renew,
  and resume handshake implementations, so protocol code mutates only the
  storage capabilities it needs instead of reaching into manager internals.
  Facade helpers left without production callers by this migration moved
  behind test-only compilation gates, and new store-level saturation tests pin
  each capacity domain as an independently observable signal: known-peer
  replacement versus unknown-peer rejection in the session table, duplicate
  pending versus pending saturation, and time-healed admission cooldowns. No
  public API or wire change; type-size bounds are unchanged. Gateway builds explicitly disable defaults.

### Architecture hardening

- Test the `sensor` and `gateway` production feature sets independently and
  compile the sensor feature for `thumbv6m-none-eabi` in the standard test script.
- Centralize encrypted-frame identity, type, nonce-prefix, replay and AEAD
  verification in one internal fail-closed path.
- Add observable, bounded post-commit recovery with `pending_len`,
  `pending_peers`, `commit_recovery_peers` and `abandon_commit_recovery`.
- Stop exporting active AEAD keys/nonces from `Session`; enrollment material is
  delivered only through `PersistPeerStaticKey`.
- Reject null provider ECDH results consistently across Install, Renew and
  Resume, and strengthen the static-ECDH provider contract for malformed keys.
- Make `Session` peer identity and factory-attested static key immutable through
  public getters so mutable manager access cannot corrupt the lookup invariant.
- Zeroize every temporary HKDF output used to construct Resume challenge MACs.
- Vendor security-sensitive Forgejo workflows locally, pin `actions/checkout`
  to an immutable revision, and enable `cargo deny`; the remaining external
  branch-flow validator is immutable and receives no secret.
- Clarify that protocol/radio waits are non-blocking while secure-element calls
  are synchronous and occupy the calling task.

### Time synchronization request

- Add authenticated sensor→gateway `TimeSyncRequest` (`0x33`) and the
  `request_time_sync` sensor API. The gateway receives a typed event and keeps
  explicit control of the existing `TimeSync` response.
- Enforce direction, AEAD replay protection, empty request bodies and a
  15-second per-peer acceptance cooldown before the host may respond.

### Reliable Events

- Add sensor→gateway `Event` (`0x31`) and authenticated gateway→sensor
  `EventAck` (`0x32`) with AEAD replay protection and strict role checks.
- ACK creation is explicitly two-phase: the gateway host durably processes an
  Event before calling `ack_event`; ACK construction failures preserve pending
  delivery state, while `release_event_delivery` supports storage failures
  without falsely acknowledging the Event.
- Add monotonic host-assigned event ids, one in-flight Event per session,
  exact ACK matching, retry with fresh AEAD counters, duplicate suppression,
  `EVENT_ACK_TIMEOUT_MS`, and `cancel_pending_event`.
- Add security tests for ACK loss/retry, replay, wrong ACK ids, premature ACK,
  direction violations, frame-type tampering and fail-closed buffer handling.

## [1.0.1] - 2026-08-06

### Security / breaking API

- Factory certificates now bind `hardware_profile_id` and `factory_key_id` in
  addition to product, PeerId and static public key. `SecureElement` exposes the
  protected metadata; Install Request/Challenge are now 215/219 bytes.

- **`SessionManager::new(factory_pubkey, local_mac)`** — egress outer header is
  always the sender identity; sessions are keyed by the remote peer. Fixes
  multi-sensor gateway session collapse and allowlist ambiguity.
- **`SigilAction::Transmit { wait_timeout_ms }`** — advisory radio wait after TX
  (host must still call `cancel_pending`).
- **Resume challenge MAC** (`sigil-resume-mac`) binds clear-text `key_expire_at`
  to the static ECDH secret; MITM expiry flips fail before key install.
- **Resume rejects active sessions** (`SessionAlreadyActive`) — use renew.
- **Renew gateway** zeroizes the X25519 scalar after ECDH (no secret overwrite leak).
- **Install gateway discovery is mandatory** — use `INSTALL_DISCOVERY_DEST` (or
  host broadcast); `continue_install` rebinds pending to the real gateway MAC
  from `InstallChallenge`. Unicast-to-known-gateway is not the supported
  first-pairing model.
- **Discovery rebind hardened** — outer≡body check before rebind; multi-pending
  → `InvalidHandshakeState`; failed challenge rolls pending back to discovery
  dest.

### Tests / docs

- Pairwise install/renew/resume tests use distinct `SENSOR_MAC` / `GW_MAC`.
- Multi-sensor install isolation test on gateway.
- README / quickstart / session-api / CLAUDE updated for identity model.

### Breaking

- Introduce a new **non-blocking session core** under `src/core/`.
  - `SessionManager<N>` with host-owned I/O; no radio or `delay_ms` inside the library.
  - Host traits `SecureElement` and `RandomSource` replace direct hardware coupling.
  - Single ingress `process_incoming_packet` + egress `encrypt_data`.
  - Three host-driven phases: **install** (identity + SE), **sensor-initiated renew** (pure-software eph↔eph ECDH), **fast resume** (static↔static via SE ECDH only).
  - Directional `tx_counter` / `rx_counter` for AEAD nonces; replay-protected RX path.
  - Explicit `cancel` / `remove` on pending handshakes; no auto-renew on expiry.
- **Remove the entire legacy blocking stack** (`src/com/`, `src/models/`, `src/crypto/`).
  - The `com`, `models`, and `legacy-lora` feature flags are gone.
  - The `lora`, `embedded-hal`, `embedded-hal-mock`, and `log` dependencies are removed.
  - The old `Sigil::read()` entry point and all blocking handshake functions are gone.
- Add `p256` (ECDH, `no_std`) and `zeroize` dependencies.

### Compatibility

- Wire layouts are **breaking**. The 17-byte peer MAC format is retained.
- No dual-stack parser; flash sensor and gateway together.

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
