# Changelog

All notable changes to this project will be documented in this file.

The format is inspired by [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to semantic versioning.

## [Unreleased]

### Changed

- `usbserial`: `SecureChannel::seal` now refuses to seal once its send counter
  reaches `u64::MAX` with the new `Error::CounterExhausted` variant instead of
  silently wrapping into AEAD nonce reuse, and commits the counter only after
  the frame is fully sealed, so a failed seal leaves the channel untouched.
  This variant is a new member of the plain `pub enum` `usbserial::Error`
  (no `#[non_exhaustive]`): downstream exhaustive matches must gain an arm,
  which is a breaking change to ship with a major version bump.
- `usbserial`: the `TX_RESULT` message now enforces an exact one-byte body
  like every other message type. Frames with trailing bytes are dropped as
  malformed instead of silently accepted; no legitimate peer emits them (the
  encoder always writes exactly one status byte) and the wire format is
  unchanged.
- `usbserial`: the feature no longer activates the optional `subtle`
  dependency, which no usbserial code uses. `subtle` still reaches those
  builds transitively via `chacha20poly1305` and remains a direct dependency
  of the `session` feature, so all builds are unchanged.

### Fixed

- `usbserial`: corrected the `TX_RESULT` type-constant doc comment — the
  completion report flows head → host, matching the message-types table.

## [1.3.0] - 2026-09-24

- Add the USB-serial link tier (`src/usbserial`) behind the new `usbserial`
  cargo feature (off by default; never implied by another feature, following
  the `ota` precedent). The tier frames the byte stream between the gateway
  host and the SAMD21 radio head:
  - Plain profile: COBS blocks with a `0x00` delimiter, CRC-16/CCITT-FALSE
    over type + body, link message types RX / TX_REQ / TX_RESULT / PING /
    PONG (0x01..0x05), 255-byte radio payload bound (SX1278 8-bit length
    register), streaming `Decoder` with bounded queue, drop counters and
    delimiter resync.
  - Secure profile: HELLO handshake (clear 16-byte nonces both directions,
    last HELLO wins), HKDF-SHA256 over a 32-byte PSK with
    `salt = host_nonce || head_nonce` and fixed directional OKM split
    (key + 4-byte nonce prefix per direction), ChaCha20-Poly1305 sealing
    with the clear counter and type byte bound as AAD, strictly increasing
    receive counters with the watermark advanced only after tag
    verification, PSK/keys zeroized on drop and redacted from `Debug`.
- Feature contract: the standalone `usbserial` configuration (and its
  combinations `gateway,usbserial`, `--all-features`) is now supported and
  exercised by `scripts/test-feature-matrix.sh`; the `compile_error!` guard
  accepts the new tier.

## [1.2.2] - 2026-09-05

- Update link on readme

## [1.2.1] - 2026-09-05

- Update README.md
- Migrate the Forgejo CI workflows to thin callers delegating to the shared
  `faicel/central_ci` reusable workflows (checks, tag creation on `dev`/`main`,
  publish on tag, branch-flow validation) and delete the local
  `.forgejo/workflows/_rust-crate-checks.yml` gate. All callers pass
  `test_command: bash scripts/test.sh`; the feature clippy matrix (all
  features, sensor, gateway) moves into that script so CI lint coverage is
  unchanged. Add `scripts/deny-check.sh` as the local dependency-policy
  wrapper. `.forgejo/README.md` documents the thin-caller model and the
  owner-accepted risk of tracking the mutable `central_ci@main` ref.

## [1.2.0] - 2026-08-25

- Add the OTA firmware-update protocol module (`core::ota`) behind the new
  `ota` cargo feature (off by default; never implied by another feature).
  The module is fully additive: no `SigilEvent`, `SigilError`, or
  `FrameType` changes, and plain `sensor` / `gateway` builds carry zero OTA
  code. Feature tiers:
  - `ota` alone compiles the shared wire tier only — command constants under
    the product gateway-command envelope (`0x7F`, ids `0x10..0x18`), a
    bounds-checked frame codec that never panics on malformed input,
    `manifest_digest_input` / `manifest_digest` as the single source of
    truth for signed-manifest digests, and the local `OtaError` taxonomy.
  - `sensor,ota` adds the receive half: the host-implemented `OtaStorage`
    sink trait, the 46-byte `TrailerRecord` bootable marker (magic `"SOTA"`,
    little-endian fields, strict status byte), and the `OtaReceiver` engine
    with strictly contiguous chunk acceptance, incremental SHA-256
    integrity, erase-once block bookkeeping bounded by `MAX_STAGING_BLOCKS`,
    finalize gated on ECDSA verification through the existing
    `SecureElement::verify_ecdsa` trait, STATUS projection, ABORT, and an
    idle-timeout policy.
  - `gateway,ota` adds the send half: the host-implemented `OtaImageSource`
    trait and the `OtaSender` stop-and-wait engine with a full-image digest
    preflight, deadline-driven bounded resends (`1 + max_retries`
    transmissions per frame), cumulative-ACK progress, STATUS-driven resume,
    and REBOOT unlocking only after verified completion.
    Wire contract and trailer layout are frozen by hand-written golden-vector
    tests intended for verbatim duplication in firmware, gateway, and signing
    tooling. An interop suite drives both engines against each other through
    the real codec over a lossy in-memory link.
- Security hardening of the OTA module (same release, pre-publication):
  manifest v2 binds the PRODUCT ID into the signed digest (`sigil-ota-v2`
  domain), so images signed for one product are rejected by another sharing
  the factory root; BEGIN authenticates the manifest signature BEFORE any
  staging flash access; a rollback-protection floor (`min_acceptable_version`)
  rejects strictly older signed versions with the new wire verdict
  `VERSION_REJECTED (6)` while equal versions remain valid repairs; an
  absolute per-session lifetime ceiling bounds identical-BEGIN refresh
  pinning; literal golden vectors for the signed manifest input, digest,
  P-256 key and signature are cross-checked against the independent `p256`
  implementation; host authorization requirements (one receiver per
  authorized gateway, host-owned admission budgets) are documented.
- Extend the locked feature-matrix gate with the `ota`, `sensor,ota`, and
  `gateway,ota` configurations, and the embedded cross-checks with
  `thumbv6m-none-eabi` builds of `sensor,ota` (constrained receive half)
  and `armv7-unknown-linux-gnueabihf` builds of `gateway,ota`.
- Accept the `ota`-only configuration in the empty-set compile-time
  diagnostic so signing tooling can depend on the shared wire tier without
  any session role.

## [1.1.0] - 2026-08-23

- CI embedded cross-checks: install `thumbv6m-none-eabi` and
  `armv7-unknown-linux-gnueabihf` via `rustup target add` in
  `scripts/test.sh` before the locked `cargo check` gates. The CI container
  image does not pre-install those targets, which caused `can't find crate for
core` after the feature-matrix suite passed.

- Document the formally accepted forward-secrecy characteristic of the
  Install and Resume handshakes in a new README security/threat-model
  section. The section records the owner's formal acceptance statement —
  session epochs from Install and Resume are derived from static↔static
  ECDH, so recorded epochs become decryptable if a device's static private
  key is extracted after traffic recording (accepted on 2026-08-22) — plus
  the mitigating context (Renew derives its epochs from ephemeral P-256 ECDH
  and stays forward-secret; ATECC608-class secure elements keep static keys
  non-exportable, holding the extraction cost at the physical/side-channel
  class; re-installing mixes fresh nonces but does not restore forward
  secrecy for already-recorded epochs) and integrator guidance (do not rely
  on Install/Resume for long-epoch confidentiality; keep key lifetimes well
  under `MAX_SESSION_LIFETIME_SECS` and drive Renew regularly so most live
  epochs are forward-secret; prefer Renew rotation). CLAUDE.md carries a
  matching pointer note in its host-responsibilities guidance.
  Documentation-only change: no code, wire-format, or API change.

- Implement the gateway replay defense for clear-text handshake initiators
  per the accepted design (`docs/anti-replay-design.md`). A crate-private,
  gateway-gated `ReplayCache` FIFO ring (`heapless::Deque` sized by the
  manager generic capacity) holds `(handshake_kind, peer_mac,
initiator_nonce, seen_at)` triples of accepted install/resume requests.
  An exact-triple redelivery returns the new additive error variant
  `HandshakeReplay { peer }` with zero secure-element/HKDF work; a cache
  full of live entries refuses fresh initiators fail-closed through the new
  `ReplayCacheFull { peer }` variant (family of the table-full variants).
  Purge, lookup, and the capacity pre-check run after the cheap guards and
  before any cryptography (install: between the admission decide phase and
  the first ECDSA verify; resume: between the pending/cooldown guards and
  the request-MAC verification), and cache insertion happens only as the
  final step of a successful invocation immediately before Transmit, so
  every downstream failure leaves the cache byte-identical and never
  denies a legitimate retry. TTL expiry beyond the 3,600-second horizon is
  the only removal mechanism — exact tail-plus-head cross-wrap arithmetic
  under the monotonic half-range clock contract — and no live entry is ever
  evicted or refreshed. Sensor builds pay zero bytes (the store and its
  wiring are compiled out of non-gateway configurations). The resume
  request handler applies the one declared ordering adjustment: the
  same-peer pending guard and the per-peer cooldown now precede the
  request-MAC verification, so in-cooldown duplicates keep returning
  `RateLimited` and bad-MAC frames inside a cooldown surface as
  `RateLimited` rather than `VerificationFailed`. Twenty-eight named tests
  cover thirteen downstream-failure retry classes and fifteen core
  adversarial scenarios (pre-crypto rejection with zero-crypto assertions,
  multi-peer bounds, churn without resurrection, fail-closed saturation
  with expiry recovery, forged-frame live-entry immutability, exact
  wrap-boundary expiry, guard precedence on both paths, cached
  retransmission, stale and reboot residuals, wire/size regression pins).
  Three pre-existing suites were updated to pin the newly documented
  semantics instead: identical recordings re-delivered past the lapsed
  cooldown now assert `HandshakeReplay` with recovery restarting via a
  fresh initiator nonce, and the uniform-capacity pending-saturation
  scenario ages its fill phase past the horizon so the pending-table
  refusal surfaces through the pre-insert replay check as designed. The
  all-features suite total rises from 300 to 328 passed.

- Revise the gateway replay-defense design document
  (`docs/anti-replay-design.md`) through four security-revalidation rounds.
  The third round applied three precision corrections only: a written
  side-effect proof for the pre-authentication purge with the spoof-resistance
  invariant narrowed to live-entry immutability (strictly-expired-prefix
  reclamation permitted; post-auth relocation rejected in-document), a
  completed resume ordering contract placing session-existence and role
  checks exactly, enumerating every pre-MAC observable state including global
  cache saturation, and pinning the active-session boundary to the host
  `clear_expired_key` API (none in-handler), and named malformed-provider-key
  plus null-ECDH-output retry tests on both paths. The fourth round applied
  three precision corrections only: the install malformed-provider-key test
  now targets the actual failure site — a malformed gateway-local key
  returned by `get_static_pubkey` and rejected by encoding validation
  immediately after retrieval (post-authentication, pre-ECDH) — while a
  wire-supplied peer point is documented as unreachable at ECDH behind the
  `verify_ecdsa` trait contract (defense-in-depth only) and resume keeps its
  distinct at-ECDH stored-peer-key test; an explicit rationale states why no
  additional named failure test exists between the install admission stamp
  and the cache insert (every injectable site is already named, fixed-shape
  helpers are infallible, the pending insert is structurally impossible, and
  the stamp itself cannot fail after the same-invocation admission decide);
  install cache occupancy — exactly one slot per accepted handshake,
  persisting until horizon expiry or reboot — and its pre-authentication
  saturation-refusal exposure are disclosed, explicitly accepted, and pinned
  in precedence tests; the adversarial suite is renumbered one function per
  entry to exactly 28 named tests.
  The design adds a gateway-local bounded replay cache for authenticated
  handshake initiators: a `heapless::Deque` FIFO ring sized by the manager's
  generic capacity holds `(kind, peer_mac, initiator_nonce, seen_at)` triples
  (40 bytes per entry; about 5 KiB at the gateway default including the deque
  control block) keyed disjointly for Install and Resume. No live entry is
  ever evicted; TTL expiry beyond a 3,600-second horizon is the only removal
  mechanism, so adversarial authenticated churn beyond capacity can never
  resurrect any recorded pair inside its horizon. A cache full of unexpired
  entries refuses fresh initiators fail-closed before any cryptographic work
  via the new `ReplayCacheFull { peer }` error variant — an explicitly
  accepted availability trade-off whose refusal persists while churn
  continues (established Data sessions stay unaffected); exact-triple hits
  return the new `HandshakeReplay { peer }` variant with zero SE/HKDF calls.
  Cache inserts happen only at successful handshake-step completion (after
  pending commit), so downstream failures never poison a legitimate retry;
  install keeps its post-authentication admission stamp (an immediate retry
  returns `RateLimited`, success lands at the cooldown boundary), and the one
  declared resume ordering adjustment (pending/cooldown guards ahead of the
  request-MAC verify) is documented with its error-precedence consequences
  and pinned by tests. Cross-wrap expiry uses exact tail-plus-head
  arithmetic under a monotonic half-range clock contract. The document
  specifies the complete adversarial test plan: thirteen downstream-failure
  retry tests, named structurally-unreachable failure classes, and fifteen
  core adversarial tests (28 named tests in total) covering
  churn-without-resurrection, exact
  wrap-boundary expiry, forged no-mutation, error precedence, cached
  retransmission, reboot residual, and wire-constant/size-bound regressions.
  Design-only change: no code, dependency, wire-format, or existing
  public-API surface touched; the two error variants ship with the
  implementation task.

- Close the durable Resume-PSK zeroization gap in both install commit paths:
  the gateway `InstallConfirm` commit and the sensor `InstallCommitConfirmed`
  handler now carry the temporary PSK copy extracted from the staged pending
  state inside the zeroizing `ResumePskSecret` wrapper from extraction to its
  final destinations (committed session + host persist action), so every
  error path (rejected proof, key-expiry overflow, corrupted CommitConfirmed
  frame, saturated session table, failed recovery transition) wipes it
  instead of leaving a plain stack copy. The crate-private session
  constructor for active keys now receives the durable PSK **by borrow**:
  validation runs through the borrow, and the only plain materialization is
  the session-owned copy created after all validations succeed inside the
  zeroizing `Session`, so constructor error paths never own unwrapped PSK
  bytes. The idempotent retransmission path already moved its copy directly
  into the wrapper and is unchanged. No wire format, public API, or
  handshake-semantics change; regression suites beside the install module
  now cover success persistence on both roles, gateway-side commit insertion
  failure with retry recovery, rejected device-signature proof with retry,
  key-expiry overflow with retry on both roles, corrupted CommitConfirmed
  frame with retry, duplicate-Final retransmission PSK equality, and wrapper
  wipe-on-drop. Eight new tests raise the all-features suite total from 292
  to 300 passed; the validation-gate test-count floor is re-baselined
  accordingly (feature-scoped and doctest counts are unchanged).

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
