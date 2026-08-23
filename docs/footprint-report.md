# Sigil Footprint and Stack Measurement Report (2026-08-22)

Companion deliverable of this repository's validated performance-audit plan
(measurement-baseline phase). It records the measured byte footprint of every
pipeline-exchanged type per supported feature configuration, breaks down the
pending-handshake state per state variant, and documents the exact procedure a
host firmware uses to measure stack high-water on the real target. It follows
the crate-level footprint contract in `src/lib.rs`: the numbers below are
host-target planning inputs, never a substitute for measurement on the final
linked image.

Scope guard: this report changes no production code, asserts no new bounds,
and claims no hardware latency, energy, cycle, or stack numbers. Hardware
quantities remain UNCERTAIN until the host-firmware qualification phase
executes the procedure in section 7.

## 1. Measurement methodology

Three evidence tiers, each labeled wherever used below:

* Tier A (measured, checked-in tool): unit-test suite
  `src/core/pending/tests/footprint_report.rs`. Runs in the two-role test
  build (`--all-features`), prints `size_of` / `align_of` for the
  pipeline-exchanged types, the pending-state component primitives, and a
  nominal payload sum for every `PendingState` variant:

  ```bash
  cargo test --locked --all-features footprint_report -- --nocapture
  ```

* Tier B (measured, checked-in tool): example program
  `examples/footprint_report.rs`, run once per single-role configuration,
  printing the public types under that configuration:

  ```bash
  cargo run --locked --no-default-features --features sensor \
    --example footprint_report
  cargo run --locked --no-default-features --features gateway \
    --example footprint_report
  ```

* Tier C (derived, labeled): values computed arithmetically from measured
  tables (for example the gateway-only pending slot cost, back-solved from
  the measured manager totals). Derived rows are marked "derived".

Measurement conditions common to all tiers: host test target
(`x86_64` darwin), `size_of` semantics, `heapless = 0.8.0` pinned by
`Cargo.lock`, optimized nothing (sizes are layout facts, independent of
optimization level). Target layouts may differ; re-measure on the final
target image per section 7.

## 2. Bytes per type per configuration (current tree)

Measured 2026-08-22 on the working tree of branch
`fix/audit-sigil-performance` (Tier A for the two-role column and all pending
internals; Tier B for the mono-role columns; Tier C where marked).

| Type | `sensor` only | `gateway` only | `sensor,gateway` |
|---|---:|---:|---:|
| `SessionManager<2>` | 1240 | 1144 | 1400 |
| `SessionManager<128>` | 74 824 | 68 176 | 84 560 |
| `Session` | 216 | 232 | 264 |
| `PendingState` (enum total) | 280 | ~184 (derived) | 280 |
| `PendingHandshake` (slot total) | 312 | ~216 (derived) | 312 |
| `SigilEvent<200, 256>` | 288 | 288 | 288 |
| `SigilAction<256>` | 360 | 360 | 360 |

Feature dependence is real and explained by role-exclusive enum variants:
the two-role and sensor-only builds compile the six sensor variants including
the largest one (`InstallSensorFinalSent`, nominal payload 277 B), while a
gateway-only build compiles only the six gateway variants (largest:
`InstallGatewayAwaitConfirm`, exactly 176 B). The gateway-only enum therefore
shrinks; only its padding-rounded totals are derived rather than printed by a
tool, because the pending internals are crate-private.

## 3. Two-role breakdown: pending state components and variants

Component primitives (config-independent sizes, Tier A):

| Component | Size | Align | Notes |
|---|---:|---:|---|
| `CachedWire` (`Vec<u8, 128>`) | 136 | 8 | cached Final / CommitConfirmed frame; dominates most post-Final variants |
| `DirectionalMaterial` | 72 | 4 | 2 x (32-byte key + 4-byte prefix) halves |
| `ResumePskStash` (`SecretBytes<32>`) | 32 | 1 | zeroizing |
| `P256ContextStash` (`SecretBytes<32>`) | 32 | 1 | zeroizing, gateway renew only |
| `Nonce16Stash` (`SecretBytes<16>`) | 16 | 1 | zeroizing handshake nonces |
| `InstallGatewayStaged` (named struct) | 176 | 4 | exact padded size incl. fields |

Per-variant nominal payload sums (sum of field-type sizes, inter-field
padding excluded; the authoritative slot costs remain the `PendingState` /
`PendingHandshake` totals above):

| Variant (role gate) | Nominal payload |
|---|---:|
| `InstallSensorAwaitChallenge { sensor_nonce }` (sensor) | 16 |
| `InstallSensorFinalSent { keys, resume_psk, .. }` (sensor) | 277 |
| `RenewSensorAwaitChallenge` (sensor, unit) | 0 |
| `RenewSensorFinalSent { keys, .. }` (sensor) | 212 |
| `ResumeSensorAwaitChallenge { sensor_nonce }` (sensor) | 16 |
| `ResumeSensorFinalSent { keys, .. }` (sensor) | 212 |
| `InstallGatewayAwaitConfirm(InstallGatewayStaged)` (gateway) | 176 |
| `InstallGatewayCommitSent { cached }` (gateway) | 136 |
| `RenewGatewayAwaitConfirm { p256_context, .. }` (gateway) | 69 |
| `RenewGatewayCommitSent { cached }` (gateway) | 136 |
| `ResumeGatewayAwaitConfirm { keys, .. }` (gateway) | 76 |
| `ResumeGatewayCommitSent { cached }` (gateway) | 136 |

Read-out for right-sizing discussions: the enum total is driven by
`InstallSensorFinalSent`; inside the post-Final variants the cached-frame
buffer contributes 136 of the nominal bytes (128 capacity + 8-byte length
field), and the directional material 72. Any storage-shaping proposal should
quantify against these two levers first.

## 4. Discrepancy against previously recorded baselines

The bounds suites' doc comments (and the performance plan's baseline table)
record older host measurements: `PendingHandshake` 360, `SessionManager<2>`
1336 / 1432 / 1496, `SessionManager<128>` 80 968 / 86 608 / 90 704 across
sensor / gateway / two-role builds. The current tree measures consistently
smaller (section 2): every pending slot shrank by 48 B in sensor-bearing
builds and by 144 B in gateway-only builds relative to those records, and the
manager totals follow exactly (`N x` the per-slot delta). `Session`,
`SigilEvent`, and `SigilAction` still match their recorded values precisely.

Consequences, stated carefully:

* No approved regression bound is violated. All six `type_size_bounds`
  assertions pass unchanged; the margins simply widened.
* The stale numbers live in doc comments of suites owned by the owner-approval
  path. Refreshing them is an owner decision and was deliberately **not**
  done here; until then, this report is the authoritative record for the
  current tree.
* The pending suite's claim that the size is "identical in every session
  feature configuration" no longer describes the type (role-exclusive
  variants make the gateway-only enum smaller). Its guarding strategy remains
  sound: the assertion runs in the two-role build, which compiles the largest
  variant set, so growth in any configuration is still caught there.

## 5. Static-RAM budgeting examples (derived arithmetic)

Clearly labeled derivations from the measured tables, useful as planning
inputs only:

* Sensor default (`SessionManager<2>`, `sensor`): 1240 B for the whole
  manager value, i.e. roughly 0.6 KiB per enrolled peer slot plus fixed
  bookkeeping.
* Gateway default (`SessionManager<128>`, `gateway`): 68 176 B (~66.6 KiB);
  the two-role composition adds ~16 KiB (84 560 B) because both variant sets
  and both role bookkeepings exist simultaneously.
* Pipeline call stack planning input: one returned `SigilEvent<200,256>` +
  one `SigilAction<256>` = 648 B by value per processing call in any
  configuration (compiler lifetime reuse applies; actual peak stack comes
  only from section 7).

## 6. What these numbers are not

They are not flash sizes, not target RAM sizes, not stack usage, and not
timing. In particular: do not sum the capacities in section 3 and present the
sum as measured stack (explicit safeguard of the performance plan); peak
stack on `thumbv6m-none-eabi` is measurable only via section 7 on an
optimized target artifact of the final firmware image.

## 7. Host procedure: stack high-water on `thumbv6m-none-eabi` success paths

Executed entirely in the host firmware repository (sigil stays
consumer-independent). Two complementary methods; run both when possible.
None of the numbers below exist yet: they become available only after this
procedure runs on hardware, at which point the firmware repository records
them.

### 7.1 Static worst case from the final linked ELF

Tooling (exact names):

* `rustup component add rust-src` and a **nightly** toolchain for the emit
  flag: rebuild the firmware with
  `RUSTFLAGS="-Z emit-stack-sizes -C debuginfo=2"` (LLVM stack-size section,
  `.stack_sizes`). A plain `cargo build --release` does **not** emit it; the
  flag-bearing invocation is part of the procedure, not of normal builds.
* `cargo install stack-sizes`, then `stack-sizes path/to/firmware.elf` for a
  per-symbol stack-size listing from that section.
* `cargo install cargo-call-stack`, then
  `cargo call-stack --bin <fw> --target thumbv6m-none-eabi -- release`:
  computes the **worst-case** stack depth over the static call graph of the
  final ELF (Cortex-M oriented; flags indirect calls and interrupts). This is
  the primary static number to record.
* For C dependencies compiled into the firmware, GCC-style
  `arm-none-eabi-gcc -fstack-usage` produces `.su` files readable per
  function; rustc itself has no `.su` mode, hence the Rust-native tools
  above.

Record per success path (see 7.3) the static worst case of its entry function.

### 7.2 Runtime high-water fill

1. At boot, before any scheduling, fill the entire stack region (and, if the
   RTOS provides per-task stacks, each task stack) with a known pattern such
   as `0xA5`.
2. Run the success path under production-like radio timing, repeated
   (suggest >= 100 iterations, plus deliberate radio-loss retries to exercise
   retransmission branches).
3. Scan the region from the far end for the deepest overwritten address;
   high-water = stack_base - deepest_written. On FreeRTOS, cross-check with
   `uxTaskGetStackHighWaterMark()` for the task hosting the sigil calls; an
   MPU watermark task is an equivalent alternative.
4. Record max observed high-water per path and enforce a firmware-owned limit
   with headroom (commonly 25-50% margin, firmware policy).

### 7.3 Paths to instrument

Generic definitions (firmware maps them onto its own tasks/timers):

| Path | Success sequence through the library |
|---|---|
| Data | `encrypt_data` TX; `process_incoming_packet` RX returning `SigilEvent::Data` |
| Event | `send_event` / event ingress + `ack_event` egress |
| Install | full four-message exchange, sensor side and gateway side separately, including `PersistPeerStaticKey` handling and cached retransmission after a dropped commit frame |
| Renew | full renew exchange from `start_renew` through `RenewCommitConfirmed` |
| Resume | full resume exchange from `start_resume` through `ResumeCommitConfirmed` |

Acceptance for the firmware-side qualification: both a static worst case
(7.1) and an observed high-water (7.2) recorded per path, with the sensing
IRQ deadlines verified concurrently (that latency/energy work belongs to the
same host-firmware phase; sigil exposes no clock and cannot measure it).

## 8. Verification gates executed for this report

All green on the same working tree (one pass each):

```text
cargo fmt --all -- --check                                          clean
cargo clippy --locked --all-targets --all-features -- -D warnings   clean
cargo test --locked --all-features type_size_bounds                 6 passed
cargo build --locked --release --target thumbv6m-none-eabi
  --no-default-features --features sensor                           Finished
cargo test --locked --all-features                                  292 passed (+2 doctests)
cargo test --locked --no-default-features --features sensor         71 passed
cargo test --locked --no-default-features --features gateway        72 passed (+2 doctests)
bash scripts/test-feature-matrix.sh                                 OK
cargo check --locked --release --target armv7-unknown-linux-gnueabihf
  --no-default-features --features gateway                          Finished
```
