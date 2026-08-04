---
description: "Task list for non-blocking session core implementation"
---

# Tasks: Non-Blocking Session Core

**Input**: Design documents from `/specs/001-nonblocking-session-core/`  
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/, quickstart.md

**Tests**: Included — FR-016 / SC-007 require deterministic mock-based unit tests for new behavior.

**Organization**: Tasks grouped by user story for independent implementation and testing.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies on incomplete tasks)
- **[Story]**: User story label (`[US1]`…`[US5]`)
- Include exact file paths in descriptions

## Path Conventions

- Library root: `src/core/` (new), `src/models/`, `Cargo.toml`
- Module tests: `src/core/**/tests/` or `src/core/tests/`
- Feature docs: `specs/001-nonblocking-session-core/`

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Scaffold `src/core/` and adjust crate dependencies for hardware-agnostic builds

- [ ] T001 Create `src/core/` module tree (`mod.rs`, `session.rs`, `manager.rs`, `traits.rs`, `error.rs`, `event.rs`, `pipeline.rs`, `aead.rs`, `ecdh_soft.rs`, `derive.rs`, `pending.rs`, `install/mod.rs`, `renew/mod.rs`, `resume/mod.rs`) and wire `pub mod core` in `src/lib.rs`
- [ ] T002 Update `Cargo.toml`: add `p256` (no_std ECDH) and `zeroize`; remove `lora` and `embedded-hal` from library `[dependencies]`; bump version for breaking change; refresh `Cargo.lock`
- [ ] T003 [P] Add English module-level docs in `src/core/mod.rs` describing non-blocking host-owned I/O and the three protocol phases

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Shared types, traits, AEAD/counters, manager, mocks — MUST complete before user stories

**⚠️ CRITICAL**: No user story work begins until this phase is complete

- [ ] T004 Implement `SigilError` variants in `src/core/error.rs` (`UnknownSession`, `SessionExpired`, `Replay`, `CounterExhausted`, `VerificationFailed`, `CapacityExceeded`, `ParseError`, `NoPending`, `EcdhFailed`, `RandomFailed`, …) with English docs
- [ ] T005 [P] Implement `SecureElement` and `RandomSource` traits in `src/core/traits.rs` per `contracts/host-traits.md`
- [ ] T006 [P] Implement `SigilEvent` and `SigilAction` enums in `src/core/event.rs` per `contracts/session-api.md` using `heapless` buffers (no `alloc`)
- [ ] T007 Implement `Session` (peer `[u8; 17]`, static pubkey, optional session key + nonce prefix, `tx_counter`/`rx_counter`, `key_expire_at`) in `src/core/session.rs` per `data-model.md`
- [ ] T008 Implement `SessionManager<N>` with `heapless::FnvIndexMap` insert/get/get_mut/remove in `src/core/manager.rs`
- [ ] T009 Implement `PendingHandshake` storage + `cancel(peer)` zeroizing ephemeral secrets in `src/core/pending.rs`
- [ ] T010 [P] Implement HKDF session-key derivation helpers in `src/core/derive.rs`
- [ ] T011 Implement directional-counter AEAD nonce helpers + encrypt/decrypt wrappers in `src/core/aead.rs` (ChaCha20-Poly1305, 12-byte nonce = prefix‖counter, no XChaCha20)
- [ ] T012 [P] Implement software ephemeral P-256 ECDH + `zeroize` in `src/core/ecdh_soft.rs` for renew
- [ ] T013 [P] Implement `MockSecureElement` and `MockRandom` in `src/core/tests/mocks.rs` (deterministic ECDH/sign/random)
- [ ] T014 Add foundational unit tests for session counter/nonce rules and manager insert/remove in `src/core/tests/foundation.rs`
- [ ] T015 Adapt or freeze legacy `src/com/` LoRa-blocking entry points (compile feature gate or remove exports) so default build does not require `lora` — update `src/com/mod.rs` / `src/lib.rs` accordingly

**Checkpoint**: Foundation ready — user stories can proceed

---

## Phase 3: User Story 1 - Non-Blocking Packet Processing (Priority: P1) 🎯 MVP

**Goal**: Single non-blocking ingress decrypts data, advances `rx_counter`, returns typed errors (unknown peer / expired) without auto-renew or sleep

**Independent Test**: Feed canned encrypted/clear frames with mocks; assert `Data` event, `UnknownSession`, `SessionExpired`; confirm no delay APIs invoked

### Tests for User Story 1

- [ ] T016 [P] [US1] Write failing tests for `process_incoming_packet` data/unknown/expired paths in `src/core/tests/pipeline_data.rs`
- [ ] T017 [P] [US1] Write failing tests for replay / non-monotonic `rx_counter` rejection in `src/core/tests/aead_counters.rs`

### Implementation for User Story 1

- [ ] T018 [US1] Implement frame parse + session lookup + expiry check skeleton in `src/core/pipeline.rs`
- [ ] T019 [US1] Implement `encrypt_data` / decrypt path using `src/core/aead.rs` and advance `tx_counter`/`rx_counter` from `SessionManager` in `src/core/manager.rs` / `src/core/pipeline.rs`
- [ ] T020 [US1] Return `SigilError::SessionExpired` without starting renew/install in `src/core/pipeline.rs`
- [ ] T021 [US1] Make T016–T017 pass; ensure public pipeline APIs take `&mut impl SecureElement` / time `now` without blocking

**Checkpoint**: US1 MVP — encrypted data path works with mocks

---

## Phase 4: User Story 2 - First-Time Installation Pairing (Priority: P1)

**Goal**: Host-driven non-blocking install steps produce matching session keys + peer static pubkey; waiting returns timeout hint; cancel retains pending until explicit abort

**Independent Test**: Simulated install with `MockSecureElement`/`MockRandom`; both peers derive same key; invalid signature fails closed

### Tests for User Story 2

- [ ] T022 [P] [US2] Write failing pairwise install success + verify-fail tests in `src/core/tests/install_e2e.rs`
- [ ] T023 [P] [US2] Write failing pending-timeout-does-not-auto-clear + `cancel` tests in `src/core/tests/pending_cancel.rs`

### Implementation for User Story 2

- [ ] T024 [P] [US2] Define install wire helpers / message builders in `src/core/install/wire.rs` (keep `[u8; 17]` MAC) aligned with `contracts/wire-messages.md`
- [ ] T025 [US2] Implement sensor `start_install` / continue steps returning `SigilAction::{Transmit,WaitingForResponse}` in `src/core/install/sensor.rs`
- [ ] T026 [US2] Implement gateway handle-install steps + SE verify/sign/ECDH as required in `src/core/install/gateway.rs`
- [ ] T027 [US2] On install success, set session key, nonce prefix, counters=0, and emit `PersistStaticKey` action from `src/core/install/mod.rs`
- [ ] T028 [US2] Route install message types through `src/core/pipeline.rs` into install handlers
- [ ] T029 [US2] Make T022–T023 pass

**Checkpoint**: Install works end-to-end with mocks; cancel semantics verified

---

## Phase 5: User Story 3 - Lightweight Session Renew (Priority: P1)

**Goal**: Sensor-initiated renew via software eph↔eph; gateway responds only; new key + both counters reset; no SE identity ops

**Independent Test**: Existing session → renew with mocks; matching keys; counters 0; assert MockSecureElement sign/ECDH not required for renew path

### Tests for User Story 3

- [ ] T030 [P] [US3] Write failing sensor-initiated renew pairwise tests in `src/core/tests/renew_e2e.rs`
- [ ] T031 [P] [US3] Write failing test that gateway cannot `start_renew` (API absent or error) in `src/core/tests/renew_initiator.rs`

### Implementation for User Story 3

- [ ] T032 [P] [US3] Define renew wire builders (eph pubs ~50 B class crypto material) in `src/core/renew/wire.rs`
- [ ] T033 [US3] Implement `start_renew_sensor` using `ecdh_soft` + `RandomSource` and encrypt under old session key in `src/core/renew/sensor.rs`
- [ ] T034 [US3] Implement gateway renew accept/respond only in `src/core/renew/gateway.rs` (no gateway initiate API)
- [ ] T035 [US3] On renew success, rotate session key/prefix, reset `tx_counter`/`rx_counter`, zeroize eph secrets in `src/core/renew/mod.rs`
- [ ] T036 [US3] Route renew types in `src/core/pipeline.rs`; reject AEAD-auth failures without changing old key
- [ ] T037 [US3] Make T030–T031 pass

**Checkpoint**: Renew path complete; sensor-only initiate enforced

---

## Phase 6: User Story 4 - Fast Resume After Reboot (Priority: P2)

**Goal**: Static↔static resume via `SecureElement::ecdh` only (no eph, no ECDSA); minimal airtime; counters reset

**Independent Test**: Sessions with static pubs only → resume; matching keys; no ephemeral keygen/ECDSA calls on mock

### Tests for User Story 4

- [ ] T038 [P] [US4] Write failing fast-resume pairwise tests (success + missing static key) in `src/core/tests/resume_e2e.rs`
- [ ] T039 [P] [US4] Write failing assertion tests that resume path does not call sign_ecdsa / soft eph ECDH in `src/core/tests/resume_constraints.rs`

### Implementation for User Story 4

- [ ] T040 [P] [US4] Define resume wire builders (~60 B class, no eph/ECDSA fields) in `src/core/resume/wire.rs`
- [ ] T041 [US4] Implement sensor/gateway resume steps using `SecureElement::ecdh(peer_static)` in `src/core/resume/sensor.rs` and `src/core/resume/gateway.rs`
- [ ] T042 [US4] On success set session key/prefix, reset both counters; fail closed on missing static material in `src/core/resume/mod.rs`
- [ ] T043 [US4] Route resume types in `src/core/pipeline.rs`
- [ ] T044 [US4] Make T038–T039 pass

**Checkpoint**: Fast resume works under power/size constraints

---

## Phase 7: User Story 5 - Multi-Peer Gateway Session Table (Priority: P2)

**Goal**: Capacity-N manager (gateway 100 / sensor 1); full map errors; delete clears RAM only

**Independent Test**: Fill `SessionManager<N>`, lookup O(1), reject insert when full, delete leaves conceptual NVRAM untouched (no wipe API)

### Tests for User Story 5

- [ ] T045 [P] [US5] Write failing capacity/full-insert/delete tests in `src/core/tests/manager_capacity.rs`

### Implementation for User Story 5

- [ ] T046 [US5] Enforce `CapacityExceeded` on insert when full and document `SessionManager<1>` vs `<100>` defaults in `src/core/manager.rs`
- [ ] T047 [US5] Ensure `remove_session` only drops RAM `Session`/`PendingHandshake` (no NVRAM hooks) in `src/core/manager.rs`
- [ ] T048 [US5] Make T045 pass; add compile-time example or doc test noting gateway N=100 memory is fixed/no heap in `src/core/manager.rs`

**Checkpoint**: Multi-peer table behavior meets FR-014/FR-015

---

## Phase 8: Polish & Cross-Cutting Concerns

**Purpose**: Docs, legacy cleanup, CI sanity

- [ ] T049 [P] Update `CLAUDE.md` and `README.md` for non-blocking core, trait integration, and removal of LoRa-from-lib
- [ ] T050 [P] Update `CHANGELOG.md` with breaking changes (B+, counters, resume static↔static, sensor-only renew)
- [ ] T051 Remove or archive obsolete blocking handshake modules under `src/com/handshake/` / `src/com/init/` leftovers that still pull radio I/O; keep only what models need
- [ ] T052 Align `src/models/common/mod.rs` message types with `contracts/wire-messages.md` (install/renew/resume names) while keeping `[u8; 17]` MAC
- [ ] T053 Run `bash scripts/test.sh` and `cargo clippy -- -D warnings`; fix failures
- [ ] T054 Validate `specs/001-nonblocking-session-core/quickstart.md` against public APIs (adjust quickstart if signatures drifted)
- [ ] T055 [P] Refresh `diagramme/*.mermaid` for install/renew/resume to match non-blocking + clarified crypto (English)

---

## Dependencies & Execution Order

### Phase Dependencies

- **Phase 1 (Setup)**: Start immediately
- **Phase 2 (Foundational)**: Depends on Setup — **blocks all stories**
- **Phase 3 (US1)**: After Foundational — **MVP**
- **Phase 4 (US2)**: After Foundational; uses pipeline from US1 (sequential after US1 recommended)
- **Phase 5 (US3)**: After US1 (needs AEAD session); ideally after US2 for shared pending patterns
- **Phase 6 (US4)**: After Foundational + US1; independent of renew crypto but shares pending/pipeline
- **Phase 7 (US5)**: After T008 manager exists; can parallelize with later stories once Foundational done
- **Phase 8 (Polish)**: After desired stories complete

### User Story Dependencies

| Story | Depends on | Notes |
|-------|------------|-------|
| US1 | Phase 2 | MVP data path |
| US2 | Phase 2, US1 pipeline skeleton | Install |
| US3 | Phase 2, US1 AEAD | Sensor renew |
| US4 | Phase 2, US1 | Fast resume |
| US5 | Phase 2 manager | Capacity edge cases |

### Parallel Opportunities

- T005/T006/T010/T012/T013 in Foundational after T004
- T016/T017 tests in parallel; T022/T023; T030/T031; T038/T039; T045
- After Foundational: US5 capacity work can proceed beside US1 tests
- US3 and US4 can proceed in parallel after US1 if staffed (different files under `renew/` vs `resume/`)

---

## Parallel Example: User Story 1

```bash
# Tests in parallel:
# T016 src/core/tests/pipeline_data.rs
# T017 src/core/tests/aead_counters.rs

# Then implementation sequentially:
# T018 → T019 → T020 → T021
```

## Parallel Example: User Stories 3 & 4 (after US1)

```bash
# Developer A: renew wire + sensor/gateway (T032–T037)
# Developer B: resume wire + sensor/gateway (T040–T044)
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Phase 1 Setup  
2. Phase 2 Foundational  
3. Phase 3 US1  
4. **STOP** — validate encrypted ingress/egress with mocks  

### Incremental Delivery

1. Setup + Foundational  
2. US1 → MVP demo  
3. US2 Install  
4. US3 Renew  
5. US4 Resume  
6. US5 Capacity polish  
7. Phase 8 docs/CI  

### Suggested MVP Scope

**Phases 1–3 (T001–T021)** — non-blocking data plane only.

---

## Notes

- All tasks use checklist format with IDs and file paths  
- Tests fail first where marked  
- English comments/docs only  
- Commit after each task or logical group  
- Do not reintroduce `lora` into core dependencies  
