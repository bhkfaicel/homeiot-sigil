# Research: Non-Blocking Session Core

**Feature**: `001-nonblocking-session-core`  
**Date**: 2026-08-04

## R1 — Remove `lora` / `embedded-hal` from library core

- **Decision**: Drop `lora` and `embedded-hal` from `[dependencies]`. Host passes raw `&[u8]` in and applies `SigilAction::Transmit` out.
- **Rationale**: FR-001 / ARCHITECTURE_DEV — sigil is pure protocol logic; radio ownership caused blocking loops (`delay_ms`) incompatible with FR-003.
- **Alternatives considered**: Optional `lora` feature adapter in-tree — rejected for v1 of this redesign (keeps HAL surface area); can live in firmware or a future `sigil-lora` helper crate.

## R2 — Software ephemeral ECDH for renew (`x25519-dalek` + `zeroize`)

- **Decision**: Implement renew eph↔eph with **X25519** (`x25519-dalek`, `static_secrets`, `no_std`) and `zeroize` on ephemeral secrets after HKDF. Private scalar entropy must be **exactly 32 bytes** from `RandomSource`, then RFC 7748 clamp.
- **Rationale**: FR-008 forbids SE identity ops on renew; soft P-256 ECDH was too slow on SAMD21 (perf P1). X25519 is far cheaper while remaining `no_std`-friendly. Install/resume identity keys stay P-256 on the SecureElement.
- **Alternatives considered**: ATECC ephemeral slots — rejected (power, latency, SE contention); soft P-256 (`p256`) — rejected for renew cost on Cortex-M0+; `k256` — wrong curve for identity (install/resume stay P-256 on SE).

## R3 — Fast resume static↔static vs “no ATECC”

- **Decision**: Resume performs **static↔static ECDH via `SecureElement::ecdh(peer_static_pubkey)`**. No ephemeral keys, no ECDSA on resume path. Do **not** soft-copy SE private keys into RAM.
- **Rationale**: FR-009 + FR-012. ARCHITECTURE_DEV’s “no ATECC if static keys known” would imply exporting the static private key — forbidden. Interpret as “no ECDSA / no ephemeral / minimal airtime”; ECDH still through SE trait.
- **Alternatives considered**: Soft static private in NVRAM — rejected (FR-012 / security); eph↔eph+ECDSA resume — rejected in clarify (size/energy).

## R4 — AEAD nonce: prefix + directional counters

- **Decision**: Nonce = `prefix[4] ‖ counter_u64_be[8]`. One session `nonce_prefix` from RandomSource at key establishment. Separate `tx_counter` / `rx_counter`. On TX use local `tx_counter` then increment; on RX verify peer counter against `rx_counter` (reject replay / non-monotonic), then advance.
- **Rationale**: Clarify Q2 option B; shared prefix alone does not separate directions.
- **Alternatives considered**: Single shared counter — rejected; dual prefixes — similar complexity, not chosen.

## R5 — Wire / MAC posture (B+)

- **Decision**: Breaking message layouts and handshake crypto OK; **keep `[u8; 17]` peer MAC**. No dual-stack parser.
- **Rationale**: Clarify Q1 B+.
- **Alternatives considered**: 6-byte MAC from ARCHITECTURE_DEV — rejected by product; dual-stack — out of scope (FR-022).

## R6 — Pending handshake lifecycle

- **Decision**: Store `PendingHandshake` per peer inside manager (or side map with capacity ≤ N). Timeout hints are advisory. Clear only on success, `cancel`, or host-started replace.
- **Rationale**: Clarify Q4 option B.
- **Alternatives considered**: Auto-clear on next API call after timeout — races; host-only pending — duplicates protocol knowledge outside lib.

## R7 — Renew initiator

- **Decision**: Sensor-only initiate; gateway respond/accept only.
- **Rationale**: Clarify Q5 option A.
- **Alternatives considered**: Either-side initiate — more states/tests; gateway push — poor fit for sleepy sensors.

## R8 — Install crypto shape

- **Decision**: Keep install as the heavy identity path: SE sign/verify + SE or host ECDH as needed for challenge confidentiality; produce peer static pubkey for host NVRAM + session key + counters reset + nonce prefix.
- **Rationale**: FR-007; airtime SF7 is host policy.
- **Alternatives considered**: Make install as light as renew — would lose factory identity binding.

## R9 — Migration / versioning

- **Decision**: Major semver bump (e.g. 0.5.x → 1.0.0-rc or 0.6 breaking per repo policy). Delete blocking handshake entry points rather than feature-flag dual APIs in core.
- **Rationale**: Spec assumes breaking redesign; FR-022 no dual-stack.
- **Alternatives considered**: Soft deprecation behind `legacy-lora` feature — deferred; increases maintenance.

## R10 — Testing strategy

- **Decision**: In-tree `MockSecureElement` / `MockRandom` with canned ECDH secrets and sequential bytes; pairwise install/renew/resume vector tests; pipeline tests for expiry/replay/unknown peer; assert no delay trait in core API.
- **Rationale**: FR-016, SC-004–SC-007.
- **Alternatives considered**: Hardware-in-loop only — rejected as gate for merge.

## Resolved clarifications

All Technical Context items have concrete choices above; no remaining NEEDS CLARIFICATION blockers for `/speckit-tasks`.
