# Implementation Plan: Non-Blocking Session Core

**Branch**: `001-nonblocking-session-core` | **Date**: 2026-08-04 | **Spec**: [spec.md](./spec.md)  
**Input**: Feature specification from `/specs/001-nonblocking-session-core/spec.md`

**Note**: This template is filled in by the `/speckit-plan` command. See `.specify/templates/plan-template.md` for the execution workflow.

## Summary

Replace the LoRa-coupled, blocking handshake stack with a **hardware-agnostic, non-blocking, `no_alloc` session core**: `SessionManager<N>`, host traits (`SecureElement` / `RandomSource`), a single `process_incoming_packet` ingress, and three host-driven phases — **install** (identity + SE), **sensor-initiated renew** (pure-software eph↔eph), **fast resume** (static↔static via SE ECDH only). Breaking wire/API change (B+) but **keep `[u8; 17]` MAC**. Directional `tx_counter` / `rx_counter` for AEAD nonces. Explicit handshake `cancel`; no auto-renew on expiry.

## Technical Context

**Language/Version**: Rust edition 2024 (`no_std`, no heap)  
**Primary Dependencies**: `heapless`, `chacha20poly1305` (heapless), `hkdf`, `sha2`, `bincode` (no_std); add `x25519-dalek` (ECDH, no_std) + `zeroize` for software ephemeral renew; **remove** `lora` and `embedded-hal` from the library core  
**Storage**: N/A in-library (host owns NVRAM for static keys); RAM-only `Session` / pending handshake state  
**Testing**: `cargo test` / `scripts/test.sh`; deterministic mocks for SE + RNG (`embedded-hal-mock` only if still needed by optional adapters — prefer pure Rust mocks in-tree)  
**Target Platform**: ARM Cortex-M0+ (SAMD21) and above; host firmware supplies radio + ATECC608x  
**Project Type**: Embedded cryptography / session protocol library  
**Performance Goals**: Non-blocking public APIs (0 host sleep); renew crypto payload ~50 B; resume ~60 B class; install remains ~194 B ECIES-class challenge  
**Constraints**: No dynamic allocation; no board/radio crates in lib; no XChaCha20; no SE private key extraction; English docs/comments; major version bump (breaking)  
**Scale/Scope**: `SessionManager<1>` (sensor) / `SessionManager<100>` (gateway); three protocol phases + encrypted data path

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

Project constitution file is still a Speckit placeholder; gates below are derived from `ARCHITECTURE_DEV.md`, clarified `spec.md`, and repository critical guidance (`CLAUDE.md`).

| Gate | Rule | Status |
|------|------|--------|
| G1 | Library-first, self-contained, independently testable with mocks | PASS |
| G2 | No hardware/radio dependencies in core (`lora`, board HALs out) | PASS (plan removes them) |
| G3 | `no_std` + no heap (`heapless` / fixed arrays only) | PASS |
| G4 | Non-blocking APIs; host owns time/I/O | PASS |
| G5 | Tests required for new/changed behavior; deterministic mocks | PASS |
| G6 | English comments/docs; update CLAUDE/README on API change | PASS (implementation phase) |
| G7 | Breaking changes explicit (major); no silent dual-stack | PASS (B+) |

**Post-design re-check**: PASS — contracts and data-model stay within G1–G7; SE used only via traits; renew ECDH is software; resume ECDH uses trait (no key export).

## Project Structure

### Documentation (this feature)

```text
specs/001-nonblocking-session-core/
├── plan.md              # This file
├── research.md          # Phase 0
├── data-model.md        # Phase 1
├── quickstart.md        # Phase 1
├── contracts/           # Phase 1
│   ├── host-traits.md
│   ├── session-api.md
│   └── wire-messages.md
└── tasks.md             # Phase 2 (/speckit-tasks — not created here)
```

### Source Code (repository root)

```text
src/
├── lib.rs
├── core/                      # NEW: session core (replaces blocking com/handshake driver role)
│   ├── mod.rs
│   ├── session.rs             # Session, counters, nonce helpers
│   ├── manager.rs             # SessionManager<N>
│   ├── traits.rs              # SecureElement, RandomSource
│   ├── error.rs               # SigilError
│   ├── event.rs               # SigilEvent / SigilAction
│   ├── pipeline.rs            # process_incoming_packet
│   ├── aead.rs                # ChaCha20-Poly1305 + directional counters
│   ├── ecdh_soft.rs           # X25519 ephemeral ECDH + zeroize (renew)
│   ├── derive.rs              # HKDF session key derivation
│   ├── pending.rs             # In-progress handshake state + cancel
│   ├── install/               # Non-blocking install steps
│   ├── renew/                 # Sensor-initiated renew steps
│   └── resume/                # Static↔static fast resume steps
├── models/                    # Keep / adapt MessageSchema (17-byte MAC)
│   └── common/
├── crypto/                    # Thin wrap or migrate into core::aead
└── com/                       # LEGACY: remove LoRa I/O loops; optional re-exports during migration cut

tests/                         # Prefer module tests under src/**/tests + integration under tests/
└── (integration as needed)
```

**Structure Decision**: Single-crate library. Introduce `src/core/` as the non-blocking session engine. Retire `com/handshake/*` blocking LoRa helpers and `lora` dependency from `Cargo.toml`. Keep `models` for on-wire framing with `[u8; 17]` MACs. Major version bump when landing.

## Complexity Tracking

> No constitution gate violations requiring justification. Intentional complexity vs current tree:

| Item | Why Needed | Simpler Alternative Rejected Because |
|------|------------|-------------------------------------|
| Separate `tx_counter` / `rx_counter` | Bidirectional AEAD nonce safety | Single counter (ARCHITECTURE sketch) risks nonce reuse when both sides encrypt |
| Software X25519 for renew | Eph↔eph without ATECC; fast on M0+ | Soft P-256 was too slow; SE-only ECDH would force ATECC on every renew |
| Pending handshake + cancel API | Non-blocking host scheduler | Auto-timeout clear races with late packets |
| Remove `lora` from lib | FR-001 / G2 | Keep radio in lib would violate hardware-agnostic rule |
