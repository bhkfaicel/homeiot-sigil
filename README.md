# sigil

`no_std` Rust library for secure device communication over LoRa: messaging, encryption, init flows, key derivation, and events.

---

## What is a Sigil?

**Sigil** (from Latin *sigillum*, “seal”) traditionally denotes a symbol or mark that represents an identity, intent, or authority—like a seal on a document. In this project, **sigil** is the “seal” of your device stack: the layer that defines how devices identify, authenticate, and exchange encrypted messages over LoRa. The crate provides the communication primitives (init, keys, crypto, events) so that each device can act as a distinct, recognizable identity in the network—hence the name.

---

## Features

- **`com`** — Communication over LoRa: read/write of encrypted messages, header validation, key callbacks.
- **`models`** — Shared message and protocol models (e.g. `MessageSchema`, events, init request/response).

Build with default features or enable only what you need.

---

## Usage

Add to your `Cargo.toml` (adjust registry and version as needed):

```toml
[dependencies]
sigil = { version = "0.1", registry = "forgejo", default-features = false, features = ["com"] }
```

Example: read and decrypt a message with `Sigil::read`, using your own header validation and key lookup:

```rust
use sigil::Sigil;

// With a LoRa controller, delay, and callbacks for header validation and key lookup:
let msg = Sigil::read(
    &mut lora,
    &mut delay,
    |header| { /* validate header */ true },
    |msg_type, source| { /* return Some(key) or None */ None },
    timestamp,
)?;
```

See the public API docs and `com::init`, `com::keys`, and `crypto` modules for encryption, key derivation (e.g. HKDF via `KeyManager`), and init flows.

---

## Project structure

```
sigil/
├── src/
│   ├── lib.rs
│   ├── com/           # Communication over LoRa
│   │   ├── init/      # Init flows (gateway, sensor)
│   │   ├── keys/      # Key management (e.g. KeyManager, HKDF)
│   │   ├── event/     # Event handling
│   │   └── error/
│   ├── models/        # Shared message and protocol models
│   │   └── common/
│   └── crypto/        # ChaCha20-Poly1305 encrypt/decrypt
├── scripts/
│   └── test.sh        # Runs cargo test
├── Cargo.toml
├── LICENSE
└── README.md
```

---

## Status

Early development. API may change. Suitable for evaluation and integration in embedded LoRa stacks.

---

## License

Personal Use Only — Non-Commercial. See [LICENSE](LICENSE) for full terms and disclaimers.
