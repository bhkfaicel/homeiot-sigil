# sigil

`no_std` Rust library for secure device communication over LoRa: messaging, encryption, install/renew handshakes, key derivation, and events.

---

## What is a Sigil?

**Sigil** (from Latin _sigillum_, “seal”) traditionally denotes a symbol or mark that represents an identity, intent, or authority—like a seal on a document. In this project, **sigil** is the “seal” of your device stack: the layer that defines how devices identify, authenticate, and exchange encrypted messages over LoRa.

---

## Features

- **`com`** — Communication over LoRa: read/write of encrypted messages, header validation, key callbacks.
- **`models`** — Shared message and protocol models (`MessageSchema`, events, handshake types).

---

## Handshake flows

### Install (first pairing)

Clear-text 3-message exchange with **ECIES + ECDSA** for identity proof:

```
HandshakeRequest → HandshakeChallenge (ECIES 194B) → HandshakeConfirm (ECDSA 64B)
→ session_key = HKDF(ECDH éphémère, sensor_nonce ‖ gateway_nonce)
```

**Sensor:** `com::handshake::install::sensor::install_session()` (alias: `initiate_handshake`)  
**Gateway:** `com::handshake::install::gateway::handle_install_request()` (alias: `handle_handshake_request`)

### Renew (session key rotation)

Encrypted 3-message exchange on the **existing session key** — **ECDH only** (no ECDSA, no ECIES):

```
KeyRenewRequest → KeyRenewChallenge → KeyRenewAck
→ session_key_new = HKDF(ECDH éphémère, sensor_nonce ‖ gateway_nonce)
```

**Sensor:** `com::handshake::renew::sensor::renew_session()`  
**Gateway:** `com::handshake::renew::gateway::handle_renew_request()`

Trigger renew when `ValidatedKey::should_renew()` returns true (~75% of key lifetime elapsed).

See `diagramme/install.mermaid` and `diagramme/renew.mermaid` for sequence diagrams.

---

## Usage

Add to your `Cargo.toml` (adjust registry and version as needed):

```toml
[dependencies]
sigil = { version = "0.3", registry = "forgejo", default-features = false, features = ["com"] }
```

Read and decrypt a message with `Sigil::read`:

```rust
use sigil::Sigil;

let msg = Sigil::read(
    &mut lora,
    &mut delay,
    |header| { /* validate header */ true },
    |msg_type, source| { /* return Some(session_key) or None */ None },
    timestamp,
)?;
```

Renew example (sensor, already paired):

```rust
use sigil::com::handshake::renew::sensor::renew_session;

let session = renew_session(
    &mut lora,
    &mut delay,
    sensor_mac,
    battery_level,
    gateway_mac,
    &current_session_key,
    &chacha_nonce,
    new_sensor_nonce,
    |eph_pubkey| { /* ATECC608 ECDH → shared_secret */ Ok(shared_secret) },
    timestamp,
)?;
// session.keys.key is the new session key
```

---

## Project structure

```
sigil/
├── diagramme/           # Mermaid sequence diagrams (install, renew)
├── src/
│   ├── com/
│   │   ├── handshake/
│   │   │   ├── primitives/     # Shared crypto helpers (HKDF inputs, payloads)
│   │   │   ├── lora_helpers/   # send_encrypted, try_receive_encrypted, …
│   │   │   ├── install_core/   # ECIES + ECDSA (install only)
│   │   │   ├── renew_core/     # Lightweight renew (ECDH only)
│   │   │   ├── install/        # install_session, handle_install_request
│   │   │   └── renew/          # renew_session, handle_renew_request
│   │   ├── keys/               # KeyManager, ValidatedKey
│   │   ├── event/
│   │   └── mod.rs              # Sigil::read()
│   ├── models/common/
│   └── crypto/                 # ChaCha20-Poly1305
├── scripts/test.sh
└── Cargo.toml
```

---

## Status

Active development. Install API is stable; renew API was simplified in the unreleased refactor (see CHANGELOG).

---

## License

Personal Use Only — Non-Commercial. See [LICENSE](LICENSE) for full terms and disclaimers.
