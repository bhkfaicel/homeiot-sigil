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

Clear-text 3-message exchange with **ephemeral-to-ephemeral ECDH + ECDSA** for identity proof:

```
HandshakeRequest → HandshakeChallenge {gw_eph_pubkey, …} → HandshakeConfirm {sig_gateway_nonce, sensor_eph_pubkey}
→ session_key = HKDF(ECDH(eph↔eph), sensor_nonce ‖ gateway_nonce)
```

**Sensor:** `install_session()` — callback `ecdh_ephemeral_with_peer(gw_eph_pubkey) → (sensor_eph_pubkey, shared_secret)`  
**Gateway:** `handle_install_request()` — callbacks `generate_gateway_ephemeral() → gw_eph_pubkey` and `ecdh_with_sensor_ephemeral(sensor_eph_pubkey) → shared_secret` (plus ECDSA verify/sign callbacks)

### Renew (session key rotation)

Encrypted 3-message exchange on the **existing session key** — **ephemeral-to-ephemeral ECDH** (no ECDSA, no ECIES):

```
KeyRenewRequest → KeyRenewChallenge {gw_eph_pubkey} → KeyRenewAck {sensor_eph_pubkey}
→ session_key_new = HKDF(ECDH(eph↔eph), sensor_nonce ‖ gateway_nonce)
```

**Sensor:** `com::handshake::renew::sensor::renew_session()` — callback `ecdh_ephemeral_with_peer(gw_eph_pubkey) → (sensor_eph_pubkey, shared_secret)`  
**Gateway:** `com::handshake::renew::gateway::handle_renew_request()` — callbacks `generate_gateway_ephemeral() → gw_eph_pubkey` and `ecdh_with_sensor_ephemeral(sensor_eph_pubkey) → shared_secret`

Trigger renew when `ValidatedKey::should_renew()` returns true (~75% of key lifetime elapsed).

### Session resume (re-pair session without full install)

Clear-text 3-message exchange for **already-enrolled** sensors when the **session key is lost** but long-term identity is still trusted (no `AllGateways` broadcast, no re-enrollment):

```
SessionResumeRequest {sig_sensor_nonce} → SessionResumeChallenge {gw_eph_pubkey, …} → SessionResumeConfirm {sig_gateway_nonce, sensor_eph_pubkey}
→ session_key = HKDF(ECDH(eph↔eph), sensor_nonce ‖ gateway_nonce)
```

**Sensor:** `com::handshake::resume::sensor::resume_session()` — sign `sensor_nonce` with long-term key + `ecdh_ephemeral_with_peer`  
**Gateway:** `com::handshake::resume::gateway::handle_resume_request()` — lookup enrolled `sensor_pubkey`, verify resume signature, then same eph-eph callbacks as install

Use when: paired sensor lost session key in flash but gateway still has enrollment. Prefer **renew** when the old session key is still available.

See `diagramme/install.mermaid`, `diagramme/renew.mermaid`, and `diagramme/session_resume.mermaid`.

---

## Usage

Add to your `Cargo.toml` (adjust registry and version as needed):

```toml
[dependencies]
# Stable (prod):
sigil = { version = "=0.4.0", registry = "forgejo", default-features = false, features = ["com"] }
# Unstable (client staging), after a `dev` publish:
# sigil = { version = "=0.4.0", registry = "forgejorc", default-features = false, features = ["com"] }
```

Publish / release flow (tags, registries, `release/X.Y`): see [`.forgejo/README.md`](.forgejo/README.md).

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
    |gw_eph_pubkey| {
        /* ATECC608: generate sensor ephemeral keypair + ECDH with gw_eph_pubkey */
        Ok((sensor_eph_pubkey, shared_secret))
    },
    timestamp,
)?;
// session.keys.key is the new session key
```

Session resume example (sensor, enrolled but session key lost):

```rust
use sigil::com::handshake::resume::sensor::resume_session;

let session = resume_session(
    &mut lora,
    &mut delay,
    sensor_mac,
    battery_level,
    gateway_mac,
    new_sensor_nonce,
    sig_sensor_nonce, // ECDSA(sensor_nonce) with long-term ATECC key
    |gw_eph_pubkey| {
        Ok((sensor_eph_pubkey, shared_secret))
    },
    |gateway_pubkey, sig| { /* verify gateway sig on sensor_nonce */ true },
    |gateway_nonce| { /* sign gateway_nonce */ sig_gateway_nonce },
    timestamp,
)?;
```

---

## Project structure

```
sigil/
├── diagramme/           # Mermaid sequence diagrams (install, renew, session_resume)
├── src/
│   ├── com/
│   │   ├── handshake/
│   │   │   ├── primitives/     # Shared crypto helpers (HKDF inputs, payloads)
│   │   │   ├── lora_helpers/   # send_encrypted, try_receive_encrypted, …
│   │   │   ├── install_core/   # Ephemeral-to-ephemeral ECDH + ECDSA (install)
│   │   │   ├── renew_core/     # Lightweight renew (ephemeral-to-ephemeral ECDH)
│   │   │   ├── resume_core/    # Session resume (ECDSA + eph-eph, no old session key)
│   │   │   ├── install/        # install_session, handle_install_request
│   │   │   ├── renew/          # renew_session, handle_renew_request
│   │   │   └── resume/         # resume_session, handle_resume_request
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
