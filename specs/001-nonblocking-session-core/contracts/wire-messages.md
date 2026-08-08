# Contract: Wire Messages (B+ breaking)

**Feature**: `001-nonblocking-session-core`  
**Note**: Layouts are **not** dual-stack compatible with pre-core firmwares. MAC fields remain `[u8; 17]`.

## Framing

Every sigil frame carries an **outer header** in clear text:

```text
[peer_mac: 17 bytes] [protocol_version: 1 byte = 0x03] [frame_type: 1 byte]
[type-specific payload]
```

`peer_mac` is the **sender** durable identity (`SessionManager::local_mac` on
egress). Receivers look up sessions by that sender MAC.

`protocol_version` (position 17) must equal `0x03`; other values are rejected.
The `frame_type` byte (position 18) allows the receiver to classify the
message **without decryption** — see [`crate::core::frame::FrameType`].

### Frame type byte assignments

| Range    | Protocol | Types                                        |
| -------- | -------- | -------------------------------------------- |
| `0x00`   | Data     | Application data (AEAD)                      |
| `0x01-4` | Install  | Request, Challenge, Confirm, CommitConfirmed |
| `0x11-4` | Renew    | Request, Challenge, Ack, CommitConfirmed     |
| `0x21-4` | Resume   | Request, Challenge, Confirm, CommitConfirmed |
| `0x30`   | Time     | TimeSync (gateway → sensor, AEAD)            |
| `0x31-2` | Event    | Event, EventAck (AEAD)                       |
| `0x33`   | Time     | TimeSyncRequest (sensor → gateway, AEAD)     |

## Encrypted payload format (Data + TimeSync + Event/Ack + Renew* + ResumeConfirm + *CommitConfirmed)

After the outer header, encrypted frames carry:

```text
[nonce_prefix:4] [tx_counter_be:8] [ciphertext + AEAD tag: variable]
```

The full 12-byte AEAD nonce is reconstructed as `nonce_prefix ‖ tx_counter_be`.

**AAD (Additional Authenticated Data):** ChaCha20-Poly1305 authenticates the
clear-text outer header as AAD (19 bytes):

```text
AAD = peer_mac[17] ‖ protocol_version[1] ‖ frame_type[1]
```

This binds the ciphertext to its routing type and protocol version so an on-air
flip of `frame_type` (e.g. Data `0x00` → RenewRequest `0x11`) fails the
Poly1305 tag.

## Reliable Event / EventAck

| Message  | Direction   | Frame type | Authenticated plaintext             |
| -------- | ----------- | ---------- | ----------------------------------- |
| Event    | Sensor → GW | `0x31`     | `event_id_be[8] || app_payload[..]` |
| EventAck | GW → Sensor | `0x32`     | `event_id_be[8]`                    |

`EventAck` has a fixed 55-byte wire length. `Event` and `EventAck` use the
normal directional session key, nonce prefix and AEAD replay counter. Each
retry is newly encrypted with a fresh counter; retransmitting cached wire bytes
is rejected as replay.

The ACK is an application commit acknowledgement, not merely a radio receipt.
The gateway host calls `ack_event` only after durable processing. It must
deduplicate `(sensor PeerId, event_id)` in durable storage across gateway
reboots. Sensor hosts allocate strictly increasing `u64` ids durably across
sensor reboots and retry the same id with the same semantic payload.

## Time synchronization request

| Message         | Direction   | Frame type | Authenticated plaintext |
| --------------- | ----------- | ---------- | ----------------------- |
| TimeSyncRequest | Sensor → GW | `0x33`     | empty                   |
| TimeSync        | GW → Sensor | `0x30`     | `time[4] || sequence[4] || uncertainty[2]` |

`TimeSyncRequest` is a 47-byte AEAD frame and uses the normal session replay
counter. The gateway never responds automatically inside Sigil: it receives a
typed event, applies host policy, then calls `encrypt_time_sync`. Sigil accepts
at most one authenticated request per peer every 15 seconds.

## Clear-text payload format (Install Request/Challenge/Confirm + Resume Request/Challenge)

After the outer header, clear-text frames carry protocol-specific fields
(public keys, nonces, signatures) with no encryption.

## Phase message layouts

### Install (clear-text identity + factory attestation + ECDSA + ECDH)

Both peers verify that the peer static public key carries a **factory
certificate**: ECDSA signature by the shared factory root over
`version ‖ product_id ‖ hardware_profile_id ‖ factory_key_id ‖ peer_mac ‖
compressed_pubkey`. This certificate is
static, provisioned in the ATECC at the factory. The factory root is configured on
`SessionManager` at construction (cached in RAM); it is never taken from the
packet. MAC allowlisting remains a host policy step before calling
`handle_install_request`.

| Step                   | Direction   | Frame type | Body after outer header                                                                                              |
| ---------------------- | ----------- | ---------- | -------------------------------------------------------------------------------------------------------------------- |
| InstallRequest         | Sensor → GW | `0x01`     | `sensor_peer_mac[17]`, `hardware_profile_id[1]`, `factory_key_id[1]`, `sensor_static_pub[33]`, `factory_cert_sig[64]`, `sensor_nonce[16]`, `sensor_sig[64]`         |
| InstallChallenge       | GW → Sensor | `0x02`     | `gw_peer_mac[17]`, `hardware_profile_id[1]`, `factory_key_id[1]`, `gw_static_pub[33]`, `factory_cert_sig[64]`, `gw_nonce[16]`, `key_lifetime_secs[4]`, `gw_sig[64]` |
| InstallConfirm         | Sensor → GW | `0x03`     | `sensor_peer_mac[17]`, `confirm_sig[64]`                                                                             |
| InstallCommitConfirmed | GW → Sensor | `0x04` | AEAD under **new** g2s key (empty plaintext, counter 0) |


Wire lengths (including outer header): Request **215**, Challenge **219**, Confirm **100**.

`factory_cert_sig` = ECDSA(factory_priv, version ‖ product_id ‖ hardware_profile_id
‖ factory_key_id ‖ peer_mac ‖ device_static_pub).

Device ECDSA possession proofs **bind the peer MAC**:

```text
sensor_sig = ECDSA(sensor_priv, "sigil-install-request-v3" ‖ peer_mac ‖ hardware_profile_id ‖ factory_key_id ‖ pubkey ‖ nonce)
gw_sig     = ECDSA(gw_priv, "sigil-install-challenge-v3" ‖ sensor_mac ‖ sensor_nonce ‖ gateway_mac ‖ hardware_profile_id ‖ factory_key_id ‖ gateway_pub ‖ gateway_nonce ‖ key_lifetime_secs)
confirm_sig= ECDSA(sensor_priv, "sigil-install-confirm-v3" ‖ sensor_mac ‖ sensor_nonce ‖ gateway_mac ‖ gateway_nonce ‖ key_lifetime_secs)
```

A MITM that flips `peer_mac` without the device private key fails verification.
Cost on the sensor is negligible (same 64-byte signature; ~17 extra bytes hashed).

Session key derivation (both sides):

```text
shared = ECDH(static_priv, peer_static_pub)
info   = b"sigil-install" ‖ sensor_nonce ‖ gateway_nonce
(session_key, nonce_prefix) = HKDF-SHA256(IKM=shared, salt=None, info)
```

Mixing both handshake nonces ensures each install produces fresh key material
even when the static ECDH shared secret is unchanged.

### Renew (sensor-initiated, encrypted under current session key)

| Step                 | Direction   | Frame type | Plaintext body (after AEAD decrypt)                                |
| -------------------- | ----------- | ---------- | ------------------------------------------------------------------ |
| RenewRequest         | Sensor → GW | `0x11`     | `sensor_eph_pubkey[32]` (X25519)                                   |
| RenewChallenge       | GW → Sensor | `0x12`     | `gw_eph_pubkey[32]` (X25519), `key_lifetime_secs[4]`               |
| RenewAck             | Sensor → GW | `0x13`     | (empty — frame_type byte is sufficient)                            |
| RenewCommitConfirmed | GW → Sensor | `0x14` | AEAD under **new** g2s key (empty plaintext, counter 0) |


Both sides derive new session key via eph↔eph X25519 ECDH + HKDF; reset counters; new nonce_prefix.

HKDF info:
`b"sigil-renew" ‖ peer_mac[17] ‖ sensor_eph[32] ‖ gateway_eph[32] ‖ key_lifetime_secs_be[4]`.

`RenewAck` MUST use AEAD counter `0` under the new key; gateway then sets `rx_counter = 1`.

### Fast resume (static↔static)

| Step                  | Direction   | Frame type | Body after outer header                                                                                                                                                 |
| --------------------- | ----------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ResumeRequest         | Sensor → GW | `0x21`     | `sensor_nonce[16]`, `req_mac[16]` (clear text; MAC keyed by durable `resume_psk` from install; **verified before SE-ECDH**) — **51-byte** frame                         |
| ResumeChallenge       | GW → Sensor | `0x22`     | `gateway_nonce[16]`, `key_lifetime_secs[4]`, `chal_mac[16]` (clear text; MAC keyed by static ECDH; lifetime also bound into HKDF)                                       |
| ResumeConfirm         | Sensor → GW | `0x23`     | AEAD under **new** session key: `nonce_prefix[4] ‖ counter_be[8]=0 ‖ ciphertext+tag` (empty plaintext; AAD = outer header). Gateway sets `rx_counter = 1` after accept. |
| ResumeCommitConfirmed | GW → Sensor | `0x24` | AEAD under **new** g2s key (empty plaintext, counter 0) |


ECDH = SE(static_priv) × peer_static_pub on each side.

At install, both peers also derive a durable resume PSK (persisted by the host):

```text
resume_psk = HKDF(shared_install, info=b"sigil-resume-psk" ‖ sensor_nonce ‖ gateway_nonce)[0..32]
```

ResumeRequest MAC :


```text
req_mac = HKDF(resume_psk, info=b"sigil-resume-req" ‖ sensor_mac ‖ sensor_nonce)[0..16]
```

Session key derivation (both sides):

```text
shared = ECDH(static_priv, peer_static_pub)
info   = b"sigil-resume" ‖ sensor_nonce ‖ gateway_nonce ‖ key_lifetime_secs_be
(session_key, nonce_prefix) = HKDF-SHA256(IKM=shared, salt=None, info)
```

`key_lifetime_secs` is a big-endian `u32` duration in seconds. Each peer adds
it to its own local monotonic clock, so their epochs may differ. It is carried
in clear text on the challenge but authenticated by key agreement: a MITM flip yields different keys →
ResumeConfirm AEAD fails. Gateway hosts must also respect
`RESUME_REQUEST_COOLDOWN` (**15 seconds**) between accepted resume ECDH
operations for the same peer (after a valid request MAC).

The encrypted confirm proves possession of the new key before the gateway
installs it (same pattern as RenewAck).

## Versioning

- Breaking change: bump crate major (or repo's breaking 0.x policy).
- Optional future: version byte in header — **not required** for this feature if whole fleet flashes together.
