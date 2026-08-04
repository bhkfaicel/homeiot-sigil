# Contract: Wire Messages (B+ breaking)

**Feature**: `001-nonblocking-session-core`  
**Note**: Layouts are **not** dual-stack compatible with pre-core firmwares. MAC fields remain `[u8; 17]`.

## Framing

Reuse / adapt existing `MessageSchema` + `HeaderSchema` concepts:
- Source / destination MAC: 17 bytes
- Message type discriminant
- Body: clear or AEAD blob

Encrypted body wire form for application data:

```text
nonce_prefix[4] || tx_counter_be[8] || ciphertext || tag[16]
```

(Exact packing may embed the 12-byte nonce as a contiguous field = prefix‖counter.)

## Phase message types (logical names)

### Install (heavy / clear + ECIES challenge)

| Step | Direction | Contents (logical) |
|------|-----------|-------------------|
| InstallRequest | Sensor → GW | sensor_nonce, sensor_static_pubkey[33], sig |
| InstallChallenge | GW → Sensor | ECIES ciphertext (~194 B class) carrying gateway material |
| InstallConfirm | Sensor → GW | sig over gateway nonce |

### Renew (sensor-initiated, encrypted under current session key)

| Step | Direction | Contents (logical) |
|------|-----------|-------------------|
| RenewRequest | Sensor → GW | sensor_nonce, sensor_eph_pubkey[33], … |
| RenewChallenge | GW → Sensor | gateway_eph_pubkey[33], gateway_nonce, key_expire_at, … |
| RenewAck | Sensor → GW | ack / integrity proof under old key |

Both sides derive new session key via eph↔eph ECDH + HKDF; reset counters; new nonce_prefix.

Target crypto material ~50 B class for ephemeral pubs (excluding full frame).

### Fast resume (static↔static, minimal)

| Step | Direction | Contents (logical) |
|------|-----------|-------------------|
| ResumeRequest | Sensor → GW | sensor_nonce, … (no eph pubkey, no ECDSA) |
| ResumeChallenge | GW → Sensor | gateway_nonce, key_expire_at, … |
| ResumeConfirm | Sensor → GW | short confirm |

ECDH = SE(static_priv) × peer_static_pub on each side. Target ~60 B crypto class.

## Versioning

- Breaking change: bump crate major (or repo’s breaking 0.x policy).
- Optional future: version byte in header — **not required** for this feature if whole fleet flashes together.
