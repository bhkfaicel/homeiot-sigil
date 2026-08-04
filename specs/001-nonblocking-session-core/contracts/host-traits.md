# Contract: Host Traits

**Feature**: `001-nonblocking-session-core`  
**Audience**: Firmware integrators

## `SecureElement`

Host-provided secure-element (e.g. ATECC608x) operations. Private keys never leave the device.

```text
ecdh(peer_pubkey: &[u8; 33]) -> Result<[u8; 32], CryptoError>
  - ECDH using local static (or designated) private key slot × peer compressed P-256 public key
  - Used by: install (as required), fast resume (static↔static), NOT renew ephemeral path

sign_ecdsa(message: &[u8]) -> Result<[u8; 64], CryptoError>
  - ECDSA P-256 signature (r||s)
  - Used by: install identity proofs only

verify_ecdsa(pubkey: &[u8; 33], message: &[u8], signature: &[u8; 64]) -> Result<bool, CryptoError>
  - Optional if verify can be pure software; may live as separate host fn or library verify with p256
```

**Rules**:
- Library MUST NOT request raw private key export.
- Errors map to `SigilError::EcdhFailed` / `VerificationFailed`.

## `RandomSource`

```text
fill_random(dest: &mut [u8]) -> Result<(), RandomError>
```

**Used for**:
- Ephemeral private key material (renew)
- Session `nonce_prefix[4]`
- Protocol nonces as specified per phase

**Rules**: Failure aborts the step without installing a session key.

## Test doubles (required in-tree)

| Mock | Behavior |
|------|----------|
| `MockSecureElement` | Fixed ECDH shared secret for known peer pubs; canned signatures |
| `MockRandom` | Deterministic sequential or recorded bytes |
