# Contract: Session API (non-blocking)

**Feature**: `001-nonblocking-session-core`  
**Audience**: Firmware main loop

## Types (logical)

```text
SessionManager<const N: usize>

SigilEvent:
  - Data { peer: [u8; 17], payload: bytes }
  - (handshake may be internalized — see pipeline)

SigilAction:
  - Transmit { dest: [u8; 17], payload: bytes }
  - WaitingForResponse { peer: [u8; 17], timeout_ms: u32 }
  - Success { peer: [u8; 17] }
  - PersistStaticKey { peer: [u8; 17], pubkey: [u8; 33] }   # install success hint

SigilError: UnknownSession | SessionExpired | Replay | CounterExhausted |
            VerificationFailed | CapacityExceeded | ParseError | NoPending |
            EcdhFailed | RandomFailed | ...
```

## Ingress

```text
process_incoming_packet(
  &mut self,
  raw: &[u8],
  now: u32,
  se: &mut impl SecureElement,
  rng: &mut impl RandomSource,   # if needed for reactive steps
) -> Result<(Option<SigilEvent>, Option<SigilAction>), SigilError>
```

**Behavior**:
- Never blocks / sleeps.
- Unknown peer → `UnknownSession`.
- Expired key on protected message → `SessionExpired` (no auto-renew).
- May return Transmit and/or WaitingForResponse for handshake continuation.
- On data success, advances `rx_counter`.

## Egress helpers (host-driven)

```text
start_install_sensor(...) -> Result<SigilAction, SigilError>
handle_install_gateway(...) -> Result<SigilAction, SigilError>
# exact split: step functions that return actions

start_renew_sensor(...) -> Result<SigilAction, SigilError>     # SENSOR ONLY
handle_renew_gateway(...) -> Result<SigilAction, SigilError>

start_resume_sensor(...) -> Result<SigilAction, SigilError>
handle_resume_gateway(...) -> Result<SigilAction, SigilError>

encrypt_data(peer, plaintext, now) -> Result<Vec payload, SigilError>
  - uses tx_counter + nonce_prefix; increments tx_counter on success

cancel(peer) -> Result<(), SigilError>
  - clears PendingHandshake; zeroizes ephemeral secrets

remove_session(peer) -> Result<(), SigilError>
  - RAM only
```

## Non-goals

- No `delay_ms` / LoRa send/receive inside these APIs.
- No gateway `start_renew_*`.
- No auto-clear pending on timeout.
