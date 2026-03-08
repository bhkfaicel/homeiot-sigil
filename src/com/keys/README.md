# KeyManager - HKDF Key Manager

## Embedded Compatibility

### ✅ Compatible with SAMD21 and other Cortex-M microcontrollers

The `KeyManager` module is designed to work on embedded systems with the following constraints:

- ✅ **no_std**: No dependency on the standard library
- ✅ **heapless**: Uses only static allocations
- ✅ **Minimal RAM**: ~100 bytes of RAM for structures
- ✅ **Flash**: ~5-10 KB of compiled code (with optimizations)

### SAMD21 Specifications

The SAMD21 (ARM Cortex-M0+) has:

- **RAM**: 32 KB
- **Flash**: 256 KB
- **Architecture**: thumbv6m-none-eabi

The `KeyManager` is **fully compatible** with these constraints.

### Memory Consumption

#### RAM (stack)

- `KeyManager`: 49 bytes (32 + 17)
- HKDF operations: ~200-300 bytes temporary
- **Total estimated**: < 500 bytes of RAM

#### Flash

- HKDF code: ~3-5 KB
- SHA-256 code: ~2-4 KB
- KeyManager code: ~1-2 KB
- **Total estimated**: ~6-11 KB of Flash

### Performance

On SAMD21 (48 MHz, Cortex-M0+):

- `derive_device_key()`: ~2-5 ms
- `derive_session_key()`: ~2-5 ms
- `derive_usage_key()`: ~2-5 ms

**Note**: Operations are synchronous and blocking. For real-time applications, consider execution in a dedicated task.

### Dependencies

The following dependencies are required and no_std compatible:

```toml
hkdf = { version = "0.12", default-features = false }
sha2 = { version = "0.10", default-features = false, features = ["oid"] }
```

### Usage on SAMD21

```rust
use sigil::com::init::keys::KeyManager;

// Load the master secret from flash memory (or Secure Element)
let master_key = load_master_key_from_flash();

// Get the device identifier (MAC address from UID)
let device_id = get_device_mac_address();

// Create the key manager
let key_manager = KeyManager::new(master_key, device_id);

// Derive the device key (can be cached)
let device_key = key_manager.derive_device_key();
```

### Recommended Optimizations

1. **Caching**: Derive `device_key` once at startup and store it
2. **Session keys**: Derive only when necessary (not for every message)
3. **Release compilation**: Use `opt-level = "z"` and `lto = true` to reduce size

### Limitations

- ⚠️ No hardware acceleration: SHA-256 is executed in software
- ⚠️ Performance: ~2-5 ms per derivation (acceptable for most cases)
- ⚠️ No integrated Secure Element: The master secret must be stored in flash (not ideal)

### Production Recommendations

For maximum security on SAMD21:

1. Use an **external Secure Element** (ATECC608A) to store the master secret
2. Implement **secure loading** of the master secret at startup
3. **Encrypt** the master secret in flash if Secure Element unavailable
4. **Cache** the device key to avoid recalculations
