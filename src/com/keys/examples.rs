//! KeyManager usage examples
//!
//! This file shows how to use KeyManager in different scenarios.

#![no_std]
#![allow(dead_code)]

use super::KeyManager;

/// Example 1: Basic usage with a master secret and device identifier
pub fn example_basic_usage() {
    // ⚠️ IN PRODUCTION: The master secret must be loaded from secure storage
    // (Secure Element, TPM, or protected memory)
    let master_key = load_master_key_from_secure_storage();

    // The device identifier (e.g., MAC address)
    let device_id = get_device_mac_address();

    // Create the key manager
    let key_manager = KeyManager::new(master_key, device_id);

    // Derive the unique device key
    let device_key = key_manager.derive_device_key();

    // Use this key to encrypt/decrypt messages
    // encrypt_message(&message, &device_key);
}

/// Example 2: Usage with ephemeral session keys
pub fn example_session_keys() {
    let master_key = load_master_key_from_secure_storage();
    let device_id = get_device_mac_address();
    let key_manager = KeyManager::new(master_key, device_id);

    // For each message, generate a unique nonce
    let nonce = generate_random_nonce();

    // Derive a unique session key for this message
    let session_key = key_manager.derive_session_key(&nonce);

    // Use the session key to encrypt the message
    // encrypt_message(&message, &session_key);
}

/// Example 3: Key separation by function
pub fn example_usage_keys() {
    let master_key = load_master_key_from_secure_storage();
    let device_id = get_device_mac_address();
    let key_manager = KeyManager::new(master_key, device_id);

    // Different keys for different usages
    let installation_key = key_manager.derive_usage_key(b"installation");
    let validation_key = key_manager.derive_usage_key(b"validation");
    let data_key = key_manager.derive_usage_key(b"data");
    let control_key = key_manager.derive_usage_key(b"control");

    // Use the appropriate key according to message type
    // match message_type {
    //     MessageType::Install => encrypt(&message, &installation_key),
    //     MessageType::Validate => encrypt(&message, &validation_key),
    //     MessageType::Data => encrypt(&message, &data_key),
    //     MessageType::Control => encrypt(&message, &control_key),
    // }
}

/// Example 4: Migration from DEFAULT_KEY
pub fn example_migration_from_default_key() {
    // Old code (INSECURE):
    // use sigil::com::init::DEFAULT_KEY;
    // encrypt_message(&message, &DEFAULT_KEY);

    // New code (SECURE):
    let master_key = load_master_key_from_secure_storage();
    let device_id = get_device_mac_address();
    let key_manager = KeyManager::new(master_key, device_id);

    // Option 1: Use the device key
    let device_key = key_manager.derive_device_key();
    // encrypt_message(&message, &device_key);

    // Option 2: Use a session key
    let nonce = generate_random_nonce();
    let session_key = key_manager.derive_session_key(&nonce);
    // encrypt_message(&message, &session_key);
}

// Helper functions (to be implemented according to your platform)
fn load_master_key_from_secure_storage() -> [u8; 32] {
    // TODO: Load from Secure Element, TPM, or protected memory
    // ⚠️ NEVER hardcode here!
    [0u8; 32]
}

fn get_device_mac_address() -> [u8; 17] {
    // TODO: Read the device MAC address
    [0u8; 17]
}

fn generate_random_nonce() -> [u8; 12] {
    // TODO: Generate a cryptographically secure nonce
    [0u8; 12]
}
