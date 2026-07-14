//! Shared cryptographic primitives for install and renew flows.
//!
//! **Renew (ephemeral-to-ephemeral):** both peers generate a fresh P-256 ephemeral keypair.
//! The gateway sends `gw_eph_pubkey` in `KeyRenewChallenge`; the sensor replies with
//! `sensor_eph_pubkey` in `KeyRenewAck`. Each side derives
//! `shared_secret = ECDH(local_eph_priv, peer_eph_pub)` and then `session_key_new` via HKDF.

use crate::com::handshake::{CHALLENGE_PLAINTEXT_LEN, PUBLIC_KEY_LEN, SIGNATURE_LEN};

/// Payload inside a lightweight [`super::renew_core::KeyRenewChallenge`] (69 bytes).
pub const RENEW_CHALLENGE_PAYLOAD_LEN: usize = PUBLIC_KEY_LEN + 32 + 4;

/// Builds the 133-byte ECIES install challenge plaintext.
pub fn build_install_plaintext(
    sig_sensor_nonce: &[u8; SIGNATURE_LEN],
    gateway_pubkey: &[u8; PUBLIC_KEY_LEN],
    gateway_nonce: &[u8; 32],
    key_expire_at: u32,
) -> [u8; CHALLENGE_PLAINTEXT_LEN] {
    let mut plaintext = [0u8; CHALLENGE_PLAINTEXT_LEN];
    plaintext[..SIGNATURE_LEN].copy_from_slice(sig_sensor_nonce);
    plaintext[SIGNATURE_LEN..SIGNATURE_LEN + PUBLIC_KEY_LEN].copy_from_slice(gateway_pubkey);
    plaintext[SIGNATURE_LEN + PUBLIC_KEY_LEN..SIGNATURE_LEN + PUBLIC_KEY_LEN + 32]
        .copy_from_slice(gateway_nonce);
    plaintext[SIGNATURE_LEN + PUBLIC_KEY_LEN + 32..].copy_from_slice(&key_expire_at.to_be_bytes());
    plaintext
}

/// Builds the lightweight renew challenge body (no ECDSA signatures).
pub fn build_renew_challenge_payload(
    eph_pubkey_compressed: &[u8; PUBLIC_KEY_LEN],
    gateway_nonce: &[u8; 32],
    key_expire_at: u32,
) -> [u8; RENEW_CHALLENGE_PAYLOAD_LEN] {
    let mut payload = [0u8; RENEW_CHALLENGE_PAYLOAD_LEN];
    payload[..PUBLIC_KEY_LEN].copy_from_slice(eph_pubkey_compressed);
    payload[PUBLIC_KEY_LEN..PUBLIC_KEY_LEN + 32].copy_from_slice(gateway_nonce);
    payload[PUBLIC_KEY_LEN + 32..].copy_from_slice(&key_expire_at.to_be_bytes());
    payload
}

/// Parses a renew challenge payload into its fields.
pub fn parse_renew_challenge_payload(
    payload: &[u8; RENEW_CHALLENGE_PAYLOAD_LEN],
) -> ([u8; PUBLIC_KEY_LEN], [u8; 32], u32) {
    let eph_pubkey = payload[..PUBLIC_KEY_LEN].try_into().expect("eph pubkey len");
    let gateway_nonce = payload[PUBLIC_KEY_LEN..PUBLIC_KEY_LEN + 32]
        .try_into()
        .expect("gateway nonce len");
    let key_expire_at = u32::from_be_bytes(
        payload[PUBLIC_KEY_LEN + 32..]
            .try_into()
            .expect("expire len"),
    );
    (eph_pubkey, gateway_nonce, key_expire_at)
}

#[cfg(test)]
mod tests {
    use super::{
        build_install_plaintext, build_renew_challenge_payload, parse_renew_challenge_payload,
        RENEW_CHALLENGE_PAYLOAD_LEN,
    };
    use crate::com::handshake::{CHALLENGE_PLAINTEXT_LEN, PUBLIC_KEY_LEN, SIGNATURE_LEN};

    #[test]
    fn build_install_plaintext_layout() {
        let sig = [0x01u8; SIGNATURE_LEN];
        let gw_pk = [0x02u8; PUBLIC_KEY_LEN];
        let gw_nonce = [0x03u8; 32];
        let expire_at = 1_700_000u32;

        let plaintext = build_install_plaintext(&sig, &gw_pk, &gw_nonce, expire_at);

        assert_eq!(plaintext.len(), CHALLENGE_PLAINTEXT_LEN);
        assert_eq!(&plaintext[..SIGNATURE_LEN], &sig);
        assert_eq!(
            &plaintext[SIGNATURE_LEN..SIGNATURE_LEN + PUBLIC_KEY_LEN],
            &gw_pk
        );
        assert_eq!(
            &plaintext[SIGNATURE_LEN + PUBLIC_KEY_LEN..SIGNATURE_LEN + PUBLIC_KEY_LEN + 32],
            &gw_nonce
        );
        assert_eq!(
            u32::from_be_bytes(
                plaintext[SIGNATURE_LEN + PUBLIC_KEY_LEN + 32..]
                    .try_into()
                    .unwrap()
            ),
            expire_at
        );
    }

    #[test]
    fn build_and_parse_renew_challenge_payload_roundtrip() {
        let eph = [0x11u8; PUBLIC_KEY_LEN];
        let gw_nonce = [0xBBu8; 32];
        let expire_at = 42u32;

        let payload = build_renew_challenge_payload(&eph, &gw_nonce, expire_at);
        assert_eq!(payload.len(), RENEW_CHALLENGE_PAYLOAD_LEN);

        let (parsed_eph, parsed_nonce, parsed_expire) = parse_renew_challenge_payload(&payload);
        assert_eq!(parsed_eph, eph);
        assert_eq!(parsed_nonce, gw_nonce);
        assert_eq!(parsed_expire, expire_at);
    }
}
