use crate::com::handshake::{PUBLIC_KEY_LEN, SIGNATURE_LEN};
use bincode::{Decode, Encode};

/// Install challenge: gateway ephemeral pubkey + ECDSA proof + session parameters (clear-text).
///
/// Sent in clear on LoRa during first-time pairing. The sensor generates its own ephemeral
/// keypair, performs **ephemeral-to-ephemeral** ECDH with `eph_pubkey_compressed`, and returns
/// its ephemeral pubkey in [`HandshakeConfirm`].
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub struct HandshakeChallenge {
    eph_pubkey_compressed: [u8; PUBLIC_KEY_LEN],
    sig_sensor_nonce: [u8; SIGNATURE_LEN],
    gateway_pubkey: [u8; PUBLIC_KEY_LEN],
    gateway_nonce: [u8; 32],
    key_expire_at: u32,
}

impl HandshakeChallenge {
    /// Builds a structured install challenge (replaces the former ECIES 194-byte blob).
    pub fn new(
        eph_pubkey_compressed: [u8; PUBLIC_KEY_LEN],
        sig_sensor_nonce: [u8; SIGNATURE_LEN],
        gateway_pubkey: [u8; PUBLIC_KEY_LEN],
        gateway_nonce: [u8; 32],
        key_expire_at: u32,
    ) -> Self {
        Self {
            eph_pubkey_compressed,
            sig_sensor_nonce,
            gateway_pubkey,
            gateway_nonce,
            key_expire_at,
        }
    }

    /// Gateway ephemeral public key (33-byte compressed P-256).
    pub fn eph_pubkey_compressed(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.eph_pubkey_compressed
    }

    /// Gateway ECDSA signature of the sensor nonce.
    pub fn sig_sensor_nonce(&self) -> &[u8; SIGNATURE_LEN] {
        &self.sig_sensor_nonce
    }

    /// Gateway long-term public key for signature verification.
    pub fn gateway_pubkey(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.gateway_pubkey
    }

    pub fn gateway_nonce(&self) -> &[u8; 32] {
        &self.gateway_nonce
    }

    pub fn key_expire_at(&self) -> u32 {
        self.key_expire_at
    }
}

/// ECDSA confirmation plus sensor ephemeral pubkey (install only).
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub struct HandshakeConfirm {
    sig_gateway_nonce: [u8; SIGNATURE_LEN],
    sensor_eph_pubkey_compressed: [u8; PUBLIC_KEY_LEN],
}

impl HandshakeConfirm {
    /// Builds confirm with the sensor ECDSA signature and ephemeral public key.
    pub fn new(
        sig_gateway_nonce: [u8; SIGNATURE_LEN],
        sensor_eph_pubkey_compressed: [u8; PUBLIC_KEY_LEN],
    ) -> Self {
        Self {
            sig_gateway_nonce,
            sensor_eph_pubkey_compressed,
        }
    }

    /// Returns the sensor's ECDSA signature of the gateway nonce.
    pub fn sig_gateway_nonce(&self) -> &[u8; SIGNATURE_LEN] {
        &self.sig_gateway_nonce
    }

    /// Returns the sensor ephemeral public key for gateway-side ECDH completion.
    pub fn sensor_eph_pubkey_compressed(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.sensor_eph_pubkey_compressed
    }
}

/// Successful sensor-side session: session keys plus the gateway that issued the challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeSession {
    pub keys: crate::com::keys::Keys,
    pub gateway_mac: [u8; 17],
}

/// Result returned by the gateway after a successful session establishment.
#[derive(Debug)]
pub struct HandshakeResult {
    pub session_key: [u8; 32],
    pub sensor_pubkey: [u8; PUBLIC_KEY_LEN],
    pub key_expire_at: u32,
}

#[cfg(test)]
mod tests {
    use super::{HandshakeChallenge, HandshakeConfirm};
    use crate::com::handshake::{PUBLIC_KEY_LEN, SIGNATURE_LEN};

    #[test]
    fn handshake_challenge_roundtrip_encode() {
        let challenge = HandshakeChallenge::new(
            [0x11u8; PUBLIC_KEY_LEN],
            [0x22u8; SIGNATURE_LEN],
            [0x33u8; PUBLIC_KEY_LEN],
            [0x44u8; 32],
            1_700_000u32,
        );
        let mut encoded = [0u8; 256];
        let len = bincode::encode_into_slice(&challenge, &mut encoded, bincode::config::standard())
            .expect("encode");
        let (decoded, _) = bincode::decode_from_slice::<HandshakeChallenge, _>(
            &encoded[..len],
            bincode::config::standard(),
        )
        .expect("decode");
        assert_eq!(decoded, challenge);
    }

    #[test]
    fn handshake_confirm_roundtrip_encode() {
        let confirm = HandshakeConfirm::new([0x55u8; SIGNATURE_LEN], [0x66u8; PUBLIC_KEY_LEN]);
        let mut encoded = [0u8; 128];
        let len = bincode::encode_into_slice(&confirm, &mut encoded, bincode::config::standard())
            .expect("encode");
        let (decoded, _) = bincode::decode_from_slice::<HandshakeConfirm, _>(
            &encoded[..len],
            bincode::config::standard(),
        )
        .expect("decode");
        assert_eq!(decoded, confirm);
        assert_eq!(
            decoded.sensor_eph_pubkey_compressed(),
            &[0x66u8; PUBLIC_KEY_LEN]
        );
    }
}
