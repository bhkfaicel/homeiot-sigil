use crate::com::handshake::PUBLIC_KEY_LEN;
use bincode::{Decode, Encode};

/// Lightweight renew challenge: gateway ephemeral ECDH pubkey + nonces (no ECDSA, no ECIES).
///
/// Sent encrypted with the **current** session key. The sensor generates its own ephemeral
/// keypair, performs **ephemeral-to-ephemeral** ECDH with `eph_pubkey_compressed`, and
/// returns its ephemeral pubkey in [`KeyRenewAck`].
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub struct KeyRenewChallenge {
    eph_pubkey_compressed: [u8; PUBLIC_KEY_LEN],
    gateway_nonce: [u8; 32],
    key_expire_at: u32,
}

impl KeyRenewChallenge {
    pub fn new(
        eph_pubkey_compressed: [u8; PUBLIC_KEY_LEN],
        gateway_nonce: [u8; 32],
        key_expire_at: u32,
    ) -> Self {
        Self {
            eph_pubkey_compressed,
            gateway_nonce,
            key_expire_at,
        }
    }

    pub fn eph_pubkey_compressed(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.eph_pubkey_compressed
    }

    pub fn gateway_nonce(&self) -> &[u8; 32] {
        &self.gateway_nonce
    }

    pub fn key_expire_at(&self) -> u32 {
        self.key_expire_at
    }
}

/// Sensor acknowledgment for renew: carries the sensor ephemeral ECDH pubkey.
///
/// Authentication is provided by AEAD on the current session key. The gateway completes
/// ephemeral-to-ephemeral ECDH with `sensor_eph_pubkey_compressed` to derive the same
/// shared secret as the sensor.
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub struct KeyRenewAck {
    sensor_eph_pubkey_compressed: [u8; PUBLIC_KEY_LEN],
}

impl KeyRenewAck {
    /// Builds an ack carrying the sensor's compressed ephemeral public key.
    pub fn new(sensor_eph_pubkey_compressed: [u8; PUBLIC_KEY_LEN]) -> Self {
        Self {
            sensor_eph_pubkey_compressed,
        }
    }

    /// Returns the sensor ephemeral public key (33-byte compressed P-256).
    pub fn sensor_eph_pubkey_compressed(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.sensor_eph_pubkey_compressed
    }
}

#[cfg(test)]
mod tests {
    use super::KeyRenewAck;
    use crate::com::handshake::PUBLIC_KEY_LEN;

    #[test]
    fn key_renew_ack_roundtrip_encode() {
        let ack = KeyRenewAck::new([0x22u8; PUBLIC_KEY_LEN]);
        let mut encoded = [0u8; 64];
        let len = bincode::encode_into_slice(&ack, &mut encoded, bincode::config::standard())
            .expect("encode");
        let (decoded, _) = bincode::decode_from_slice::<KeyRenewAck, _>(
            &encoded[..len],
            bincode::config::standard(),
        )
        .expect("decode");
        assert_eq!(decoded, ack);
        assert_eq!(
            decoded.sensor_eph_pubkey_compressed(),
            &[0x22u8; PUBLIC_KEY_LEN]
        );
    }
}
