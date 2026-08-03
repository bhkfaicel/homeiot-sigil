use bincode::{Decode, Encode};

/// Session resume trigger for an already-enrolled sensor (clear-text, directed to gateway).
///
/// Proves possession of the sensor long-term key via ECDSA over `sensor_nonce` without
/// rebroadcasting identity or requiring the previous session key (unlike renew).
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub struct SessionResumeRequest {
    sensor_nonce: [u8; 32],
    sig_sensor_nonce: [u8; crate::com::handshake::SIGNATURE_LEN],
}

impl SessionResumeRequest {
    /// Builds a resume request with the sensor nonce and its ECDSA signature.
    pub fn new(
        sensor_nonce: [u8; 32],
        sig_sensor_nonce: [u8; crate::com::handshake::SIGNATURE_LEN],
    ) -> Self {
        Self {
            sensor_nonce,
            sig_sensor_nonce,
        }
    }

    pub fn sensor_nonce(&self) -> &[u8; 32] {
        &self.sensor_nonce
    }

    pub fn sig_sensor_nonce(&self) -> &[u8; crate::com::handshake::SIGNATURE_LEN] {
        &self.sig_sensor_nonce
    }
}

#[cfg(test)]
mod tests {
    use super::SessionResumeRequest;
    use crate::com::handshake::SIGNATURE_LEN;

    #[test]
    fn session_resume_request_roundtrip_encode() {
        let req = SessionResumeRequest::new([0xAA; 32], [0x55; SIGNATURE_LEN]);
        let mut encoded = [0u8; 128];
        let len = bincode::encode_into_slice(&req, &mut encoded, bincode::config::standard())
            .expect("encode");
        let (decoded, _) = bincode::decode_from_slice::<SessionResumeRequest, _>(
            &encoded[..len],
            bincode::config::standard(),
        )
        .expect("decode");
        assert_eq!(decoded, req);
    }
}
