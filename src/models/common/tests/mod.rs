use crate::{
    com::handshake::{PUBLIC_KEY_LEN, SIGNATURE_LEN, HANDSHAKE_MESSAGE_MAX},
    models::common::{
        BodySchema, Destination::AllGateways, MessageSchema, MessageType,
        RequestType, Status, TIMESTAMP_NOT_AVAILABLE, ENCRYPTED_BODY_MAX, deserialize_body,
    },
    com::handshake::sensor::HandshakeRequest,
};

fn dummy_pubkey() -> [u8; PUBLIC_KEY_LEN] {
    [0u8; PUBLIC_KEY_LEN]
}

fn dummy_sig() -> [u8; SIGNATURE_LEN] {
    [0u8; SIGNATURE_LEN]
}

#[test]
fn test_message_serialize_deserialize() {
    let key: [u8; 32] = [0x26; 32];
    let nonce: [u8; 12] = [1u8; 12];
    let src: [u8; 17] = *b"26:06:91:67:89:AB";

    let original_msg = MessageSchema::create_body_request(
        src,
        100,
        AllGateways,
        MessageType::HandshakeRequest,
        RequestType::HandshakeRequest(HandshakeRequest::new(
            [0xAA; 32],
            dummy_pubkey(),
            dummy_sig(),
        )),
        TIMESTAMP_NOT_AVAILABLE,
    );

    let mut msg = original_msg.clone();

    // Serialize
    let buffer = msg
        .serialize::<{ HANDSHAKE_MESSAGE_MAX }>(&key, &nonce, None)
        .expect("Serialization failed");

    // Deserialize
    let parsed_msg =
        super::deserialize::<{ HANDSHAKE_MESSAGE_MAX }>(&buffer).expect("Deserialization failed");

    // Assert header fields
    assert_eq!(parsed_msg.header.src, original_msg.header.src);
    assert_eq!(parsed_msg.header.dist, original_msg.header.dist);
    assert_eq!(
        parsed_msg.header.message_type,
        original_msg.header.message_type
    );
    assert_eq!(parsed_msg.header.status, original_msg.header.status);
    assert_eq!(parsed_msg.header.timestamp, original_msg.header.timestamp);
    let message = deserialize_body::<{ ENCRYPTED_BODY_MAX }>(
        parsed_msg.header,
        &parsed_msg.body,
        &key,
        None,
    )
    .unwrap();
    // Assert body content
    match (message.body, &original_msg.body) {
        (
            BodySchema::RequestType(RequestType::HandshakeRequest(a)),
            BodySchema::RequestType(RequestType::HandshakeRequest(b)),
        ) => {
            assert_eq!(a.sensor_nonce(), b.sensor_nonce())
        }
        _ => {}
    }
}

#[test]
fn test_status_enum_values() {
    assert_eq!(Status::Ok as u8, 0);
    assert_eq!(Status::Cancelled as u8, 1);
    assert_eq!(Status::UnknownStatus as u8, 2);
    assert_eq!(Status::InvalidArgument as u8, 3);
    assert_eq!(Status::NotFound as u8, 4);
    assert_eq!(Status::AlreadyExists as u8, 5);
    assert_eq!(Status::PermissionDenied as u8, 6);
    assert_eq!(Status::ResourceExhausted as u8, 7);
    assert_eq!(Status::Aborted as u8, 8);
    assert_eq!(Status::OutOfRange as u8, 9);
    assert_eq!(Status::Internal as u8, 10);
    assert_eq!(Status::Unavailable as u8, 11);
    assert_eq!(Status::Unauthenticated as u8, 12);
}

#[test]
fn test_status_serialize_deserialize() {
    let key: [u8; 32] = [0x26; 32];
    let nonce: [u8; 12] = [1u8; 12];
    let src: [u8; 17] = *b"26:06:91:67:89:AB";

    let mut msg = MessageSchema::create_body_request(
        src,
        100,
        AllGateways,
        MessageType::HandshakeRequest,
        RequestType::HandshakeRequest(HandshakeRequest::new(
            [0xAA; 32],
            dummy_pubkey(),
            dummy_sig(),
        )),
        TIMESTAMP_NOT_AVAILABLE,
    );

    msg.header.status = Status::Cancelled;

    let buffer = msg
        .serialize::<{ HANDSHAKE_MESSAGE_MAX }>(&key, &nonce, None)
        .expect("Serialization failed");

    let parsed_msg =
        super::deserialize::<{ HANDSHAKE_MESSAGE_MAX }>(&buffer).expect("Deserialization failed");

    assert_eq!(parsed_msg.header.status, Status::Cancelled);

    let message = deserialize_body::<{ ENCRYPTED_BODY_MAX }>(
        parsed_msg.header,
        &parsed_msg.body,
        &key,
        None,
    )
    .unwrap();
    assert_eq!(message.header.status, Status::Cancelled);
}
