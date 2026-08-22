#![cfg(test)]

use super::*;

fn sample_peer_id() -> [u8; PEER_ID_LEN] {
    [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff, 0x00,
    ]
}

fn sample_compressed_pubkey() -> [u8; COMPRESSED_PUBKEY_LEN] {
    let mut k = [0u8; COMPRESSED_PUBKEY_LEN];
    k[0] = 0x02;
    k[1..].fill(0xAB);
    k
}

fn sample_signature() -> [u8; SIGNATURE_RS_LEN] {
    let mut s = [0u8; SIGNATURE_RS_LEN];
    s.iter_mut().enumerate().for_each(|(i, b)| *b = i as u8);
    s
}

#[test]
fn cert_message_is_55_bytes_with_exact_offsets() {
    let msg = build_factory_cert_message(
        ProductId::Sensor,
        3,
        7,
        &sample_peer_id(),
        &sample_compressed_pubkey(),
    )
    .expect("valid inputs build a message");

    assert_eq!(msg.len(), FACTORY_CERT_MSG_LEN);
    assert_eq!(msg.len(), 55);
    // Version.
    assert_eq!(msg[0], FACTORY_CERT_VERSION);
    assert_eq!(msg[0], 0x01);
    // product_id big-endian at 1..3.
    assert_eq!(msg[1..3], [0x00, 0x01]);
    // multi-SKU identifiers.
    assert_eq!(msg[3], 3);
    assert_eq!(msg[4], 7);
    // peer_id at 5..22.
    assert_eq!(&msg[5..22], &sample_peer_id()[..]);
    // compressed pubkey at 22..55.
    assert_eq!(&msg[22..55], &sample_compressed_pubkey()[..]);
}

#[test]
fn cert_message_rejects_invalid_inputs() {
    // Peer id wrong length.
    assert_eq!(
        build_factory_cert_message(
            ProductId::Gateway,
            1,
            1,
            &[0u8; 16],
            &sample_compressed_pubkey()
        ),
        Err(RecordError::InvalidPeerIdLen(16))
    );
    // Compressed pubkey wrong length.
    assert_eq!(
        build_factory_cert_message(ProductId::Sensor, 1, 1, &sample_peer_id(), &[0u8; 32]),
        Err(RecordError::InvalidCompressedPubkeyLen(32))
    );
}

#[test]
fn product_id_round_trips_over_the_wire_and_rejects_unknown() {
    // Known values encode/decode through the wire u16.
    for (p, wire) in [(ProductId::Sensor, 0x0001u16), (ProductId::Gateway, 0x0002)] {
        assert_eq!(p.as_u16(), wire);
        assert_eq!(p.to_be_bytes(), wire.to_be_bytes());
        assert_eq!(ProductId::from_u16(wire), Some(p));
    }
    // Unknown wire value is rejected.
    assert_eq!(ProductId::from_u16(0x0003), None);
    assert_eq!(ProductId::from_u16(0xFFFF), None);
}

#[test]
fn factory_record_round_trips_with_magic_and_reserved() {
    let rec = FactoryRecord::build(&sample_signature(), 3, 7).expect("builds");
    assert_eq!(rec.len(), FACTORY_RECORD_LEN);
    assert_eq!(rec.len(), 72);
    // Signature at 0..64.
    assert_eq!(&rec[0..64], &sample_signature()[..]);
    // Magic "SGM1" at 64..68.
    assert_eq!(&rec[64..68], b"SGM1");
    // Identifiers at 68, 69.
    assert_eq!(rec[68], 3);
    assert_eq!(rec[69], 7);
    // Reserved zero at 70..72.
    assert_eq!(&rec[70..72], &[0u8, 0]);

    let parsed = FactoryRecord::from_bytes(&rec).expect("parses");
    assert_eq!(parsed.hardware_profile_id, 3);
    assert_eq!(parsed.factory_key_id, 7);
    assert_eq!(parsed.signature_rs, sample_signature());
}

#[test]
fn factory_record_rejects_bad_magic_and_reserved() {
    let mut rec = FactoryRecord::build(&sample_signature(), 1, 1).unwrap();
    // Corrupt magic.
    rec[64] = b'X';
    assert_eq!(
        FactoryRecord::from_bytes(&rec),
        Err(RecordError::InvalidMagic(*b"XGM1"))
    );

    let mut rec = FactoryRecord::build(&sample_signature(), 1, 1).unwrap();
    // Corrupt reserved byte.
    rec[70] = 0xFF;
    assert_eq!(
        FactoryRecord::from_bytes(&rec),
        Err(RecordError::InvalidReserved([0xFF, 0]))
    );
}

#[test]
fn factory_record_rejects_wrong_signature_length() {
    assert_eq!(
        FactoryRecord::build(&[0u8; 63], 1, 1),
        Err(RecordError::InvalidSignatureLen(63))
    );
}
