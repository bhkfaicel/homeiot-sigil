use crate::com::init::{
    self,
    gateway::{Status, Validate, ValidateResponse},
    sensor::tests::helpers::{create_controller, create_expectations},
    sensor::{PUBLIC_KEY_LEN, SIGNATURE_LEN},
};
use crate::models::common::{
    Destination::OneDestination, MessageSchema, MessageType, RequestType, ResponseType,
};
use lora::sx1278::{Controller, Mode};

#[test]
fn ok() {
    let sensor_mac = [
        67, 56, 58, 67, 53, 58, 68, 55, 58, 48, 49, 58, 54, 50, 58, 50, 51,
    ];
    let gateway_mac = [
        26, 56, 58, 67, 53, 58, 06, 55, 58, 48, 49, 58, 54, 91, 58, 50, 51,
    ];
    let mode = Mode::Manual;
    let new_key: [u8; 32] = [0x20; 32];
    let timestamp = 260691;
    let expire_at = 220790;
    let gw_pubkey = [0u8; PUBLIC_KEY_LEN];
    let gw_sig = [0u8; SIGNATURE_LEN];
    let valid = Validate::new(new_key, expire_at, gateway_mac, gw_pubkey, gw_sig);
    let mut request_message = MessageSchema::create_body_request(
        gateway_mac,
        0,
        OneDestination(sensor_mac),
        MessageType::ValidateRequest,
        RequestType::Validate(Validate {
            key: new_key,
            expire_at,
            gateway_mac,
            gateway_public_key: gw_pubkey,
            gateway_signature: gw_sig,
        }),
        timestamp,
    );
    let request_buffer = request_message
        .serialize_clear::<{ init::INIT_MESSAGE_MAX }>()
        .expect("serialize_clear");
    let mut response_message = MessageSchema::create_body_response(
        gateway_mac,
        sensor_mac,
        MessageType::ValidateResponse,
        ResponseType::SensorValidate(ValidateResponse {
            status: Status::Installed,
            sensor_mac,
        }),
        timestamp,
    );
    let nonce = [0u8; 12];
    let response_buffer = response_message
        .serialize::<{ init::INIT_MESSAGE_MAX }>(&new_key, &nonce, None)
        .expect("serialize");
    let expectations = create_expectations(&request_buffer, &response_buffer, mode, true);
    let (mut spi, mut cs, mut rst, mut delay) = create_controller(&expectations);
    let mut controller = Controller::new(&mut spi, &mut cs, &mut rst, &mut delay, mode).unwrap();
    let result = valid.request(
        &mut controller,
        &mut delay,
        sensor_mac,
        gateway_mac,
        timestamp,
        new_key,
        expire_at,
    );
    assert!(result.is_ok());
    spi.done();
    cs.done();
    rst.done();
}

#[test]
fn timeout_wrong_destination() {
    use crate::com::error::model::ComError;
    use crate::com::init::sensor::tests::helpers::create_expectations_for_request_send_with_timeout;
    let sensor_mac = [
        67, 56, 58, 67, 53, 58, 68, 55, 58, 48, 49, 58, 54, 50, 58, 50, 51,
    ];
    let gateway_mac = [
        26, 56, 58, 67, 53, 58, 06, 55, 58, 48, 49, 58, 54, 91, 58, 50, 51,
    ];
    let mode = Mode::Manual;
    let new_key: [u8; 32] = [0x20; 32];
    let timestamp = 260691;
    let expire_at = 220790;
    let gw_pubkey = [0u8; PUBLIC_KEY_LEN];
    let gw_sig = [0u8; SIGNATURE_LEN];
    let expectations = create_expectations_for_request_send_with_timeout(
        mode,
        gateway_mac,
        sensor_mac,
        new_key,
        expire_at,
        gw_pubkey,
        gw_sig,
        timestamp,
    );
    let (mut spi, mut cs, mut rst, mut delay) = create_controller(&expectations);
    let mut controller = Controller::new(&mut spi, &mut cs, &mut rst, &mut delay, mode).unwrap();
    let valid = Validate::new(new_key, expire_at, gateway_mac, gw_pubkey, gw_sig);
    let result = valid.request(
        &mut controller,
        &mut delay,
        sensor_mac,
        gateway_mac,
        timestamp,
        new_key,
        expire_at,
    );
    assert!(matches!(result, Err(ComError::Timeout)));
    spi.done();
    cs.done();
    rst.done();
}
