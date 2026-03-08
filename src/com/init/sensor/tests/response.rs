use crate::com::init::{
    self,
    gateway::{Status, Validate, ValidateResponse},
    sensor::Install,
    sensor::tests::helpers::{
        create_controller, create_expectations, create_expectations_for_request_send_with_timeout,
    },
};
use crate::com::init::test_helpers::{dummy_pubkey, dummy_sig};
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
    let gw_pubkey = [0u8; crate::com::init::sensor::PUBLIC_KEY_LEN];
    let gw_sig = [0u8; crate::com::init::sensor::SIGNATURE_LEN];
    let valid = Validate::new(new_key, expire_at, gateway_mac, gw_pubkey, gw_sig);
    let mut request_message = MessageSchema::create_body_request(
        gateway_mac,
        0,
        OneDestination(sensor_mac),
        MessageType::ValidateRequest,
        RequestType::Validate(valid.clone()),
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
    let init = Install::new(
        sensor_mac,
        crate::models::common::ProductType::ContactSensor,
        dummy_pubkey(),
        dummy_sig(),
    );
    let result = init.response(
        &mut controller,
        &mut delay,
        nonce,
        gateway_mac,
        timestamp,
        new_key,
        expire_at,
        gw_pubkey,
        gw_sig,
    );
    assert!(result.is_ok());
    spi.done();
    cs.done();
    rst.done();
}

fn run_timeout_test() {
    use crate::com::error::model::ComError;
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
    let gw_pubkey = [0u8; crate::com::init::sensor::PUBLIC_KEY_LEN];
    let gw_sig = [0u8; crate::com::init::sensor::SIGNATURE_LEN];
    let expectations = create_expectations_for_request_send_with_timeout(
        mode, gateway_mac, sensor_mac, new_key, expire_at, gw_pubkey, gw_sig, timestamp,
    );
    let (mut spi, mut cs, mut rst, mut delay) = create_controller(&expectations);
    let mut controller = Controller::new(&mut spi, &mut cs, &mut rst, &mut delay, mode).unwrap();
    let init = Install::new(
        sensor_mac,
        crate::models::common::ProductType::ContactSensor,
        dummy_pubkey(),
        dummy_sig(),
    );
    let result = init.response(
        &mut controller,
        &mut delay,
        [0x11u8; 12],
        gateway_mac,
        timestamp,
        new_key,
        expire_at,
        gw_pubkey,
        gw_sig,
    );
    assert!(matches!(result, Err(ComError::Timeout)));
    spi.done();
    cs.done();
    rst.done();
}

#[test]
fn timeout_wrong_destination() {
    run_timeout_test();
}

#[test]
fn timeout_buffer_too_big() {
    run_timeout_test();
}

#[test]
fn timeout_deserialize_failed() {
    run_timeout_test();
}
