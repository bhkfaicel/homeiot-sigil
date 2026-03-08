use lora::sx1278::{
    Controller, Mode,
    tests::common::{expectations_for_new, expectations_for_send},
};

use crate::{
    com::init::{
        gateway::{Keys, Status, Validate, ValidateResponse},
        sensor::{PUBLIC_KEY_LEN, SIGNATURE_LEN},
        sensor::tests::helpers::create_controller,
    },
    models::common::{MessageSchema, MessageType, ResponseType},
};

#[test]
fn ok() {
    let nonce = [0x11; 12];
    let sensor_mac = [
        67, 56, 58, 67, 53, 58, 68, 55, 58, 48, 49, 58, 54, 50, 58, 50, 51,
    ];
    let gateway_mac = [
        26, 56, 58, 67, 53, 58, 06, 55, 58, 48, 49, 58, 54, 91, 58, 50, 51,
    ];
    let mode = Mode::Manual;
    let key: [u8; 32] = [0x20; 32];
    let timestamp = 260691;
    let expire_at = 220790;

    let mut response_message = MessageSchema::create_body_response(
        gateway_mac,
        sensor_mac,
        MessageType::ValidateResponse,
        ResponseType::SensorValidate(ValidateResponse {
            status: Status::Installed,
            sensor_mac: sensor_mac,
        }),
        timestamp,
    );
    let response_buffer = response_message
        .serialize::<{ crate::com::init::INIT_MESSAGE_MAX }>(&key, &nonce, None)
        .unwrap();
    let mut expectations = expectations_for_new(mode);
    expectations.extend(expectations_for_send(&response_buffer, mode));
    let (mut spi, mut cs, mut rst, mut delay) = create_controller(&expectations);

    let mut controller = Controller::new(&mut spi, &mut cs, &mut rst, &mut delay, mode).unwrap();
    let valid = Validate::new(key, expire_at, gateway_mac, [0u8; PUBLIC_KEY_LEN], [0u8; SIGNATURE_LEN]);
    let response = valid.response(&mut controller, &mut delay, nonce, sensor_mac, timestamp);
    let expected_response = Keys {
        key,
        expire_at,
        timestamp,
    };
    assert_eq!(response.unwrap(), expected_response);
    spi.done();
    cs.done();
    rst.done();
}
