use crate::com::init::DEFAULT_KEY;
use crate::com::init::gateway::Validate;
use crate::com::init::sensor::tests::helpers::{
    create_controller, simulate_sending_good_message_via_lora,
};
use crate::com::init::sensor::{Install, PUBLIC_KEY_LEN, SIGNATURE_LEN};
use crate::models::common::{Destination, MessageSchema, MessageType, ProductType, RequestType};

use lora::sx1278::tests::common::expectations_for_receiver_mode;
use lora::sx1278::{Controller, Mode};

#[test]
fn ok() {
    let nonce = [0x11; 12];
    let sensor_mac = [
        67, 56, 58, 67, 53, 58, 68, 55, 58, 48, 49, 58, 54, 50, 58, 50, 51,
    ];
    let gateway_mac = [
        26, 56, 58, 67, 53, 58, 06, 55, 58, 48, 49, 58, 54, 91, 58, 50, 51,
    ];
    let battery_level = 80;
    let mode = Mode::Manual;
    let timestamp = 260691;
    let mut request_message = MessageSchema::create_body_request(
        sensor_mac,
        battery_level,
        Destination::AllGateways,
        MessageType::InstallSensorRequest,
        RequestType::Install(Install::new(
            sensor_mac,
            ProductType::ContactSensor,
            [0u8; PUBLIC_KEY_LEN],
            [0u8; SIGNATURE_LEN],
        )),
        timestamp,
    );
    let request_buffer = request_message
        .serialize_clear::<{ crate::com::init::INIT_MESSAGE_MAX }>()
        .unwrap();
    let new_key: [u8; 32] = [0x20; 32];
    let expire_at = 220790;
    let response_message = MessageSchema::create_body_request(
        gateway_mac,
        battery_level,
        Destination::OneDestination(sensor_mac),
        MessageType::ValidateRequest,
        RequestType::Validate(Validate::new(
            new_key,
            expire_at,
            gateway_mac,
            [0u8; PUBLIC_KEY_LEN],
            [0u8; SIGNATURE_LEN],
        )),
        timestamp,
    );
    let mut expectations = simulate_sending_good_message_via_lora(
        DEFAULT_KEY,
        nonce,
        mode,
        &request_buffer,
        response_message,
        false,
    )
    .0;
    expectations.extend(expectations_for_receiver_mode());
    let (mut spi, mut cs, mut rst, mut delay) = create_controller(&expectations);

    let mut controller = Controller::new(&mut spi, &mut cs, &mut rst, &mut delay, mode).unwrap();

    let result = Install::request(
        &mut controller,
        &mut delay,
        sensor_mac,
        battery_level,
        crate::models::common::ProductType::ContactSensor,
        [0u8; PUBLIC_KEY_LEN],
        [0u8; SIGNATURE_LEN],
        timestamp,
    );
    assert_eq!(result.unwrap(), ());
    spi.done();
    cs.done();
    rst.done();
}
