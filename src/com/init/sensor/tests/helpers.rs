use crate::com::init::gateway::Validate;
use crate::com::init::sensor::{PUBLIC_KEY_LEN, SIGNATURE_LEN};
use crate::com::init::INIT_MESSAGE_MAX;
use crate::models::common::ResponseType;
use crate::models::common::{MessageSchema, MessageType};
use alloc::vec;
use embedded_hal_mock::eh1::delay::NoopDelay;
use embedded_hal_mock::eh1::digital::{
    Mock as PinMock, State as PinState, Transaction as PinTransaction,
};
use embedded_hal_mock::eh1::spi::{Mock as SpiMock, Transaction as SpiTransaction};
use lora::sx1278::Mode;
use lora::sx1278::tests::common::{
    expectations_for_new, expectations_for_receive_no_packet, expectations_for_receive_success,
    expectations_for_receiver_mode, expectations_for_send,
};

/// Expectations for when send() returns MessageTooLong (no send SPI; returns before idle()).
pub fn create_expectations_for_message_too_long(mode: Mode) -> vec::Vec<SpiTransaction<u8>> {
    expectations_for_new(mode)
}

/// Expectations for gateway Validate request send (no receive): new + send path.
pub fn create_expectations_for_request_send(
    mode: Mode,
    gateway_mac: [u8; 17],
    sensor_mac: [u8; 17],
    new_key: [u8; 32],
    expire_at: u32,
    gw_pubkey: [u8; PUBLIC_KEY_LEN],
    gw_sig: [u8; SIGNATURE_LEN],
    timestamp: u32,
) -> vec::Vec<SpiTransaction<u8>> {
    use crate::models::common::{Destination::OneDestination, MessageSchema, MessageType, RequestType};
    let mut message = MessageSchema::create_body_request(
        gateway_mac,
        0,
        OneDestination(sensor_mac),
        MessageType::ValidateRequest,
        RequestType::Validate(Validate::new(
            new_key,
            expire_at,
            gateway_mac,
            gw_pubkey,
            gw_sig,
        )),
        timestamp,
    );
    let buffer = message
        .serialize_clear::<{ INIT_MESSAGE_MAX }>()
        .expect("serialize_clear");
    let mut expectations = expectations_for_new(mode);
    expectations.extend(expectations_for_send(&buffer, mode));
    expectations
}

/// Same as create_expectations_for_request_send plus 4× receive NoPacket (for timeout tests).
pub fn create_expectations_for_request_send_with_timeout(
    mode: Mode,
    gateway_mac: [u8; 17],
    sensor_mac: [u8; 17],
    new_key: [u8; 32],
    expire_at: u32,
    gw_pubkey: [u8; PUBLIC_KEY_LEN],
    gw_sig: [u8; SIGNATURE_LEN],
    timestamp: u32,
) -> vec::Vec<SpiTransaction<u8>> {
    let mut expectations = create_expectations_for_request_send(
        mode, gateway_mac, sensor_mac, new_key, expire_at, gw_pubkey, gw_sig, timestamp,
    );
    // Validate::request: set_mode(Receiver) after send() (2 writes), then 4× receive() (NoPacket)
    expectations.extend(expectations_for_receiver_mode());
    // Each receive() in this timeout scenario returns `NoPacket` and calls `restore_mode()`,
    // which for `Receiver` re-applies RX_CONTINUOUS + DIO mapping.
    expectations.extend(expectations_for_receive_no_packet(4, Mode::Receiver));
    expectations
}

/// Expectations for init response (ValidateResponse) send: new + send path.
pub fn create_expectations_for_response_send(
    mode: Mode,
    gateway_mac: [u8; 17],
    sensor_mac: [u8; 17],
    new_key: [u8; 32],
    nonce: [u8; 12],
    timestamp: u32,
) -> vec::Vec<SpiTransaction<u8>> {
    use crate::com::init::gateway::{Status, ValidateResponse};
    use crate::models::common::{MessageSchema, MessageType, ResponseType};
    let mut message = MessageSchema::create_body_response(
        gateway_mac,
        sensor_mac,
        MessageType::ValidateResponse,
        ResponseType::SensorValidate(ValidateResponse {
            status: Status::Installed,
            sensor_mac,
        }),
        timestamp,
    );
    let buffer = message
        .serialize::<{ INIT_MESSAGE_MAX }>(&new_key, &nonce, None)
        .expect("serialize");
    let mut expectations = expectations_for_new(mode);
    expectations.extend(expectations_for_send(&buffer, mode));
    expectations
}

pub fn create_expectations(
    request_buffer: &[u8],
    response_buffer: &[u8],
    mode: Mode,
    with_response: bool,
) -> vec::Vec<SpiTransaction<u8>> {
    let mut expectations = expectations_for_new(mode);
    let expectations_for_send = expectations_for_send(request_buffer, mode);
    expectations.extend(expectations_for_send);
    if with_response {
        let expectations_for_response = create_expectations_for_recieve(response_buffer);
        expectations.extend(expectations_for_response);
    }
    expectations
}

pub fn create_expectations_for_recieve(response_buffer: &[u8]) -> vec::Vec<SpiTransaction<u8>> {
    let mut expectations: vec::Vec<SpiTransaction<u8>> = vec![];
    expectations.extend(expectations_for_receiver_mode());
    expectations.extend(expectations_for_receive_success::<{ INIT_MESSAGE_MAX }>(
        &response_buffer,
        0x42,
        Mode::Receiver,
    ));
    expectations
}

pub fn simulate_sending_good_message_via_lora(
    key: [u8; 32],
    nonce: [u8; 12],
    mode: Mode,
    request_buffer: &[u8],
    mut response_message: MessageSchema,
    with_response: bool,
) -> (vec::Vec<SpiTransaction<u8>>, [u8; INIT_MESSAGE_MAX]) {
    let response_buffer = response_message
        .serialize::<{ INIT_MESSAGE_MAX }>(&key, &nonce, None)
        .unwrap();
    let expectations = create_expectations(request_buffer, &response_buffer, mode, with_response);
    (expectations, response_buffer)
}

pub fn simulate_sending_bad_message_via_lora(
    sensor_mac: [u8; 17],
    gateway_mac: [u8; 17],
    new_key: [u8; 32],
    expire_at: u32,
    timestamp: u32,
    key: [u8; 32],
    nonce: [u8; 12],
    mode: Mode,
    request_buffer: &[u8],
    with_response: bool,
) -> (vec::Vec<SpiTransaction<u8>>, [u8; INIT_MESSAGE_MAX]) {
    let mut response_message = MessageSchema::create_body_response(
        sensor_mac,
        gateway_mac,
        MessageType::InstallResponse,
        ResponseType::Validate(Validate::new(new_key, expire_at, gateway_mac, [0u8; PUBLIC_KEY_LEN], [0u8; SIGNATURE_LEN])),
        timestamp,
    );
    let mut response_buffer = response_message
        .serialize::<{ INIT_MESSAGE_MAX }>(&key, &nonce, None)
        .unwrap();
    response_buffer[100] = 30;
    let expectations = create_expectations(request_buffer, &response_buffer, mode, with_response);
    (expectations, response_buffer)
}

pub fn create_controller(
    expectations: &[SpiTransaction<u8>],
) -> (
    embedded_hal_mock::common::Generic<SpiTransaction<u8>>,
    embedded_hal_mock::common::Generic<PinTransaction>,
    embedded_hal_mock::common::Generic<PinTransaction>,
    NoopDelay,
) {
    let spi = SpiMock::new(expectations);

    let mut cs_actions = vec![];
    for _ in 0..expectations.len() {
        cs_actions.push(PinTransaction::set(PinState::Low));
        cs_actions.push(PinTransaction::set(PinState::High));
    }
    let cs = PinMock::new(&cs_actions);

    let rst = PinMock::new(&[
        PinTransaction::set(PinState::Low),
        PinTransaction::set(PinState::High),
    ]);

    let delay = NoopDelay::new();

    (spi, cs, rst, delay)
}
