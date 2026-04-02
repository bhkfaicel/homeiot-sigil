#[cfg(test)]
mod tests {
    const DEFAULT_KEY: [u8; 32] = [0x26; 32];

    use crate::com::event::message::Event;
    use crate::com::event::{response, send};
    use crate::com::handshake::sensor::tests::helpers::create_controller;
    use crate::com::keys::KeyManager;
    use crate::models::common::Destination::OneDestination;
    use crate::models::common::TIMESTAMP_NOT_AVAILABLE;
    use crate::models::common::{MessageSchema, MessageType, RequestType, ResponseType, Status};

    use lora::sx1278::tests::common::{expectations_for_new, expectations_for_send};
    use lora::sx1278::{Controller, Mode};

    #[test]
    fn send_event_ok() {
        let nonce = [0xAA; 12];
        let sensor_mac = [
            67, 56, 58, 67, 53, 58, 68, 55, 58, 48, 49, 58, 54, 50, 58, 50, 51,
        ];
        let destination = [
            26, 56, 58, 67, 53, 58, 06, 55, 58, 48, 49, 58, 54, 91, 58, 50, 51,
        ];
        let battery_level = 78;
        let event = Event::is_open(true);
        let mode = Mode::Receiver;
        let timestamp = 1234567890;
        let key_manager = KeyManager::new(DEFAULT_KEY, sensor_mac);
        let event_key = key_manager.derive_usage_key(b"event");

        let mut message = MessageSchema::create_body_request(
            sensor_mac,
            battery_level,
            OneDestination(destination),
            MessageType::Event,
            RequestType::Event(event),
            timestamp,
        );
        let buffer = message
            .serialize::<255>(&event_key, &nonce, None)
            .expect("serialize");
        let mut expectations = expectations_for_new(mode);
        expectations.extend(expectations_for_send(&buffer, mode));
        let (mut spi, mut cs, mut rst, mut delay) = create_controller(&expectations);
        let mut controller =
            Controller::new(&mut spi, &mut cs, &mut rst, &mut delay, mode).unwrap();
        let result = send(
            &mut controller,
            &mut delay,
            nonce,
            event_key,
            sensor_mac,
            battery_level,
            event,
            destination,
            timestamp,
        );
        assert!(result.is_ok());
        spi.done();
        cs.done();
        rst.done();
    }

    #[test]
    fn send_event_response_ok() {
        let nonce = [0xBB; 12];
        let src_mac = [
            26, 56, 58, 67, 53, 58, 06, 55, 58, 48, 49, 58, 54, 91, 58, 50, 51,
        ];
        let dist_mac = [
            67, 56, 58, 67, 53, 58, 68, 55, 58, 48, 49, 58, 54, 50, 58, 50, 51,
        ];
        let status = Status::Ok;
        let mode = Mode::Receiver;
        let timestamp = 677892231;
        let key_manager = KeyManager::new(DEFAULT_KEY, src_mac);
        let event_key = key_manager.derive_usage_key(b"event");

        let mut message = MessageSchema::create_body_response(
            dist_mac,
            src_mac,
            MessageType::EventResponse,
            ResponseType::Event(crate::models::common::Ack {
                status,
                device_mac: dist_mac,
            }),
            timestamp,
        );
        let buffer = message
            .serialize::<255>(&event_key, &nonce, None)
            .expect("serialize");
        let mut expectations = expectations_for_new(mode);
        expectations.extend(expectations_for_send(&buffer, mode));
        let (mut spi, mut cs, mut rst, mut delay) = create_controller(&expectations);
        let mut controller =
            Controller::new(&mut spi, &mut cs, &mut rst, &mut delay, mode).unwrap();
        let result = response(
            &mut controller,
            &mut delay,
            nonce,
            event_key,
            src_mac,
            dist_mac,
            status,
            timestamp,
        );
        assert!(result.is_ok());
        spi.done();
        cs.done();
        rst.done();
    }

    #[test]
    fn send_event_vibration_count_ok() {
        let nonce = [0xCC; 12];
        let sensor_mac = [
            67, 56, 58, 67, 53, 58, 68, 55, 58, 48, 49, 58, 54, 50, 58, 50, 51,
        ];
        let destination = [
            26, 56, 58, 67, 53, 58, 06, 55, 58, 48, 49, 58, 54, 91, 58, 50, 51,
        ];
        let battery_level = 85;
        use crate::com::event::message::TimeUnit;
        let event = Event::vibration_count(5, 5, TimeUnit::Seconds, false);
        let mode = Mode::Receiver;
        let key_manager = KeyManager::new(DEFAULT_KEY, sensor_mac);
        let event_key = key_manager.derive_usage_key(b"event");

        let mut message = MessageSchema::create_body_request(
            sensor_mac,
            battery_level,
            OneDestination(destination),
            MessageType::Event,
            RequestType::Event(event),
            TIMESTAMP_NOT_AVAILABLE,
        );
        let buffer = message
            .serialize::<255>(&event_key, &nonce, None)
            .expect("serialize");
        let mut expectations = expectations_for_new(mode);
        expectations.extend(expectations_for_send(&buffer, mode));
        let (mut spi, mut cs, mut rst, mut delay) = create_controller(&expectations);
        let mut controller =
            Controller::new(&mut spi, &mut cs, &mut rst, &mut delay, mode).unwrap();
        let result = send(
            &mut controller,
            &mut delay,
            nonce,
            event_key,
            sensor_mac,
            battery_level,
            event,
            destination,
            TIMESTAMP_NOT_AVAILABLE,
        );
        assert!(result.is_ok());
        spi.done();
        cs.done();
        rst.done();
    }
}
