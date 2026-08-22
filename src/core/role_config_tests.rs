//! Tests that intentionally run when only one production role is enabled.

#![cfg(test)]

use crate::core::event::SigilAction;
use crate::core::manager::SessionManager;
use crate::core::test_support::{MockRandom, MockSecureElement, test_manager_with_mac};

#[cfg(feature = "sensor")]
use crate::core::session::{DirectionalMaterial, Session, SessionRole};

const SENSOR_MAC: [u8; 17] = [0x31; 17];
const GATEWAY_MAC: [u8; 17] = [0x32; 17];
#[cfg(feature = "sensor")]
const RESUME_PSK: [u8; 32] = [0x5a; 32];

#[test]
fn manager_rejects_a_malformed_factory_root() {
    assert!(matches!(
        SessionManager::<2>::new([0u8; 33], SENSOR_MAC),
        Err(crate::core::error::SigilError::InvalidStaticKey)
    ));
}

#[cfg(feature = "sensor")]
#[test]
fn sensor_only_drives_install_renew_and_resume_entrypoints() {
    let mut install_manager: SessionManager<2> = test_manager_with_mac(SENSOR_MAC);
    let mut se = MockSecureElement::sensor(1, SENSOR_MAC);
    let mut rng = MockRandom::new();
    assert!(matches!(
        install_manager
            .start_install::<256>(
                crate::core::install::INSTALL_DISCOVERY_DEST,
                &mut se,
                &mut rng,
                1
            )
            .unwrap(),
        SigilAction::Transmit { .. }
    ));

    let material = DirectionalMaterial::symmetric_for_test([0x11; 32], [0x22; 4]);
    let mut renew_manager: SessionManager<2> = test_manager_with_mac(SENSOR_MAC);
    renew_manager
        .insert(
            Session::new_active(
                GATEWAY_MAC,
                [0x02; 33],
                material,
                SessionRole::Sensor,
                RESUME_PSK,
                10_000,
                0,
            )
            .unwrap(),
        )
        .unwrap();
    assert!(matches!(
        renew_manager.start_renew::<256>(GATEWAY_MAC, 1).unwrap(),
        SigilAction::Transmit { .. }
    ));

    let mut resume_manager: SessionManager<2> = test_manager_with_mac(SENSOR_MAC);
    resume_manager
        .insert(
            Session::new_enrolled(GATEWAY_MAC, [0x02; 33], RESUME_PSK, SessionRole::Sensor)
                .unwrap(),
        )
        .unwrap();
    assert!(matches!(
        resume_manager
            .start_resume::<256>(GATEWAY_MAC, &mut se, &mut rng, 1)
            .unwrap(),
        SigilAction::Transmit { .. }
    ));
}

#[cfg(feature = "gateway")]
#[test]
fn gateway_only_accepts_a_valid_install_request() {
    use crate::core::install::wire::{InstallRequest, build_install_request};
    use crate::core::traits::SecureElement;

    let mut gateway: SessionManager<2> = test_manager_with_mac(GATEWAY_MAC);
    let mut sensor_se = MockSecureElement::sensor(1, SENSOR_MAC);
    let sensor_pubkey = sensor_se.get_static_pubkey().unwrap();
    let metadata = sensor_se.get_factory_cert_metadata().unwrap();
    let sensor_nonce = [0x44; 16];
    let signed = crate::core::install::install_request_sign_message(
        &SENSOR_MAC,
        metadata,
        &sensor_pubkey,
        &sensor_nonce,
    )
    .unwrap();
    let request = InstallRequest {
        sensor_peer_mac: SENSOR_MAC,
        hardware_profile_id: metadata.hardware_profile_id,
        factory_key_id: metadata.factory_key_id,
        sensor_static_pubkey: sensor_pubkey,
        factory_cert_sig: sensor_se.get_factory_cert().unwrap(),
        sensor_nonce,
        sensor_signature: sensor_se.sign_ecdsa(&signed).unwrap(),
    };

    let mut gateway_se = MockSecureElement::gateway(2, GATEWAY_MAC);
    let mut rng = MockRandom::new();
    assert!(matches!(
        gateway
            .handle_install_request::<256>(
                &build_install_request(&request).unwrap(),
                &mut gateway_se,
                &mut rng,
                1,
                3_600,
            )
            .unwrap(),
        SigilAction::Transmit { .. }
    ));
    assert_eq!(gateway.pending_len(), 1);
}
