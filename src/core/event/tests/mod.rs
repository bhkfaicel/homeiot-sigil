#![cfg(test)]

//! Unit tests for event and action types
//!
//! These tests verify both the default LoRa capacities and custom (non-default)
//! generic capacities, demonstrating the configurability of the event/action
//! types for different transport maximums.

mod type_size_bounds;

use crate::core::event::{DATA_MAX, MSG_MAX, ResumePskSecret, SigilAction, SigilEvent};
use heapless::Vec;

#[test]
fn test_event_data() {
    let peer = [1u8; 17];
    let mut payload: Vec<u8, DATA_MAX> = Vec::new();
    payload.push(0x42).unwrap();
    payload.push(0x43).unwrap();

    let event = SigilEvent::<DATA_MAX, MSG_MAX>::Data {
        peer,
        payload: payload.clone(),
    };

    match event {
        SigilEvent::Data {
            peer: p,
            payload: pl,
        } => {
            assert_eq!(p, peer);
            assert_eq!(pl, payload);
        }
        _ => panic!("Unexpected event type"),
    }
}

#[test]
fn test_event_data_custom_size() {
    // Verify that a non-default capacity (12 bytes, e.g. Sigfox) compiles and works
    let peer = [1u8; 17];
    let mut payload: Vec<u8, 12> = Vec::new();
    payload.push(0xAB).unwrap();

    let event = SigilEvent::<12, 64>::Data {
        peer,
        payload: payload.clone(),
    };

    match event {
        SigilEvent::Data {
            peer: p,
            payload: pl,
        } => {
            assert_eq!(p, peer);
            assert_eq!(pl, payload);
        }
        _ => panic!("Unexpected event type"),
    }
}

#[test]
fn test_reliable_event_and_ack_types() {
    let peer = [1u8; 17];
    let mut payload: Vec<u8, DATA_MAX> = Vec::new();
    payload.extend_from_slice(b"door-open").unwrap();
    let event = SigilEvent::<DATA_MAX, MSG_MAX>::Event {
        peer,
        event_id: 42,
        payload,
        duplicate: false,
    };
    assert!(matches!(
        event,
        SigilEvent::Event {
            peer: p,
            event_id: 42,
            duplicate: false,
            ..
        } if p == peer
    ));
    let ack = SigilEvent::<DATA_MAX, MSG_MAX>::EventAck { peer, event_id: 42 };
    assert!(matches!(ack, SigilEvent::EventAck { event_id: 42, .. }));
}

#[test]
fn test_time_sync_request_type() {
    let peer = [0x33u8; 17];
    let event = SigilEvent::<DATA_MAX, MSG_MAX>::TimeSyncRequest { peer };
    assert!(matches!(
        event,
        SigilEvent::TimeSyncRequest { peer: p } if p == peer
    ));
}

#[test]
fn test_action_transmit() {
    let dest = [1u8; 17];
    let mut payload: Vec<u8, MSG_MAX> = Vec::new();
    payload.push(0x42).unwrap();

    let action = SigilAction::<MSG_MAX>::Transmit {
        dest,
        payload: payload.clone(),
        wait_timeout_ms: Some(1000),
    };

    match action {
        SigilAction::Transmit {
            dest: d,
            payload: pl,
            wait_timeout_ms,
        } => {
            assert_eq!(d, dest);
            assert_eq!(pl, payload);
            assert_eq!(wait_timeout_ms, Some(1000));
        }
        _ => panic!("Unexpected action type"),
    }
}

#[test]
fn test_action_transmit_custom_size() {
    // Verify that a compact action type (64 bytes) compiles and works
    let dest = [1u8; 17];
    let mut payload: Vec<u8, 64> = Vec::new();
    payload.push(0x99).unwrap();

    let action = SigilAction::<64>::Transmit {
        dest,
        payload: payload.clone(),
        wait_timeout_ms: None,
    };

    match action {
        SigilAction::Transmit {
            dest: d,
            payload: pl,
            wait_timeout_ms,
        } => {
            assert_eq!(d, dest);
            assert_eq!(pl, payload);
            assert!(wait_timeout_ms.is_none());
        }
        _ => panic!("Unexpected action type"),
    }
}

#[test]
fn test_action_success() {
    let peer = [1u8; 17];
    let action = SigilAction::<MSG_MAX>::Success { peer };
    match action {
        SigilAction::Success { peer: p } => assert_eq!(p, peer),
        _ => panic!("Unexpected action type"),
    }
}

#[test]
fn test_action_persist_peer_static_key() {
    let peer = [1u8; 17];
    let pubkey = [2u8; 33];
    let resume_psk = [0x5Au8; 32];

    let action = SigilAction::<MSG_MAX>::PersistPeerStaticKey {
        peer,
        pubkey,
        resume_psk: ResumePskSecret::new(resume_psk),
        transmit: heapless::Vec::new(),
        wait_timeout_ms: None,
    };

    match action {
        SigilAction::PersistPeerStaticKey {
            peer: p,
            pubkey: pk,
            resume_psk: psk,
            transmit,
            wait_timeout_ms,
        } => {
            assert_eq!(p, peer);
            assert_eq!(pk, pubkey);
            assert_eq!(psk.expose_secret(), &resume_psk);
            assert!(transmit.is_empty());
            assert!(wait_timeout_ms.is_none());
        }
        _ => panic!("Unexpected action type"),
    }
}

#[test]
fn test_debug_redacts_resume_psk_and_plaintext_payloads() {
    let secret = [0x5Au8; 32];
    let action = SigilAction::<MSG_MAX>::PersistPeerStaticKey {
        peer: [1u8; 17],
        pubkey: [2u8; 33],
        resume_psk: ResumePskSecret::new(secret),
        transmit: heapless::Vec::new(),
        wait_timeout_ms: None,
    };
    let action_debug = alloc::format!("{action:?}");
    assert!(action_debug.contains("[REDACTED]"));
    assert!(!action_debug.contains("90, 90, 90"));

    let mut payload = Vec::<u8, DATA_MAX>::new();
    payload.extend_from_slice(b"private-door-state").unwrap();
    let event = SigilEvent::<DATA_MAX, MSG_MAX>::Data {
        peer: [3u8; 17],
        payload,
    };
    let event_debug = alloc::format!("{event:?}");
    assert!(event_debug.contains("[REDACTED; 18 bytes]"));
    assert!(!event_debug.contains("private-door-state"));
}

#[test]
fn test_debug_covers_every_event_variant_without_exposing_frames() {
    let peer = [7u8; 17];
    let mut frame = Vec::<u8, MSG_MAX>::new();
    frame.extend_from_slice(b"wire-secret-marker").unwrap();
    let events = alloc::vec![
        SigilEvent::<DATA_MAX, MSG_MAX>::Event {
            peer,
            event_id: 1,
            payload: Vec::new(),
            duplicate: false,
        },
        SigilEvent::EventAck { peer, event_id: 1 },
        SigilEvent::TimeSync {
            peer,
            gateway_time: 2,
            sync_sequence: 3,
            uncertainty_secs: 4,
        },
        SigilEvent::TimeSyncRequest { peer },
        SigilEvent::InstallRequest {
            peer,
            frame: frame.clone(),
        },
        SigilEvent::InstallChallenge {
            peer,
            frame: frame.clone(),
        },
        SigilEvent::InstallConfirm {
            peer,
            frame: frame.clone(),
        },
        SigilEvent::RenewRequest {
            peer,
            frame: frame.clone(),
        },
        SigilEvent::RenewChallenge {
            peer,
            frame: frame.clone(),
        },
        SigilEvent::RenewConfirm {
            peer,
            frame: frame.clone(),
        },
        SigilEvent::ResumeRequest {
            peer,
            frame: frame.clone(),
        },
        SigilEvent::ResumeChallenge {
            peer,
            frame: frame.clone(),
        },
        SigilEvent::ResumeConfirm {
            peer,
            frame: frame.clone(),
        },
        SigilEvent::InstallCommitConfirmed {
            peer,
            frame: frame.clone(),
        },
        SigilEvent::RenewCommitConfirmed {
            peer,
            frame: frame.clone(),
        },
        SigilEvent::ResumeCommitConfirmed { peer, frame },
    ];

    for event in events {
        let output = alloc::format!("{event:?}");
        assert!(!output.contains("wire-secret-marker"));
        if output.contains("frame") {
            assert!(output.contains("[REDACTED; 18 bytes]"));
        }
    }
}

#[test]
fn test_action_needs_host_dispatch() {
    // Classification pairs with NeedsHostDispatch — not Success.
    let peer = [7u8; 17];
    let action = SigilAction::<MSG_MAX>::NeedsHostDispatch { peer };
    match action {
        SigilAction::NeedsHostDispatch { peer: p } => assert_eq!(p, peer),
        _ => panic!("Unexpected action type"),
    }
}

#[test]
fn test_event_install_steps() {
    // Per-step install variants carry the raw frame in MSG capacity.
    let peer = [1u8; 17];
    let mut frame: Vec<u8, MSG_MAX> = Vec::new();
    frame.push(0x01).unwrap();
    frame.push(0x02).unwrap();

    let req = SigilEvent::<DATA_MAX, MSG_MAX>::InstallRequest {
        peer,
        frame: frame.clone(),
    };
    let chal = SigilEvent::<DATA_MAX, MSG_MAX>::InstallChallenge {
        peer,
        frame: frame.clone(),
    };
    let conf = SigilEvent::<DATA_MAX, MSG_MAX>::InstallConfirm {
        peer,
        frame: frame.clone(),
    };

    match req {
        SigilEvent::InstallRequest { peer: p, frame: f } => {
            assert_eq!(p, peer);
            assert_eq!(f, frame);
        }
        _ => panic!("Unexpected event type"),
    }
    assert!(matches!(chal, SigilEvent::InstallChallenge { .. }));
    assert!(matches!(conf, SigilEvent::InstallConfirm { .. }));
    let commit = SigilEvent::<DATA_MAX, MSG_MAX>::InstallCommitConfirmed {
        peer,
        frame: frame.clone(),
    };
    assert!(matches!(commit, SigilEvent::InstallCommitConfirmed { .. }));
}

#[test]
fn test_event_renew_steps() {
    let peer = [2u8; 17];
    let mut frame: Vec<u8, MSG_MAX> = Vec::new();
    frame.push(0x11).unwrap();

    let req = SigilEvent::<DATA_MAX, MSG_MAX>::RenewRequest {
        peer,
        frame: frame.clone(),
    };
    let chal = SigilEvent::<DATA_MAX, MSG_MAX>::RenewChallenge {
        peer,
        frame: frame.clone(),
    };
    let ack = SigilEvent::<DATA_MAX, MSG_MAX>::RenewConfirm {
        peer,
        frame: frame.clone(),
    };

    match req {
        SigilEvent::RenewRequest { peer: p, frame: f } => {
            assert_eq!(p, peer);
            assert_eq!(f, frame);
        }
        _ => panic!("Unexpected event type"),
    }
    assert!(matches!(chal, SigilEvent::RenewChallenge { .. }));
    assert!(matches!(ack, SigilEvent::RenewConfirm { .. }));
    let commit = SigilEvent::<DATA_MAX, MSG_MAX>::RenewCommitConfirmed {
        peer,
        frame: frame.clone(),
    };
    assert!(matches!(commit, SigilEvent::RenewCommitConfirmed { .. }));
}

#[test]
fn test_event_resume_steps() {
    let peer = [3u8; 17];
    let mut frame: Vec<u8, MSG_MAX> = Vec::new();
    frame.push(0x21).unwrap();

    let req = SigilEvent::<DATA_MAX, MSG_MAX>::ResumeRequest {
        peer,
        frame: frame.clone(),
    };
    let chal = SigilEvent::<DATA_MAX, MSG_MAX>::ResumeChallenge {
        peer,
        frame: frame.clone(),
    };
    let conf = SigilEvent::<DATA_MAX, MSG_MAX>::ResumeConfirm {
        peer,
        frame: frame.clone(),
    };

    match req {
        SigilEvent::ResumeRequest { peer: p, frame: f } => {
            assert_eq!(p, peer);
            assert_eq!(f, frame);
        }
        _ => panic!("Unexpected event type"),
    }
    assert!(matches!(chal, SigilEvent::ResumeChallenge { .. }));
    assert!(matches!(conf, SigilEvent::ResumeConfirm { .. }));
    let commit = SigilEvent::<DATA_MAX, MSG_MAX>::ResumeCommitConfirmed {
        peer,
        frame: frame.clone(),
    };
    assert!(matches!(commit, SigilEvent::ResumeCommitConfirmed { .. }));
}
