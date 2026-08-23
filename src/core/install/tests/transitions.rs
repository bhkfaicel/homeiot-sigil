//! Table-driven dispatch tests for the Install handshake transitions.
//!
//! These suites complement the scenario tests in the parent module by
//! exercising the **whole dispatch table** of `continue_install` /
//! `handle_install_request` as data:
//!
//! - every **rejected** (pending state, message type) pair fails closed with
//!   `InvalidStep` and leaves the prior valid state, its staged secrets, and
//!   its cached frame untouched (fail-atomic preservation);
//! - malformed / non-install frames are rejected at parse level before any
//!   dispatch decision or pending mutation;
//! - every **accepted** install transition (request → challenge, challenge →
//!   Final staging, duplicate challenge → cached-Final retransmission,
//!   Final → gateway commit, duplicate Final → cached-CommitConfirmed
//!   retransmission, CommitConfirmed → sensor commit) is walked over a real
//!   pairwise mock flow, including the duplicate-CommitConfirmed rejection
//!   after the sensor already committed.

use crate::core::error::SigilError;
use crate::core::event::SigilAction;
use crate::core::frame::{FRAME_TYPE_OFFSET, FrameType, PROTOCOL_VERSION, PROTOCOL_VERSION_OFFSET};
use crate::core::install::INSTALL_TIMEOUT_MS;
use crate::core::install::wire::InstallMessageType;
use crate::core::manager::SessionManager;
use crate::core::pending::{
    InstallGatewayStaged, Nonce16Stash, PendingHandshake, PendingState, ResumePskStash,
};
use crate::core::session::{DirectionalMaterial, PeerId};
use crate::core::test_support::{MockRandom, MockSecureElement};

/// Sensor MAC used by the pairwise accepted-transition walk.
const SENSOR_MAC: PeerId = [0x71u8; 17];
/// Gateway MAC used by the pairwise accepted-transition walk.
const GW_MAC: PeerId = [0x72u8; 17];
/// Peer key for the rejected-dispatch matrix (single-manager rows).
const PEER: PeerId = [7u8; 17];

/// Deterministic initiator / gateway nonce bytes for staged pendings.
const NONCE: [u8; 16] = [0x11u8; 16];
/// Deterministic second nonce (sensor side of the gateway staging).
const NONCE2: [u8; 16] = [0x22u8; 16];
/// Deterministic resume PSK staged inside secret-bearing variants.
const PSK: [u8; 32] = [0x5Au8; 32];
/// Deterministic compressed static pubkey staged in pendings.
const PUBKEY: [u8; 33] = [0x02u8; 33];
/// Deterministic session-key lifetime staged in pendings.
const LIFETIME: u32 = 86_400;
/// Host time (seconds) at which the synthetic pendings are created.
const NOW: u32 = 1_000;

/// Deterministic directional material for staged pendings.
fn material() -> DirectionalMaterial {
    DirectionalMaterial::symmetric_for_test([0xCDu8; 32], [0xEFu8; 4])
}

/// Deterministic Final frame cached inside the sensor recovery state.
fn final_frame() -> heapless::Vec<u8, 128> {
    let mut frame = heapless::Vec::<u8, 128>::new();
    for byte in 0..48u8 {
        frame.push(0xA0 ^ byte).unwrap();
    }
    frame
}

/// Deterministic CommitConfirmed frame cached inside the gateway recovery state.
fn commit_frame() -> heapless::Vec<u8, 128> {
    let mut frame = heapless::Vec::<u8, 128>::new();
    for byte in 0..40u8 {
        frame.push(0x50 ^ byte).unwrap();
    }
    frame
}

/// The four install pending states exercised by the dispatch table.
#[derive(Clone, Copy)]
enum PendingKind {
    /// Sensor: request sent, awaiting the gateway challenge.
    SensorAwaitChallenge,
    /// Sensor: Final sent, awaiting CommitConfirmed (recovery state).
    SensorFinalSent,
    /// Gateway: challenge sent, awaiting the sensor Final.
    GatewayAwaitConfirm,
    /// Gateway: CommitConfirmed sent (recovery state, cached reTX).
    GatewayCommitSent,
}

/// Observable fingerprints of the secrets, cached frames, and bookkeeping a
/// rejected transition must leave exactly as it found them.
struct Fingerprint {
    /// Stashed handshake nonce (initiator or gateway challenge nonce).
    nonce: [u8; 16],
    /// Staged resume PSK.
    psk: [u8; 32],
    /// Staged sensor → gateway AEAD key half.
    s2g_key: [u8; 32],
    /// Cached Final / CommitConfirmed frame.
    cached: heapless::Vec<u8, 128>,
    /// Absolute tick deadline (must not move on a rejected transition).
    deadline: u32,
}

impl PendingKind {
    /// Inserts a pending handshake of this kind keyed at `peer` into `mgr`
    /// and returns the fingerprints a rejected transition must preserve.
    fn insert(&self, mgr: &mut SessionManager<16>, peer: PeerId) -> Fingerprint {
        match self {
            PendingKind::SensorAwaitChallenge => {
                let pending =
                    PendingHandshake::new_install_sensor(peer, NONCE, INSTALL_TIMEOUT_MS, NOW);
                let deadline = pending.deadline_at;
                mgr.insert_pending(peer, pending).unwrap();
                Fingerprint {
                    nonce: NONCE,
                    psk: [0u8; 32],
                    s2g_key: [0u8; 32],
                    cached: heapless::Vec::new(),
                    deadline,
                }
            }
            PendingKind::SensorFinalSent => {
                let mut pending =
                    PendingHandshake::new_install_sensor(peer, NONCE, INSTALL_TIMEOUT_MS, NOW);
                pending
                    .install_sensor_stage_final(
                        material(),
                        PSK,
                        PUBKEY,
                        LIFETIME,
                        &final_frame(),
                        NOW,
                    )
                    .unwrap();
                let deadline = pending.deadline_at;
                mgr.insert_pending(peer, pending).unwrap();
                Fingerprint {
                    nonce: [0u8; 16],
                    psk: PSK,
                    s2g_key: material().s2g_key,
                    cached: final_frame(),
                    deadline,
                }
            }
            PendingKind::GatewayAwaitConfirm => {
                let staged = InstallGatewayStaged {
                    keys: material(),
                    resume_psk: ResumePskStash::new(PSK),
                    sensor_static_pubkey: PUBKEY,
                    key_lifetime_secs: LIFETIME,
                    gateway_nonce: Nonce16Stash::new(NONCE),
                    sensor_nonce: Nonce16Stash::new(NONCE2),
                };
                let pending = PendingHandshake::new_install_gateway_await_confirm(
                    peer,
                    staged,
                    INSTALL_TIMEOUT_MS,
                    NOW,
                );
                let deadline = pending.deadline_at;
                mgr.insert_pending(peer, pending).unwrap();
                Fingerprint {
                    nonce: NONCE,
                    psk: PSK,
                    s2g_key: material().s2g_key,
                    cached: heapless::Vec::new(),
                    deadline,
                }
            }
            PendingKind::GatewayCommitSent => {
                let staged = InstallGatewayStaged {
                    keys: material(),
                    resume_psk: ResumePskStash::new(PSK),
                    sensor_static_pubkey: PUBKEY,
                    key_lifetime_secs: LIFETIME,
                    gateway_nonce: Nonce16Stash::new(NONCE),
                    sensor_nonce: Nonce16Stash::new(NONCE2),
                };
                let mut pending = PendingHandshake::new_install_gateway_await_confirm(
                    peer,
                    staged,
                    INSTALL_TIMEOUT_MS,
                    NOW,
                );
                pending
                    .install_gateway_commit_sent(&commit_frame(), NOW)
                    .unwrap();
                let deadline = pending.deadline_at;
                mgr.insert_pending(peer, pending).unwrap();
                Fingerprint {
                    nonce: [0u8; 16],
                    psk: [0u8; 32],
                    s2g_key: [0u8; 32],
                    cached: commit_frame(),
                    deadline,
                }
            }
        }
    }

    /// Asserts the pending at `peer` is still exactly the same tagged state
    /// with the same secret / cache fingerprints as `before` (fail-atomic
    /// preservation on a rejected transition).
    fn assert_preserved(&self, mgr: &SessionManager<16>, peer: &PeerId, before: &Fingerprint) {
        let pending = mgr
            .get_pending(peer)
            .expect("rejected transition must keep the pending entry");
        assert_eq!(pending.deadline_at, before.deadline);
        match (self, pending.state()) {
            (
                PendingKind::SensorAwaitChallenge,
                PendingState::InstallSensorAwaitChallenge { sensor_nonce },
            ) => {
                assert_eq!(*sensor_nonce.as_array(), before.nonce);
            }
            (
                PendingKind::SensorFinalSent,
                PendingState::InstallSensorFinalSent {
                    keys,
                    resume_psk,
                    cached,
                    ..
                },
            ) => {
                assert_eq!(keys.s2g_key, before.s2g_key);
                assert_eq!(*resume_psk.as_array(), before.psk);
                assert_eq!(cached.as_slice(), before.cached.as_slice());
            }
            (
                PendingKind::GatewayAwaitConfirm,
                PendingState::InstallGatewayAwaitConfirm(staged),
            ) => {
                assert_eq!(*staged.gateway_nonce.as_array(), before.nonce);
                assert_eq!(staged.keys.s2g_key, before.s2g_key);
                assert_eq!(*staged.resume_psk.as_array(), before.psk);
            }
            (PendingKind::GatewayCommitSent, PendingState::InstallGatewayCommitSent { cached }) => {
                assert_eq!(cached.as_slice(), before.cached.as_slice());
            }
            (kind, state) => panic!(
                "rejected transition must not change the pending state: expected {:?}, got {:?}",
                kind_name(kind),
                state_name(state)
            ),
        }
    }
}

/// Short label of a pending kind for assertion messages.
fn kind_name(kind: &PendingKind) -> &'static str {
    match kind {
        PendingKind::SensorAwaitChallenge => "InstallSensorAwaitChallenge",
        PendingKind::SensorFinalSent => "InstallSensorFinalSent",
        PendingKind::GatewayAwaitConfirm => "InstallGatewayAwaitConfirm",
        PendingKind::GatewayCommitSent => "InstallGatewayCommitSent",
    }
}

/// Short label of the live tagged state for assertion messages.
fn state_name(state: &PendingState) -> &'static str {
    match state {
        PendingState::InstallSensorAwaitChallenge { .. } => "InstallSensorAwaitChallenge",
        PendingState::InstallSensorFinalSent { .. } => "InstallSensorFinalSent",
        PendingState::InstallGatewayAwaitConfirm(_) => "InstallGatewayAwaitConfirm",
        PendingState::InstallGatewayCommitSent { .. } => "InstallGatewayCommitSent",
        _ => "non-install pending state",
    }
}

/// Builds a minimal synthetic install frame of `msg` whose peer field (body
/// MAC for clear-text messages, outer header for the AEAD CommitConfirmed)
/// identifies `peer`. Dispatch-level rejection happens before any body
/// parsing, so these frames only need a structurally valid outer header.
fn synthetic_frame(msg: InstallMessageType, peer: &PeerId) -> heapless::Vec<u8, 256> {
    let frame_type = match msg {
        InstallMessageType::Request => FrameType::InstallRequest,
        InstallMessageType::Challenge => FrameType::InstallChallenge,
        InstallMessageType::Confirm => FrameType::InstallConfirm,
        InstallMessageType::CommitConfirmed => FrameType::InstallCommitConfirmed,
    } as u8;
    let mut packet = heapless::Vec::<u8, 256>::new();
    packet.extend_from_slice(peer).unwrap();
    packet.push(PROTOCOL_VERSION).unwrap();
    packet.push(frame_type).unwrap();
    if !matches!(msg, InstallMessageType::CommitConfirmed) {
        // Clear-text install bodies start with the body peer MAC; Challenge
        // additionally requires outer ≡ body for the structural pre-check.
        packet.extend_from_slice(peer).unwrap();
    }
    packet
}

#[test]
fn install_dispatch_table_rejects_invalid_state_message_pairs() {
    // Every (pending state, message type) pair that is NOT one of the five
    // accepted dispatch combinations must fail closed with InvalidStep while
    // preserving the prior valid state and its staged secrets / cache.
    use InstallMessageType as M;
    use PendingKind as K;
    let rejected: &[(K, M)] = &[
        // Sensor awaiting its challenge: only a Challenge is meaningful.
        (K::SensorAwaitChallenge, M::Request),
        (K::SensorAwaitChallenge, M::Confirm),
        (K::SensorAwaitChallenge, M::CommitConfirmed),
        // Sensor already sent its Final: only Challenge (reTX) or the
        // CommitConfirmed are meaningful.
        (K::SensorFinalSent, M::Request),
        (K::SensorFinalSent, M::Confirm),
        // Gateway awaiting the Final: only a Confirm is meaningful.
        (K::GatewayAwaitConfirm, M::Request),
        (K::GatewayAwaitConfirm, M::Challenge),
        (K::GatewayAwaitConfirm, M::CommitConfirmed),
        // Gateway already committed: only a duplicate Final (reTX) is
        // meaningful.
        (K::GatewayCommitSent, M::Request),
        (K::GatewayCommitSent, M::Challenge),
        (K::GatewayCommitSent, M::CommitConfirmed),
    ];

    for &(kind, msg) in rejected {
        let mut mgr: SessionManager<16> = crate::core::test_support::test_manager();
        let before = kind.insert(&mut mgr, PEER);

        let frame = synthetic_frame(msg, &PEER);
        let result = mgr.continue_install::<256>(&frame, &mut MockSecureElement::default(), NOW);

        assert_eq!(
            result,
            Err(SigilError::InvalidStep { peer: PEER }),
            "dispatch table must reject {:?} + {:?}",
            kind_name(&kind),
            msg
        );
        // Fail-atomic: the prior valid state, secrets, cache, and deadline
        // all survive the rejected transition untouched.
        kind.assert_preserved(&mgr, &PEER, &before);
    }
}

#[test]
fn install_dispatch_table_rejects_malformed_frames_before_dispatch() {
    // Malformed / non-install frames must fail at parse level before any
    // dispatch decision or pending mutation, in every pending state.
    use PendingKind as K;

    // Truncated frame (shorter than the outer header) and a well-formed
    // outer header carrying a non-install frame type (Data).
    let mut data_frame = heapless::Vec::<u8, 256>::new();
    data_frame.extend_from_slice(&PEER).unwrap();
    data_frame.push(PROTOCOL_VERSION).unwrap();
    data_frame.push(FrameType::Data as u8).unwrap();
    let malformed: &[&[u8]] = &[&[0u8; 10], &data_frame];

    for kind in [
        K::SensorAwaitChallenge,
        K::SensorFinalSent,
        K::GatewayAwaitConfirm,
        K::GatewayCommitSent,
    ] {
        for frame in malformed {
            let mut mgr: SessionManager<16> = crate::core::test_support::test_manager();
            let before = kind.insert(&mut mgr, PEER);

            let result = mgr.continue_install::<256>(frame, &mut MockSecureElement::default(), NOW);
            assert_eq!(
                result,
                Err(SigilError::MalformedFrame),
                "non-install / truncated frames must reject as malformed in {:?}",
                kind_name(&kind)
            );
            kind.assert_preserved(&mgr, &PEER, &before);
        }
    }
}

/// Which real pairwise frame an accepted-transition row consumes.
#[derive(Clone, Copy)]
enum FrameSel {
    /// The sensor's initial InstallRequest.
    Request,
    /// The gateway's InstallChallenge.
    Challenge,
    /// The sensor's InstallConfirm (Final).
    Confirm,
    /// The gateway's InstallCommitConfirmed.
    Commit,
}

/// The expected outcome of one accepted-transition table row.
#[derive(Clone, Copy)]
enum Expected {
    /// Gateway accepts the request: emits the challenge and stages the
    /// gateway await-confirm pending.
    GatewayAcceptsRequest,
    /// Sensor accepts the challenge: stages Final (recovery state) and
    /// transmits the confirm.
    SensorStagesFinal,
    /// Sensor receives a duplicate challenge after Final: retransmits the
    /// cached Final byte-exactly without re-running crypto.
    SensorRetransmitsFinal,
    /// Gateway accepts the Final: commits the session, emits
    /// PersistPeerStaticKey with the CommitConfirmed follow-up TX.
    GatewayCommits,
    /// Gateway receives a duplicate Final after commit: retransmits the
    /// cached CommitConfirmed byte-exactly.
    GatewayRetransmitsCommit,
    /// Sensor accepts the CommitConfirmed: inserts the session, emits
    /// PersistPeerStaticKey, clears its pending.
    SensorCommits,
    /// Sensor receives a duplicate CommitConfirmed after committing: its
    /// pending is gone, so the frame is rejected with NoPending.
    SensorDuplicateCommitRejected,
}

#[test]
fn install_dispatch_table_accepted_transitions() {
    // Walks every accepted install transition as table rows over one real
    // pairwise mock flow. Frames produced by a row become the input of later
    // rows; retransmission rows assert byte-exact equality with the original.
    let table: &[(&str, FrameSel, Expected)] = &[
        (
            "no gateway pending + Request -> challenge + AwaitConfirm",
            FrameSel::Request,
            Expected::GatewayAcceptsRequest,
        ),
        (
            "SensorAwaitChallenge + Challenge -> Final staged + FinalSent",
            FrameSel::Challenge,
            Expected::SensorStagesFinal,
        ),
        (
            "SensorFinalSent + duplicate Challenge -> reTX cached Final",
            FrameSel::Challenge,
            Expected::SensorRetransmitsFinal,
        ),
        (
            "GatewayAwaitConfirm + Confirm -> commit + CommitSent",
            FrameSel::Confirm,
            Expected::GatewayCommits,
        ),
        (
            "GatewayCommitSent + duplicate Confirm -> reTX cached CommitConfirmed",
            FrameSel::Confirm,
            Expected::GatewayRetransmitsCommit,
        ),
        (
            "SensorFinalSent + CommitConfirmed -> session + Persist",
            FrameSel::Commit,
            Expected::SensorCommits,
        ),
        (
            "sensor pending cleared + duplicate CommitConfirmed -> NoPending",
            FrameSel::Commit,
            Expected::SensorDuplicateCommitRejected,
        ),
    ];

    let mut sensor: SessionManager<16> =
        crate::core::test_support::test_manager_with_mac(SENSOR_MAC);
    let mut gateway: SessionManager<16> = crate::core::test_support::test_manager_with_mac(GW_MAC);
    let mut se_sensor = MockSecureElement::sensor(1, SENSOR_MAC);
    let mut se_gateway = MockSecureElement::gateway(2, GW_MAC);
    let mut rng_sensor = MockRandom::new();
    let mut rng_gateway = MockRandom::new();

    // Pre-amble: the sensor starts install (covered by scenario tests); its
    // request frame feeds the first table row.
    let request = match sensor
        .start_install::<256>(GW_MAC, &mut se_sensor, &mut rng_sensor, NOW)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!("start_install must transmit the request"),
    };

    // Real frames collected while the rows execute.
    let mut challenge = heapless::Vec::<u8, 256>::new();
    let mut confirm = heapless::Vec::<u8, 256>::new();
    let mut commit = heapless::Vec::<u8, 256>::new();

    for &(label, sel, expected) in table {
        // Clone the selected frame so producing new frames cannot alias the
        // borrowed input within the same iteration.
        let frame = match sel {
            FrameSel::Request => request.clone(),
            FrameSel::Challenge => challenge.clone(),
            FrameSel::Confirm => confirm.clone(),
            FrameSel::Commit => commit.clone(),
        };

        match expected {
            Expected::GatewayAcceptsRequest => {
                let action = gateway
                    .handle_install_request::<256>(
                        &frame,
                        &mut se_gateway,
                        &mut rng_gateway,
                        NOW,
                        LIFETIME,
                    )
                    .unwrap_or_else(|e| panic!("{label}: {e:?}"));
                match action {
                    SigilAction::Transmit { dest, payload, .. } => {
                        assert_eq!(dest, SENSOR_MAC, "{label}");
                        assert_eq!(
                            payload[FRAME_TYPE_OFFSET],
                            FrameType::InstallChallenge as u8,
                            "{label}"
                        );
                        assert_eq!(
                            payload[PROTOCOL_VERSION_OFFSET], PROTOCOL_VERSION,
                            "{label}"
                        );
                        challenge = payload;
                    }
                    _ => panic!("{label}: gateway must transmit the challenge"),
                }
                assert!(
                    matches!(
                        gateway.get_pending(&SENSOR_MAC).unwrap().state(),
                        PendingState::InstallGatewayAwaitConfirm(_)
                    ),
                    "{label}: gateway pending must await the sensor Final"
                );
            }
            Expected::SensorStagesFinal => {
                let action = sensor
                    .continue_install::<256>(&frame, &mut se_sensor, NOW)
                    .unwrap_or_else(|e| panic!("{label}: {e:?}"));
                match action {
                    SigilAction::Transmit { dest, payload, .. } => {
                        assert_eq!(dest, GW_MAC, "{label}");
                        assert_eq!(
                            payload[FRAME_TYPE_OFFSET],
                            FrameType::InstallConfirm as u8,
                            "{label}"
                        );
                        confirm = payload;
                    }
                    _ => panic!("{label}: sensor must transmit the Final"),
                }
                // Final staged: recovery state caches exactly the frame sent.
                match sensor.get_pending(&GW_MAC).unwrap().state() {
                    PendingState::InstallSensorFinalSent { cached, .. } => {
                        assert_eq!(cached.as_slice(), confirm.as_slice(), "{label}");
                    }
                    _ => panic!("{label}: sensor pending must be FinalSent"),
                }
                // Commit ordering: no session before CommitConfirmed.
                assert!(sensor.get(&GW_MAC).is_none(), "{label}");
            }
            Expected::SensorRetransmitsFinal => {
                let action = sensor
                    .continue_install::<256>(&frame, &mut se_sensor, NOW)
                    .unwrap_or_else(|e| panic!("{label}: {e:?}"));
                match action {
                    SigilAction::Transmit { dest, payload, .. } => {
                        assert_eq!(dest, GW_MAC, "{label}");
                        // Idempotent reTX: byte-exact cached Final, no re-sign.
                        assert_eq!(payload.as_slice(), confirm.as_slice(), "{label}");
                    }
                    _ => panic!("{label}: duplicate challenge must reTX the Final"),
                }
                assert!(
                    matches!(
                        sensor.get_pending(&GW_MAC).unwrap().state(),
                        PendingState::InstallSensorFinalSent { .. }
                    ),
                    "{label}: reTX must keep the FinalSent recovery state"
                );
                assert!(sensor.get(&GW_MAC).is_none(), "{label}");
            }
            Expected::GatewayCommits => {
                let action = gateway
                    .continue_install::<256>(&frame, &mut se_gateway, NOW)
                    .unwrap_or_else(|e| panic!("{label}: {e:?}"));
                match action {
                    SigilAction::PersistPeerStaticKey {
                        peer,
                        transmit,
                        wait_timeout_ms,
                        ..
                    } => {
                        assert_eq!(peer, SENSOR_MAC, "{label}");
                        assert!(!transmit.is_empty(), "{label}");
                        assert!(wait_timeout_ms.is_some(), "{label}");
                        assert_eq!(
                            transmit[FRAME_TYPE_OFFSET],
                            FrameType::InstallCommitConfirmed as u8,
                            "{label}"
                        );
                        commit = transmit;
                    }
                    _ => panic!("{label}: gateway Final must Persist + CommitConfirmed TX"),
                }
                assert!(
                    matches!(
                        gateway.get_pending(&SENSOR_MAC).unwrap().state(),
                        PendingState::InstallGatewayCommitSent { .. }
                    ),
                    "{label}: gateway pending must keep CommitSent for reTX"
                );
                assert!(
                    gateway.get(&SENSOR_MAC).is_some(),
                    "{label}: gateway commits the session at Final"
                );
            }
            Expected::GatewayRetransmitsCommit => {
                let action = gateway
                    .continue_install::<256>(&frame, &mut se_gateway, NOW)
                    .unwrap_or_else(|e| panic!("{label}: {e:?}"));
                match action {
                    SigilAction::PersistPeerStaticKey { transmit, .. } => {
                        // Idempotent reTX: byte-exact cached CommitConfirmed.
                        assert_eq!(transmit.as_slice(), commit.as_slice(), "{label}");
                    }
                    _ => panic!("{label}: duplicate Final must reTX the CommitConfirmed"),
                }
                assert!(
                    matches!(
                        gateway.get_pending(&SENSOR_MAC).unwrap().state(),
                        PendingState::InstallGatewayCommitSent { .. }
                    ),
                    "{label}"
                );
            }
            Expected::SensorCommits => {
                let action = sensor
                    .continue_install::<256>(&frame, &mut se_sensor, NOW)
                    .unwrap_or_else(|e| panic!("{label}: {e:?}"));
                match action {
                    SigilAction::PersistPeerStaticKey {
                        peer,
                        transmit,
                        resume_psk,
                        ..
                    } => {
                        assert_eq!(peer, GW_MAC, "{label}");
                        // The sensor sends no follow-up frame at commit.
                        assert!(transmit.is_empty(), "{label}");
                        assert_eq!(
                            Some(*resume_psk.expose_secret()),
                            sensor.get(&GW_MAC).unwrap().resume_psk().copied(),
                            "{label}"
                        );
                    }
                    _ => panic!("{label}: sensor commit must Persist"),
                }
                assert!(
                    sensor.get(&GW_MAC).unwrap().session_key().is_some(),
                    "{label}: sensor session must be active"
                );
                assert!(
                    sensor.get_pending(&GW_MAC).is_none(),
                    "{label}: sensor pending must clear at commit"
                );
            }
            Expected::SensorDuplicateCommitRejected => {
                let result = sensor.continue_install::<256>(&frame, &mut se_sensor, NOW);
                assert_eq!(
                    result,
                    Err(SigilError::NoPending { peer: GW_MAC }),
                    "{label}: duplicate CommitConfirmed after commit has no pending left"
                );
                // The committed session is unaffected by the duplicate.
                assert!(
                    sensor.get(&GW_MAC).unwrap().session_key().is_some(),
                    "{label}"
                );
            }
        }
    }

    // The walk must have produced and consumed every real frame.
    assert!(!challenge.is_empty());
    assert!(!confirm.is_empty());
    assert!(!commit.is_empty());
}
