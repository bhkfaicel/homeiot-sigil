//! Table-driven dispatch tests for the Resume handshake transitions.
//!
//! These suites complement the scenario tests in the parent module by
//! exercising the **whole dispatch table** of `continue_resume` /
//! `handle_resume_request` as data.
//!
//! # Dispatch grid (explicit cell count)
//!
//! Unlike install / renew, resume routes **both** the sensor and the gateway
//! message handling through the single `continue_resume` entry point, so its
//! grid is the complete (pending state × resume message type) cross product:
//! 4 states × 4 message types = **16 cells**:
//!
//! - **5 accepted** cells: (SensorAwaitChallenge, Challenge),
//!   (SensorFinalSent, Challenge → cached-Final retransmission),
//!   (SensorFinalSent, CommitConfirmed), (GatewayAwaitConfirm, Confirm),
//!   (GatewayCommitSent, Confirm → cached-CommitConfirmed retransmission);
//! - **11 rejected** cells: every other combination, asserted below with
//!   fail-atomic fingerprints.
//!
//! Non-resume frame types never reach the table: they are rejected at
//! parse level before the pending lookup (exercised by the malformed-frame
//! suite below). Non-resume pending variants fall through the same
//! `_ => Invalid` catch-all as the 11 rejected rows, so the 16 resume cells
//! plus the parse gate cover the observable dispatch behavior.
//!
//! The suites below verify that:
//!
//! - every **rejected** (pending state, message type) pair fails closed with
//!   `InvalidStep` and leaves the prior valid state, its staged secrets, and
//!   its cached frame untouched (fail-atomic preservation);
//! - malformed / non-resume frames are rejected at parse level before any
//!   dispatch decision or pending mutation;
//! - every **accepted** resume transition (request → challenge, challenge →
//!   Final staging, duplicate challenge → cached-Final retransmission,
//!   Final → gateway commit, duplicate Final → cached-CommitConfirmed
//!   retransmission, CommitConfirmed → sensor commit) is walked over a real
//!   pairwise mock flow, including the duplicate-CommitConfirmed rejection
//!   after the sensor already committed;
//! - the entry guards of `start_resume` reject without replacing pending
//!   state, and the sensor-side stale-recovery replacement is fail-atomic
//!   when the fresh request cannot be built (the gateway-side analog is
//!   proven by the scenario test for the failed ECDH replacement);
//! - the CommitConfirmed counter-must-be-zero rule is enforced without
//!   consuming the sensor recovery state.

use crate::core::aead;
use crate::core::error::SigilError;
use crate::core::event::SigilAction;
use crate::core::frame::{
    FRAME_TYPE_OFFSET, FrameType, PROTOCOL_VERSION, PROTOCOL_VERSION_OFFSET, build_header,
};
use crate::core::manager::SessionManager;
use crate::core::pending::{PendingHandshake, PendingState};
use crate::core::resume::RESUME_TIMEOUT_MS;
use crate::core::session::{DirectionalMaterial, PeerId, Session, SessionRole};
use crate::core::test_support::{
    FailingRandom, MockRandom, MockSecureElement, test_manager, test_manager_with_mac,
};

/// Sensor MAC used by the pairwise accepted-transition walk.
const SENSOR_MAC: PeerId = [0x83u8; 17];
/// Gateway MAC used by the pairwise accepted-transition walk.
const GW_MAC: PeerId = [0x84u8; 17];
/// Peer key for the rejected-dispatch matrix (single-manager rows).
const PEER: PeerId = [7u8; 17];

/// Deterministic durable resume PSK shared by the enrolled managers.
const RESUME_PSK: [u8; 32] = [0x5Au8; 32];
/// Deterministic peer static pubkey staged in the enrolled sessions.
const STATIC_PUB: [u8; 33] = [2u8; 33];
/// Deterministic request nonce stashed in the sensor await-challenge state.
const NONCE: [u8; 16] = [0x31u8; 16];
/// Deterministic session-key lifetime staged in pendings / challenges.
const LIFETIME: u32 = 86_400;
/// Host time (seconds) at which the synthetic pendings and flows are created.
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

/// Sensor-side manager enrolled towards the gateway (post-reboot shape: peer
/// static pubkey + durable resume PSK known, no session key).
fn enrolled_sensor_manager() -> SessionManager<16> {
    let mut manager = test_manager_with_mac(SENSOR_MAC);
    manager
        .insert(Session::new_enrolled(GW_MAC, STATIC_PUB, RESUME_PSK, SessionRole::Sensor).unwrap())
        .unwrap();
    manager
}

/// Gateway-side manager enrolled towards the sensor (post-reboot shape).
fn enrolled_gateway_manager() -> SessionManager<16> {
    let mut manager = test_manager_with_mac(GW_MAC);
    manager
        .insert(
            Session::new_enrolled(SENSOR_MAC, STATIC_PUB, RESUME_PSK, SessionRole::Gateway)
                .unwrap(),
        )
        .unwrap();
    manager
}

/// Extracts the transmitted payload from an action (fails otherwise).
fn transmitted(action: SigilAction<256>) -> heapless::Vec<u8, 256> {
    match action {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!("expected transmit"),
    }
}

/// The four resume pending states exercised by the dispatch table.
#[derive(Clone, Copy)]
enum PendingKind {
    /// Sensor: request sent, awaiting the gateway challenge. Owns the
    /// request nonce until the challenge arrives.
    SensorAwaitChallenge,
    /// Sensor: Final sent, awaiting CommitConfirmed (recovery state).
    SensorFinalSent,
    /// Gateway: challenge sent, awaiting the sensor Final. Owns the
    /// directional material derived from the static↔static ECDH.
    GatewayAwaitConfirm,
    /// Gateway: CommitConfirmed sent (recovery state, cached reTX).
    GatewayCommitSent,
}

/// Observable fingerprints of the secrets, cached frames, and bookkeeping a
/// rejected transition must leave exactly as it found them.
struct Fingerprint {
    /// Stashed request nonce (sensor await-challenge state).
    nonce: [u8; 16],
    /// Staged sensor → gateway AEAD key half (recovery / gateway states).
    s2g_key: [u8; 32],
    /// Agreed session-key lifetime in seconds.
    lifetime: u32,
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
                    PendingHandshake::new_resume_sensor(peer, NONCE, RESUME_TIMEOUT_MS, NOW);
                let deadline = pending.deadline_at;
                mgr.insert_pending(peer, pending).unwrap();
                Fingerprint {
                    nonce: NONCE,
                    s2g_key: [0u8; 32],
                    lifetime: 0,
                    cached: heapless::Vec::new(),
                    deadline,
                }
            }
            PendingKind::SensorFinalSent => {
                let mut pending =
                    PendingHandshake::new_resume_sensor(peer, NONCE, RESUME_TIMEOUT_MS, NOW);
                pending
                    .resume_sensor_stage_final(material(), LIFETIME, &final_frame(), NOW)
                    .unwrap();
                let deadline = pending.deadline_at;
                mgr.insert_pending(peer, pending).unwrap();
                Fingerprint {
                    nonce: [0u8; 16],
                    s2g_key: material().s2g_key,
                    lifetime: LIFETIME,
                    cached: final_frame(),
                    deadline,
                }
            }
            PendingKind::GatewayAwaitConfirm => {
                let pending = PendingHandshake::new_resume_gateway_await_confirm(
                    peer,
                    material(),
                    LIFETIME,
                    RESUME_TIMEOUT_MS,
                    NOW,
                );
                let deadline = pending.deadline_at;
                mgr.insert_pending(peer, pending).unwrap();
                Fingerprint {
                    nonce: [0u8; 16],
                    s2g_key: material().s2g_key,
                    lifetime: LIFETIME,
                    cached: heapless::Vec::new(),
                    deadline,
                }
            }
            PendingKind::GatewayCommitSent => {
                let mut pending = PendingHandshake::new_resume_gateway_await_confirm(
                    peer,
                    material(),
                    LIFETIME,
                    RESUME_TIMEOUT_MS,
                    NOW,
                );
                pending
                    .resume_gateway_commit_sent(&commit_frame(), NOW)
                    .unwrap();
                let deadline = pending.deadline_at;
                mgr.insert_pending(peer, pending).unwrap();
                Fingerprint {
                    nonce: [0u8; 16],
                    s2g_key: [0u8; 32],
                    lifetime: 0,
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
                PendingState::ResumeSensorAwaitChallenge { sensor_nonce },
            ) => {
                assert_eq!(*sensor_nonce.as_array(), before.nonce);
            }
            (
                PendingKind::SensorFinalSent,
                PendingState::ResumeSensorFinalSent {
                    keys,
                    key_lifetime_secs,
                    cached,
                },
            ) => {
                assert_eq!(keys.s2g_key, before.s2g_key);
                assert_eq!(*key_lifetime_secs, before.lifetime);
                assert_eq!(cached.as_slice(), before.cached.as_slice());
            }
            (
                PendingKind::GatewayAwaitConfirm,
                PendingState::ResumeGatewayAwaitConfirm {
                    keys,
                    key_lifetime_secs,
                },
            ) => {
                assert_eq!(keys.s2g_key, before.s2g_key);
                assert_eq!(*key_lifetime_secs, before.lifetime);
            }
            (PendingKind::GatewayCommitSent, PendingState::ResumeGatewayCommitSent { cached }) => {
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
        PendingKind::SensorAwaitChallenge => "ResumeSensorAwaitChallenge",
        PendingKind::SensorFinalSent => "ResumeSensorFinalSent",
        PendingKind::GatewayAwaitConfirm => "ResumeGatewayAwaitConfirm",
        PendingKind::GatewayCommitSent => "ResumeGatewayCommitSent",
    }
}

/// Short label of the live tagged state for assertion messages.
fn state_name(state: &PendingState) -> &'static str {
    match state {
        PendingState::ResumeSensorAwaitChallenge { .. } => "ResumeSensorAwaitChallenge",
        PendingState::ResumeSensorFinalSent { .. } => "ResumeSensorFinalSent",
        PendingState::ResumeGatewayAwaitConfirm { .. } => "ResumeGatewayAwaitConfirm",
        PendingState::ResumeGatewayCommitSent { .. } => "ResumeGatewayCommitSent",
        _ => "non-resume pending state",
    }
}

/// Builds a minimal synthetic resume frame of `frame_type` for `peer`.
/// Dispatch-level rejection happens before any body parsing or decryption,
/// so these frames only need a structurally valid outer header.
fn synthetic_frame(frame_type: FrameType, peer: &PeerId) -> heapless::Vec<u8, 256> {
    let mut packet = heapless::Vec::<u8, 256>::new();
    packet
        .extend_from_slice(&build_header(peer, frame_type))
        .unwrap();
    packet
}

/// Builds a header-length frame whose frame-type byte is unknown.
fn unknown_type_frame(peer: &PeerId) -> heapless::Vec<u8, 256> {
    let mut packet = heapless::Vec::<u8, 256>::new();
    packet.extend_from_slice(peer).unwrap();
    packet.push(PROTOCOL_VERSION).unwrap();
    packet.push(0xFF).unwrap();
    packet
}

#[test]
fn resume_dispatch_table_rejects_invalid_state_message_pairs() {
    // Every (pending state, message type) pair that is NOT one of the five
    // accepted dispatch combinations must fail closed with InvalidStep while
    // preserving the prior valid state and its staged secrets / cache.
    //
    // The accepted pairs (covered by the pairwise walk below and by the
    // scenario tests) are (SensorAwaitChallenge, Challenge),
    // (SensorFinalSent, Challenge → cached-Final reTX),
    // (SensorFinalSent, CommitConfirmed), (GatewayAwaitConfirm, Confirm) and
    // (GatewayCommitSent, Confirm → cached-CommitConfirmed reTX). The 11 rows
    // below are every other cell of the 4-state × 4-message grid
    // (11 rejected + 5 accepted = 16 cells).
    use FrameType as M;
    use PendingKind as K;
    let rejected: &[(K, M)] = &[
        // Sensor awaiting its challenge: only a Challenge is meaningful.
        (K::SensorAwaitChallenge, M::ResumeRequest),
        (K::SensorAwaitChallenge, M::ResumeConfirm),
        (K::SensorAwaitChallenge, M::ResumeCommitConfirmed),
        // Sensor already sent its Final: only a Challenge (reTX) or the
        // CommitConfirmed are meaningful.
        (K::SensorFinalSent, M::ResumeRequest),
        (K::SensorFinalSent, M::ResumeConfirm),
        // Gateway awaiting the Final: only a Confirm is meaningful.
        (K::GatewayAwaitConfirm, M::ResumeRequest),
        (K::GatewayAwaitConfirm, M::ResumeChallenge),
        (K::GatewayAwaitConfirm, M::ResumeCommitConfirmed),
        // Gateway already committed: only a duplicate Confirm (reTX) is
        // meaningful.
        (K::GatewayCommitSent, M::ResumeRequest),
        (K::GatewayCommitSent, M::ResumeChallenge),
        (K::GatewayCommitSent, M::ResumeCommitConfirmed),
    ];

    for &(kind, msg) in rejected {
        let mut mgr: SessionManager<16> = test_manager();
        let before = kind.insert(&mut mgr, PEER);

        let frame = synthetic_frame(msg, &PEER);
        let result = mgr.continue_resume::<256>(&frame, &mut MockSecureElement::default(), NOW);

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
fn resume_dispatch_table_rejects_malformed_frames_before_dispatch() {
    // Malformed / non-resume frames must fail at parse level before any
    // dispatch decision or pending mutation, in every pending state and
    // through every resume entry point.
    use PendingKind as K;

    // Truncated frame (shorter than the peer MAC) and well-formed outer
    // headers carrying either an unknown frame-type byte or a known
    // non-resume frame type (Data).
    let mut data_frame = heapless::Vec::<u8, 256>::new();
    data_frame.extend_from_slice(&PEER).unwrap();
    data_frame.push(PROTOCOL_VERSION).unwrap();
    data_frame.push(FrameType::Data as u8).unwrap();
    let truncated: &[u8] = &[0u8; 10];

    for kind in [
        K::SensorAwaitChallenge,
        K::SensorFinalSent,
        K::GatewayAwaitConfirm,
        K::GatewayCommitSent,
    ] {
        // Shared dispatch entry point (`continue_resume`, used by both
        // roles): truncation, unknown frame-type bytes, and known non-resume
        // frame types are parse failures before the pending lookup.
        for malformed in [
            truncated,
            unknown_type_frame(&PEER).as_slice(),
            data_frame.as_slice(),
        ] {
            let mut mgr: SessionManager<16> = test_manager();
            let before = kind.insert(&mut mgr, PEER);

            let result =
                mgr.continue_resume::<256>(malformed, &mut MockSecureElement::default(), NOW);
            assert_eq!(
                result,
                Err(SigilError::MalformedFrame),
                "dispatch entry point must reject malformed input in {:?}",
                kind_name(&kind)
            );
            kind.assert_preserved(&mgr, &PEER, &before);
        }

        // Gateway request entry point: truncation and any frame other than a
        // full ResumeRequest are parse failures before session or pending
        // work.
        for malformed in [
            truncated,
            synthetic_frame(FrameType::ResumeChallenge, &PEER).as_slice(),
        ] {
            let mut mgr: SessionManager<16> = test_manager();
            let before = kind.insert(&mut mgr, PEER);

            let result = mgr.handle_resume_request::<256>(
                malformed,
                &mut MockSecureElement::default(),
                &mut MockRandom::new(),
                NOW,
                LIFETIME,
            );
            assert_eq!(
                result,
                Err(SigilError::MalformedFrame),
                "gateway request entry point must reject malformed input in {:?}",
                kind_name(&kind)
            );
            kind.assert_preserved(&mgr, &PEER, &before);
        }
    }
}

/// Which real pairwise frame an accepted-transition row consumes.
#[derive(Clone, Copy)]
enum FrameSel {
    /// The sensor's initial ResumeRequest.
    Request,
    /// The gateway's ResumeChallenge.
    Challenge,
    /// The sensor's ResumeConfirm (Final).
    Confirm,
    /// The gateway's ResumeCommitConfirmed.
    Commit,
}

/// The expected outcome of one accepted-transition table row.
#[derive(Clone, Copy)]
enum Expected {
    /// Gateway accepts the request: emits the challenge and stages the
    /// gateway await-confirm pending owning the directional material.
    GatewayAcceptsRequest,
    /// Sensor accepts the challenge: stages Final (recovery state) and
    /// transmits the confirm under the new s2g half.
    SensorStagesFinal,
    /// Sensor receives a duplicate challenge after Final: retransmits the
    /// cached Final byte-exactly without re-running crypto.
    SensorRetransmitsFinal,
    /// Gateway accepts the Final: commits the resumed key, emits the
    /// CommitConfirmed, and keeps the cached frame for idempotent reTX.
    GatewayCommits,
    /// Gateway receives a duplicate Final after commit: retransmits the
    /// cached CommitConfirmed byte-exactly.
    GatewayRetransmitsCommit,
    /// Sensor accepts the CommitConfirmed: installs the resumed key, resets
    /// the counters, and clears its pending.
    SensorCommits,
    /// Sensor receives a duplicate CommitConfirmed after committing: its
    /// pending is gone, so the frame is rejected with NoPending.
    SensorDuplicateCommitRejected,
}

#[test]
fn resume_dispatch_table_accepted_transitions() {
    // Walks every accepted resume transition as table rows over one real
    // pairwise mock flow. Frames produced by a row become the input of later
    // rows; retransmission rows assert byte-exact equality with the original.
    let table: &[(&str, FrameSel, Expected)] = &[
        (
            "no gateway pending + ResumeRequest -> challenge + AwaitConfirm",
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
            "SensorFinalSent + CommitConfirmed -> resumed session",
            FrameSel::Commit,
            Expected::SensorCommits,
        ),
        (
            "sensor pending cleared + duplicate CommitConfirmed -> NoPending",
            FrameSel::Commit,
            Expected::SensorDuplicateCommitRejected,
        ),
    ];

    let mut sensor = enrolled_sensor_manager();
    let mut gateway = enrolled_gateway_manager();
    let mut sensor_se = MockSecureElement::default();
    let mut gateway_se = MockSecureElement::default();
    let mut sensor_rng = MockRandom::new();
    let mut gateway_rng = MockRandom::new();

    // Pre-amble: the sensor starts resume (covered by scenario tests); its
    // request frame feeds the first table row.
    let request = transmitted(
        sensor
            .start_resume::<256>(GW_MAC, &mut sensor_se, &mut sensor_rng, NOW)
            .unwrap_or_else(|e| panic!("start_resume: {e:?}")),
    );

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
                    .handle_resume_request::<256>(
                        &frame,
                        &mut gateway_se,
                        &mut gateway_rng,
                        NOW,
                        LIFETIME,
                    )
                    .unwrap_or_else(|e| panic!("{label}: {e:?}"));
                match action {
                    SigilAction::Transmit {
                        dest,
                        payload,
                        wait_timeout_ms,
                    } => {
                        assert_eq!(dest, SENSOR_MAC, "{label}");
                        assert_eq!(
                            payload[FRAME_TYPE_OFFSET],
                            FrameType::ResumeChallenge as u8,
                            "{label}"
                        );
                        assert_eq!(
                            payload[PROTOCOL_VERSION_OFFSET], PROTOCOL_VERSION,
                            "{label}"
                        );
                        assert!(wait_timeout_ms.is_some(), "{label}");
                        challenge = payload;
                    }
                    _ => panic!("{label}: gateway must transmit the challenge"),
                }
                // The tagged gateway state owns the directional material
                // derived from the static↔static ECDH plus the agreed
                // lifetime until the sensor Final.
                match gateway.get_pending(&SENSOR_MAC).unwrap().state() {
                    PendingState::ResumeGatewayAwaitConfirm {
                        key_lifetime_secs, ..
                    } => {
                        assert_eq!(*key_lifetime_secs, LIFETIME, "{label}");
                    }
                    _ => panic!("{label}: gateway pending must await the sensor Final"),
                }
                // The enrolled (rebooted) gateway still has no session key
                // until the Final commits.
                assert!(
                    gateway.get(&SENSOR_MAC).unwrap().session_key().is_none(),
                    "{label}"
                );
            }
            Expected::SensorStagesFinal => {
                let action = sensor
                    .continue_resume::<256>(&frame, &mut sensor_se, NOW)
                    .unwrap_or_else(|e| panic!("{label}: {e:?}"));
                match action {
                    SigilAction::Transmit { dest, payload, .. } => {
                        assert_eq!(dest, GW_MAC, "{label}");
                        assert_eq!(
                            payload[FRAME_TYPE_OFFSET],
                            FrameType::ResumeConfirm as u8,
                            "{label}"
                        );
                        confirm = payload;
                    }
                    _ => panic!("{label}: sensor must transmit the Final"),
                }
                // Final staged: the recovery state caches exactly the frame
                // sent and carries the authenticated lifetime; the variant
                // swap consumed the stashed request nonce by construction.
                match sensor.get_pending(&GW_MAC).unwrap().state() {
                    PendingState::ResumeSensorFinalSent {
                        keys,
                        key_lifetime_secs,
                        cached,
                    } => {
                        assert_eq!(*key_lifetime_secs, LIFETIME, "{label}");
                        assert_eq!(cached.as_slice(), confirm.as_slice(), "{label}");
                        // The staged halves match the gateway's stashed
                        // material (same static↔static ECDH + HKDF info).
                        match gateway.get_pending(&SENSOR_MAC).unwrap().state() {
                            PendingState::ResumeGatewayAwaitConfirm { keys: gw_keys, .. } => {
                                assert_eq!(keys.s2g_key, gw_keys.s2g_key, "{label}");
                            }
                            _ => panic!("{label}: gateway pending must still await Final"),
                        }
                    }
                    _ => panic!("{label}: sensor pending must be FinalSent"),
                }
                // Commit ordering: no session key before CommitConfirmed.
                assert!(
                    sensor.get(&GW_MAC).unwrap().session_key().is_none(),
                    "{label}"
                );
            }
            Expected::SensorRetransmitsFinal => {
                let action = sensor
                    .continue_resume::<256>(&frame, &mut sensor_se, NOW)
                    .unwrap_or_else(|e| panic!("{label}: {e:?}"));
                match action {
                    SigilAction::Transmit { dest, payload, .. } => {
                        assert_eq!(dest, GW_MAC, "{label}");
                        // Idempotent reTX: byte-exact cached Final, no re-run
                        // of the secure-element ECDH.
                        assert_eq!(payload.as_slice(), confirm.as_slice(), "{label}");
                    }
                    _ => panic!("{label}: duplicate challenge must reTX the Final"),
                }
                assert!(
                    matches!(
                        sensor.get_pending(&GW_MAC).unwrap().state(),
                        PendingState::ResumeSensorFinalSent { .. }
                    ),
                    "{label}: reTX must keep the FinalSent recovery state"
                );
                assert!(
                    sensor.get(&GW_MAC).unwrap().session_key().is_none(),
                    "{label}"
                );
            }
            Expected::GatewayCommits => {
                let action = gateway
                    .continue_resume::<256>(&frame, &mut gateway_se, NOW)
                    .unwrap_or_else(|e| panic!("{label}: {e:?}"));
                match action {
                    SigilAction::Transmit { dest, payload, .. } => {
                        assert_eq!(dest, SENSOR_MAC, "{label}");
                        assert_eq!(
                            payload[FRAME_TYPE_OFFSET],
                            FrameType::ResumeCommitConfirmed as u8,
                            "{label}"
                        );
                        commit = payload;
                    }
                    _ => panic!("{label}: gateway Final must transmit the CommitConfirmed"),
                }
                // Commit transition consumed the await-confirm variant (the
                // directional material stash is zeroized by the swap) and
                // kept the cached CommitConfirmed for idempotent reTX.
                match gateway.get_pending(&SENSOR_MAC).unwrap().state() {
                    PendingState::ResumeGatewayCommitSent { cached } => {
                        assert_eq!(cached.as_slice(), commit.as_slice(), "{label}");
                    }
                    _ => panic!("{label}: gateway pending must keep CommitSent for reTX"),
                }
                // Session committed at Final: resumed key on the gateway's
                // local clock epoch, fresh counters (Confirm used the new
                // s2g counter 0, CommitConfirmed the new g2s counter 0).
                let session = gateway.get(&SENSOR_MAC).unwrap();
                assert!(session.session_key().is_some(), "{label}");
                assert_eq!(session.key_expire_at(), NOW + LIFETIME, "{label}");
                assert_eq!(session.rx_counter, 1, "{label}");
                assert_eq!(session.tx_counter, 1, "{label}");
            }
            Expected::GatewayRetransmitsCommit => {
                let action = gateway
                    .continue_resume::<256>(&frame, &mut gateway_se, NOW)
                    .unwrap_or_else(|e| panic!("{label}: {e:?}"));
                match action {
                    SigilAction::Transmit { dest, payload, .. } => {
                        assert_eq!(dest, SENSOR_MAC, "{label}");
                        // Idempotent reTX: byte-exact cached CommitConfirmed.
                        assert_eq!(payload.as_slice(), commit.as_slice(), "{label}");
                    }
                    _ => panic!("{label}: duplicate Final must reTX the CommitConfirmed"),
                }
                assert!(
                    matches!(
                        gateway.get_pending(&SENSOR_MAC).unwrap().state(),
                        PendingState::ResumeGatewayCommitSent { .. }
                    ),
                    "{label}"
                );
            }
            Expected::SensorCommits => {
                let action = sensor
                    .continue_resume::<256>(&frame, &mut sensor_se, NOW)
                    .unwrap_or_else(|e| panic!("{label}: {e:?}"));
                match action {
                    SigilAction::Success { peer } => assert_eq!(peer, GW_MAC, "{label}"),
                    _ => panic!("{label}: sensor commit must return Success"),
                }
                // Resumed session mirrors the gateway's directional halves
                // on the sensor's own clock epoch; CommitConfirmed consumed
                // the new g2s counter 0, hence rx 1.
                let sensor_session = sensor.get(&GW_MAC).unwrap();
                let gateway_session = gateway.get(&SENSOR_MAC).unwrap();
                assert_eq!(
                    sensor_session.session_key(),
                    gateway_session.rx_session_key(),
                    "{label}"
                );
                assert_eq!(
                    sensor_session.rx_session_key(),
                    gateway_session.session_key(),
                    "{label}"
                );
                assert_eq!(sensor_session.key_expire_at(), NOW + LIFETIME, "{label}");
                assert_eq!(sensor_session.tx_counter, 1, "{label}");
                assert_eq!(sensor_session.rx_counter, 1, "{label}");
                assert!(
                    sensor.get_pending(&GW_MAC).is_none(),
                    "{label}: sensor pending must clear at commit"
                );
            }
            Expected::SensorDuplicateCommitRejected => {
                let result = sensor.continue_resume::<256>(&frame, &mut sensor_se, NOW);
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

#[test]
fn resume_entry_guards_reject_without_mutation() {
    // Entry guards of the sensor `start_resume`: each rejection must leave
    // the enrolled session and any pending state exactly as they were. The
    // gateway-side guards (cooldown, in-flight pending, MAC-before-ECDH,
    // role) and the gateway stale-commit replacement are covered by the
    // scenario tests in the parent module.
    use PendingKind as K;

    // Existing non-recovery pending: only the sensor FinalSent recovery
    // state may be replaced by a fresh authenticated request; every other
    // resume pending (including cross-role gateway states on this manager)
    // blocks the restart and survives it untouched.
    for kind in [
        K::SensorAwaitChallenge,
        K::GatewayAwaitConfirm,
        K::GatewayCommitSent,
    ] {
        let mut mgr = enrolled_sensor_manager();
        let before = kind.insert(&mut mgr, GW_MAC);
        assert_eq!(
            mgr.start_resume::<256>(
                GW_MAC,
                &mut MockSecureElement::default(),
                &mut MockRandom::new(),
                NOW
            ),
            Err(SigilError::PendingAlreadyExists { peer: GW_MAC }),
            "{} must block a fresh sensor resume start",
            kind_name(&kind)
        );
        kind.assert_preserved(&mgr, &GW_MAC, &before);
    }

    // Sensor-side stale-recovery replacement is fail-atomic: the FinalSent
    // recovery state (staged keys + cached Final) is replaced only after the
    // fresh request was built successfully, so an RNG failure preserves it.
    // Together with the gateway-side failed-ECDH scenario test this proves
    // replacement fail-atomicity on both sides.
    {
        let mut mgr = enrolled_sensor_manager();
        let before = K::SensorFinalSent.insert(&mut mgr, GW_MAC);
        assert_eq!(
            mgr.start_resume::<256>(
                GW_MAC,
                &mut MockSecureElement::default(),
                &mut FailingRandom,
                NOW
            ),
            Err(SigilError::RandomFailed),
            "RNG failure must abort the replacement before any removal"
        );
        K::SensorFinalSent.assert_preserved(&mgr, &GW_MAC, &before);
    }

    // Pending-table saturation: the capacity pre-check fires before the
    // request is built (the failing RNG proves nonce generation was never
    // reached) and before any pending mutation.
    {
        let mut mgr: SessionManager<2> = test_manager_with_mac(SENSOR_MAC);
        mgr.insert(
            Session::new_enrolled(GW_MAC, STATIC_PUB, RESUME_PSK, SessionRole::Sensor).unwrap(),
        )
        .unwrap();
        let other_a: PeerId = [0xA3u8; 17];
        let other_b: PeerId = [0xB3u8; 17];
        mgr.insert_pending(
            other_a,
            PendingHandshake::new_resume_sensor(other_a, NONCE, RESUME_TIMEOUT_MS, NOW),
        )
        .unwrap();
        mgr.insert_pending(
            other_b,
            PendingHandshake::new_resume_sensor(other_b, NONCE, RESUME_TIMEOUT_MS, NOW),
        )
        .unwrap();
        assert_eq!(
            mgr.start_resume::<256>(
                GW_MAC,
                &mut MockSecureElement::default(),
                &mut FailingRandom,
                NOW
            ),
            Err(SigilError::PendingTableFull),
            "pending-capacity rejection must fire before RNG consumption"
        );
    }
}

#[test]
fn resume_commit_confirmed_counter_must_be_zero() {
    // The CommitConfirmed is the first frame under the new g2s key and must
    // carry counter 0; any other counter is a replay. The rejected frame
    // must not consume the sensor recovery state or install the key.
    let mut sensor = enrolled_sensor_manager();
    let mut gateway = enrolled_gateway_manager();
    let mut sensor_se = MockSecureElement::default();
    let mut gateway_se = MockSecureElement::default();
    let mut sensor_rng = MockRandom::new();
    let mut gateway_rng = MockRandom::new();

    // Real flow up to the sensor FinalSent recovery state and the gateway
    // CommitConfirmed.
    let request = transmitted(
        sensor
            .start_resume::<256>(GW_MAC, &mut sensor_se, &mut sensor_rng, NOW)
            .unwrap(),
    );
    let challenge = transmitted(
        gateway
            .handle_resume_request::<256>(
                &request,
                &mut gateway_se,
                &mut gateway_rng,
                NOW,
                LIFETIME,
            )
            .unwrap(),
    );
    let confirm = transmitted(
        sensor
            .continue_resume::<256>(&challenge, &mut sensor_se, NOW)
            .unwrap(),
    );
    let commit = transmitted(
        gateway
            .continue_resume::<256>(&confirm, &mut gateway_se, NOW)
            .unwrap(),
    );

    // Staged g2s material read from the tagged FinalSent state (crate
    // internal, mirroring the production commit path).
    let staged = match sensor.get_pending(&GW_MAC).unwrap().state() {
        PendingState::ResumeSensorFinalSent { keys, .. } => keys.clone(),
        _ => panic!("sensor pending must be ResumeSensorFinalSent"),
    };
    let replayed = aead::build_commit_confirmed_frame::<256>(
        &GW_MAC,
        FrameType::ResumeCommitConfirmed,
        &staged.g2s_key,
        &staged.g2s_prefix,
        1,
    )
    .unwrap();

    assert_eq!(
        sensor.continue_resume::<256>(&replayed, &mut sensor_se, NOW),
        Err(SigilError::Replay {
            peer: GW_MAC,
            expected: 0,
            received: 1,
        }),
        "CommitConfirmed counters other than 0 are replays"
    );

    // Fail-atomic: the recovery state, its cached Final, and the keyless
    // enrolled session all survive the rejected counter.
    assert!(matches!(
        sensor.get_pending(&GW_MAC).unwrap().state(),
        PendingState::ResumeSensorFinalSent { .. }
    ));
    assert!(sensor.get(&GW_MAC).unwrap().session_key().is_none());

    // The genuine counter-0 CommitConfirmed still commits afterwards.
    assert!(matches!(
        sensor.continue_resume::<256>(&commit, &mut sensor_se, NOW).unwrap(),
        SigilAction::Success { peer } if peer == GW_MAC
    ));
    assert!(sensor.get_pending(&GW_MAC).is_none());
}
