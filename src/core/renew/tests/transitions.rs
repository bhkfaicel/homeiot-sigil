//! Table-driven dispatch tests for the Renew handshake transitions.
//!
//! These suites complement the scenario tests in the parent module by
//! exercising the **whole dispatch table** of `continue_renew` /
//! `handle_renew_request` / `handle_renew_confirm` as data:
//!
//! - every **rejected** (pending state, message type) pair fails closed with
//!   `InvalidStep` and leaves the prior valid state, its staged secrets, and
//!   its cached frame untouched (fail-atomic preservation);
//! - malformed / non-renew frames are rejected at parse level before any
//!   dispatch decision or pending mutation;
//! - every **accepted** renew transition (request → challenge, challenge →
//!   Final staging, duplicate challenge → cached-Final retransmission,
//!   Final → gateway commit, duplicate Final → cached-CommitConfirmed
//!   retransmission, CommitConfirmed → sensor commit) is walked over a real
//!   pairwise mock flow, including the duplicate-CommitConfirmed rejection
//!   after the sensor already committed;
//! - the entry guards of `start_renew` / `handle_renew_request` reject
//!   without consuming session counters or replacing pending state;
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
use crate::core::renew::RENEW_TIMEOUT_MS;
use crate::core::session::{DirectionalMaterial, PeerId, Session, SessionRole};
use crate::core::test_support::{
    MockRandom, MockSecureElement, test_manager, test_manager_with_mac,
};

/// Sensor MAC used by the pairwise accepted-transition walk.
const SENSOR_MAC: PeerId = [0x81u8; 17];
/// Gateway MAC used by the pairwise accepted-transition walk.
const GW_MAC: PeerId = [0x82u8; 17];
/// Peer key for the rejected-dispatch matrix (single-manager rows).
const PEER: PeerId = [7u8; 17];

/// Deterministic old-session key shared by the pairwise managers.
const OLD_KEY: [u8; 32] = [0x45u8; 32];
/// Deterministic old-session nonce prefix shared by the pairwise managers.
const OLD_PREFIX: [u8; 4] = [0xA5u8; 4];
/// Deterministic resume PSK for the active-session helpers.
const RESUME_PSK: [u8; 32] = [0x5Au8; 32];

/// Deterministic provider context staged in the gateway await-confirm state.
const CONTEXT: [u8; 32] = [0x77u8; 32];
/// Deterministic compressed ephemeral pubkey staged in pendings.
const PUBKEY: [u8; 33] = [0x02u8; 33];
/// Deterministic session-key lifetime staged in pendings / challenges.
const LIFETIME: u32 = 3_600;
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

/// Sensor-side manager with an active symmetric session towards the gateway.
fn sensor_manager() -> SessionManager<16> {
    let mut manager = test_manager_with_mac(SENSOR_MAC);
    manager
        .insert(
            Session::new_active(
                GW_MAC,
                [2u8; 33],
                DirectionalMaterial::symmetric_for_test(OLD_KEY, OLD_PREFIX),
                SessionRole::Sensor,
                RESUME_PSK,
                NOW + 86_400,
                NOW,
            )
            .unwrap(),
        )
        .unwrap();
    manager
}

/// Gateway-side manager with an active symmetric session towards the sensor.
fn gateway_manager() -> SessionManager<16> {
    let mut manager = test_manager_with_mac(GW_MAC);
    manager
        .insert(
            Session::new_active(
                SENSOR_MAC,
                [2u8; 33],
                DirectionalMaterial::symmetric_for_test(OLD_KEY, OLD_PREFIX),
                SessionRole::Gateway,
                RESUME_PSK,
                NOW + 86_400,
                NOW,
            )
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

/// The four renew pending states exercised by the dispatch table.
#[derive(Clone, Copy)]
enum PendingKind {
    /// Sensor: request sent, awaiting the gateway challenge.
    SensorAwaitChallenge,
    /// Sensor: Final sent, awaiting CommitConfirmed (recovery state).
    SensorFinalSent,
    /// Gateway: challenge sent, awaiting the sensor Final. Owns the
    /// backend-defined P-256 provider context.
    GatewayAwaitConfirm,
    /// Gateway: CommitConfirmed sent (recovery state, cached reTX).
    GatewayCommitSent,
}

/// Observable fingerprints of the secrets, cached frames, and bookkeeping a
/// rejected transition must leave exactly as it found them.
struct Fingerprint {
    /// Staged backend provider context (gateway await-confirm state).
    context: [u8; 32],
    /// Gateway ephemeral pubkey sent in the challenge.
    pubkey: [u8; 33],
    /// Staged sensor → gateway AEAD key half (sensor recovery state).
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
                // The sensor renew state is fieldless: the secure element
                // generates and consumes the ephemeral scalar at challenge
                // time, so there is no secret to fingerprint.
                let pending = PendingHandshake::new_renew_sensor(peer, RENEW_TIMEOUT_MS, NOW);
                let deadline = pending.deadline_at;
                mgr.insert_pending(peer, pending).unwrap();
                Fingerprint {
                    context: [0u8; 32],
                    pubkey: [0u8; 33],
                    s2g_key: [0u8; 32],
                    lifetime: 0,
                    cached: heapless::Vec::new(),
                    deadline,
                }
            }
            PendingKind::SensorFinalSent => {
                let mut pending = PendingHandshake::new_renew_sensor(peer, RENEW_TIMEOUT_MS, NOW);
                pending
                    .renew_sensor_stage_final(material(), LIFETIME, &final_frame(), NOW)
                    .unwrap();
                let deadline = pending.deadline_at;
                mgr.insert_pending(peer, pending).unwrap();
                Fingerprint {
                    context: [0u8; 32],
                    pubkey: [0u8; 33],
                    s2g_key: material().s2g_key,
                    lifetime: LIFETIME,
                    cached: final_frame(),
                    deadline,
                }
            }
            PendingKind::GatewayAwaitConfirm => {
                let pending = PendingHandshake::new_renew_gateway_await_confirm(
                    peer,
                    CONTEXT,
                    PUBKEY,
                    LIFETIME,
                    RENEW_TIMEOUT_MS,
                    NOW,
                );
                let deadline = pending.deadline_at;
                mgr.insert_pending(peer, pending).unwrap();
                Fingerprint {
                    context: CONTEXT,
                    pubkey: PUBKEY,
                    s2g_key: [0u8; 32],
                    lifetime: LIFETIME,
                    cached: heapless::Vec::new(),
                    deadline,
                }
            }
            PendingKind::GatewayCommitSent => {
                let mut pending = PendingHandshake::new_renew_gateway_await_confirm(
                    peer,
                    CONTEXT,
                    PUBKEY,
                    LIFETIME,
                    RENEW_TIMEOUT_MS,
                    NOW,
                );
                pending
                    .renew_gateway_commit_sent(&commit_frame(), NOW)
                    .unwrap();
                let deadline = pending.deadline_at;
                mgr.insert_pending(peer, pending).unwrap();
                Fingerprint {
                    context: [0u8; 32],
                    pubkey: [0u8; 33],
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
            (PendingKind::SensorAwaitChallenge, PendingState::RenewSensorAwaitChallenge) => {
                // Fieldless variant: only the bookkeeping must survive.
            }
            (
                PendingKind::SensorFinalSent,
                PendingState::RenewSensorFinalSent {
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
                PendingState::RenewGatewayAwaitConfirm {
                    p256_context,
                    gateway_ephemeral_pubkey,
                    key_lifetime_secs,
                },
            ) => {
                assert_eq!(*p256_context.as_array(), before.context);
                assert_eq!(*gateway_ephemeral_pubkey, before.pubkey);
                assert_eq!(*key_lifetime_secs, before.lifetime);
            }
            (PendingKind::GatewayCommitSent, PendingState::RenewGatewayCommitSent { cached }) => {
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
        PendingKind::SensorAwaitChallenge => "RenewSensorAwaitChallenge",
        PendingKind::SensorFinalSent => "RenewSensorFinalSent",
        PendingKind::GatewayAwaitConfirm => "RenewGatewayAwaitConfirm",
        PendingKind::GatewayCommitSent => "RenewGatewayCommitSent",
    }
}

/// Short label of the live tagged state for assertion messages.
fn state_name(state: &PendingState) -> &'static str {
    match state {
        PendingState::RenewSensorAwaitChallenge => "RenewSensorAwaitChallenge",
        PendingState::RenewSensorFinalSent { .. } => "RenewSensorFinalSent",
        PendingState::RenewGatewayAwaitConfirm { .. } => "RenewGatewayAwaitConfirm",
        PendingState::RenewGatewayCommitSent { .. } => "RenewGatewayCommitSent",
        _ => "non-renew pending state",
    }
}

/// Builds a minimal synthetic renew frame of `frame_type` for `peer`.
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
fn renew_dispatch_table_rejects_invalid_state_message_pairs() {
    // Every (pending state, message type) pair that is NOT one of the
    // accepted dispatch combinations must fail closed with InvalidStep while
    // preserving the prior valid state and its staged secrets / cache.
    //
    // Sensor-side dispatch (`continue_renew`): the accepted pairs are
    // (AwaitChallenge, Challenge), (FinalSent, CommitConfirmed) and
    // (FinalSent, Challenge → cached-Final reTX).
    use FrameType as M;
    use PendingKind as K;
    let rejected_continue: &[(K, M)] = &[
        // Sensor awaiting its challenge: only a Challenge is meaningful.
        (K::SensorAwaitChallenge, M::RenewRequest),
        (K::SensorAwaitChallenge, M::RenewConfirm),
        (K::SensorAwaitChallenge, M::RenewCommitConfirmed),
        // Sensor already sent its Final: only a Challenge (reTX) or the
        // CommitConfirmed are meaningful.
        (K::SensorFinalSent, M::RenewRequest),
        (K::SensorFinalSent, M::RenewConfirm),
        // Gateway states must not be advanced by the sensor entry point
        // (cross-role confusion fails closed). With the sensor blocks above
        // and the three accepted pairs, these rows cover every cell of the
        // 4-state × 4-message sensor dispatch grid (13 rejected + 3
        // accepted = 16).
        (K::GatewayAwaitConfirm, M::RenewRequest),
        (K::GatewayAwaitConfirm, M::RenewConfirm),
        (K::GatewayAwaitConfirm, M::RenewChallenge),
        (K::GatewayAwaitConfirm, M::RenewCommitConfirmed),
        (K::GatewayCommitSent, M::RenewRequest),
        (K::GatewayCommitSent, M::RenewConfirm),
        (K::GatewayCommitSent, M::RenewChallenge),
        (K::GatewayCommitSent, M::RenewCommitConfirmed),
    ];

    for &(kind, msg) in rejected_continue {
        let mut mgr: SessionManager<16> = test_manager();
        let before = kind.insert(&mut mgr, PEER);

        let frame = synthetic_frame(msg, &PEER);
        let result = mgr.continue_renew::<256>(&frame, &mut MockSecureElement::default(), NOW);

        assert_eq!(
            result,
            Err(SigilError::InvalidStep { peer: PEER }),
            "sensor dispatch table must reject {:?} + {:?}",
            kind_name(&kind),
            msg
        );
        // Fail-atomic: the prior valid state, secrets, cache, and deadline
        // all survive the rejected transition untouched.
        kind.assert_preserved(&mgr, &PEER, &before);
    }

    // Gateway-side dispatch (`handle_renew_confirm`): only the
    // challenge-waiting and post-commit recovery variants may process a
    // RenewConfirm; sensor states fail closed through this entry point.
    let rejected_confirm: &[K] = &[K::SensorAwaitChallenge, K::SensorFinalSent];
    for &kind in rejected_confirm {
        let mut mgr: SessionManager<16> = test_manager();
        let before = kind.insert(&mut mgr, PEER);

        let frame = synthetic_frame(M::RenewConfirm, &PEER);
        let result =
            mgr.handle_renew_confirm::<256>(&frame, &mut MockSecureElement::default(), NOW);

        assert_eq!(
            result,
            Err(SigilError::InvalidStep { peer: PEER }),
            "gateway dispatch table must reject {:?} + RenewConfirm",
            kind_name(&kind)
        );
        kind.assert_preserved(&mgr, &PEER, &before);
    }
}

#[test]
fn renew_dispatch_table_rejects_malformed_frames_before_dispatch() {
    // Malformed / non-renew frames must fail at parse level before any
    // dispatch decision or pending mutation, in every pending state and
    // through every renew entry point.
    use PendingKind as K;

    // Truncated frame (shorter than the outer header).
    let truncated: &[u8] = &[0u8; 10];

    for kind in [
        K::SensorAwaitChallenge,
        K::SensorFinalSent,
        K::GatewayAwaitConfirm,
        K::GatewayCommitSent,
    ] {
        // Sensor entry point: truncation and unknown frame-type bytes are
        // parse failures; a known non-renew byte is a dispatch rejection
        // owned by the table above, not a parse error.
        for malformed in [truncated, unknown_type_frame(&PEER).as_slice()] {
            let mut mgr: SessionManager<16> = test_manager();
            let before = kind.insert(&mut mgr, PEER);

            let result =
                mgr.continue_renew::<256>(malformed, &mut MockSecureElement::default(), NOW);
            assert_eq!(
                result,
                Err(SigilError::MalformedFrame),
                "sensor entry point must reject malformed input in {:?}",
                kind_name(&kind)
            );
            kind.assert_preserved(&mgr, &PEER, &before);
        }

        // Gateway Final entry point: truncation and any frame type other
        // than RenewConfirm are parse failures before pending lookup.
        for malformed in [
            truncated,
            synthetic_frame(FrameType::RenewChallenge, &PEER).as_slice(),
        ] {
            let mut mgr: SessionManager<16> = test_manager();
            let before = kind.insert(&mut mgr, PEER);

            let result =
                mgr.handle_renew_confirm::<256>(malformed, &mut MockSecureElement::default(), NOW);
            assert_eq!(
                result,
                Err(SigilError::MalformedFrame),
                "gateway Final entry point must reject malformed input in {:?}",
                kind_name(&kind)
            );
            kind.assert_preserved(&mgr, &PEER, &before);
        }

        // Gateway request entry point: frames shorter than a peer MAC are
        // parse failures before any pending or session work.
        {
            let mut mgr: SessionManager<16> = test_manager();
            let before = kind.insert(&mut mgr, PEER);

            let result = mgr.handle_renew_request::<256>(
                truncated,
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
    /// The sensor's initial RenewRequest.
    Request,
    /// The gateway's RenewChallenge.
    Challenge,
    /// The sensor's RenewConfirm (Final).
    Confirm,
    /// The gateway's RenewCommitConfirmed.
    Commit,
}

/// The expected outcome of one accepted-transition table row.
#[derive(Clone, Copy)]
enum Expected {
    /// Gateway accepts the request: emits the challenge, stages the
    /// gateway await-confirm pending (owning the P-256 provider context),
    /// and advances the session counters.
    GatewayAcceptsRequest,
    /// Sensor accepts the challenge: stages Final (recovery state) and
    /// transmits the confirm under the old key.
    SensorStagesFinal,
    /// Sensor receives a duplicate challenge after Final: retransmits the
    /// cached Final byte-exactly without re-running crypto.
    SensorRetransmitsFinal,
    /// Gateway accepts the Final: commits the rotated key, emits the
    /// CommitConfirmed, and keeps the cached frame for idempotent reTX.
    GatewayCommits,
    /// Gateway receives a duplicate Final after commit: retransmits the
    /// cached CommitConfirmed byte-exactly.
    GatewayRetransmitsCommit,
    /// Sensor accepts the CommitConfirmed: rotates the key, resets the
    /// counters, and clears its pending.
    SensorCommits,
    /// Sensor receives a duplicate CommitConfirmed after committing: its
    /// pending is gone, so the frame is rejected with NoPending.
    SensorDuplicateCommitRejected,
}

#[test]
fn renew_dispatch_table_accepted_transitions() {
    // Walks every accepted renew transition as table rows over one real
    // pairwise mock flow. Frames produced by a row become the input of later
    // rows; retransmission rows assert byte-exact equality with the original.
    let table: &[(&str, FrameSel, Expected)] = &[
        (
            "no gateway pending + RenewRequest -> challenge + AwaitConfirm",
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
            "SensorFinalSent + CommitConfirmed -> rotated session",
            FrameSel::Commit,
            Expected::SensorCommits,
        ),
        (
            "sensor pending cleared + duplicate CommitConfirmed -> NoPending",
            FrameSel::Commit,
            Expected::SensorDuplicateCommitRejected,
        ),
    ];

    let mut sensor = sensor_manager();
    let mut gateway = gateway_manager();
    let mut sensor_se = MockSecureElement::default();
    let mut gateway_se = MockSecureElement::default();
    let mut gateway_rng = MockRandom::new();

    // Pre-amble: the sensor starts renew (covered by scenario tests); its
    // request frame feeds the first table row.
    let request = transmitted(
        sensor
            .start_renew::<256>(GW_MAC, NOW)
            .unwrap_or_else(|e| panic!("start_renew: {e:?}")),
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
                    .handle_renew_request::<256>(
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
                            FrameType::RenewChallenge as u8,
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
                // The tagged gateway state owns the backend provider context
                // plus the challenge pubkey and lifetime until the Final.
                match gateway.get_pending(&SENSOR_MAC).unwrap().state() {
                    PendingState::RenewGatewayAwaitConfirm {
                        gateway_ephemeral_pubkey,
                        key_lifetime_secs,
                        ..
                    } => {
                        assert!(
                            matches!(gateway_ephemeral_pubkey[0], 0x02 | 0x03),
                            "{label}"
                        );
                        assert_eq!(*key_lifetime_secs, LIFETIME, "{label}");
                    }
                    _ => panic!("{label}: gateway pending must await the sensor Final"),
                }
                // Counters advance only after the challenge was encrypted and
                // the pending inserted: request consumed rx 0, challenge tx 0.
                let session = gateway.get(&SENSOR_MAC).unwrap();
                assert_eq!(session.rx_counter, 1, "{label}");
                assert_eq!(session.tx_counter, 1, "{label}");
                assert_eq!(session.session_key(), Some(&OLD_KEY), "{label}");
            }
            Expected::SensorStagesFinal => {
                let action = sensor
                    .continue_renew::<256>(&frame, &mut sensor_se, NOW)
                    .unwrap_or_else(|e| panic!("{label}: {e:?}"));
                match action {
                    SigilAction::Transmit { dest, payload, .. } => {
                        assert_eq!(dest, GW_MAC, "{label}");
                        assert_eq!(
                            payload[FRAME_TYPE_OFFSET],
                            FrameType::RenewConfirm as u8,
                            "{label}"
                        );
                        confirm = payload;
                    }
                    _ => panic!("{label}: sensor must transmit the Final"),
                }
                // Final staged: recovery state caches exactly the frame sent
                // and keeps the old session key until CommitConfirmed.
                match sensor.get_pending(&GW_MAC).unwrap().state() {
                    PendingState::RenewSensorFinalSent {
                        key_lifetime_secs,
                        cached,
                        ..
                    } => {
                        assert_eq!(*key_lifetime_secs, LIFETIME, "{label}");
                        assert_eq!(cached.as_slice(), confirm.as_slice(), "{label}");
                    }
                    _ => panic!("{label}: sensor pending must be FinalSent"),
                }
                // Challenge consumed rx 0; the Final consumed tx 1.
                let session = sensor.get(&GW_MAC).unwrap();
                assert_eq!(session.rx_counter, 1, "{label}");
                assert_eq!(session.tx_counter, 2, "{label}");
                assert_eq!(session.session_key(), Some(&OLD_KEY), "{label}");
            }
            Expected::SensorRetransmitsFinal => {
                let action = sensor
                    .continue_renew::<256>(&frame, &mut sensor_se, NOW)
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
                        PendingState::RenewSensorFinalSent { .. }
                    ),
                    "{label}: reTX must keep the FinalSent recovery state"
                );
                assert_eq!(
                    sensor.get(&GW_MAC).unwrap().session_key(),
                    Some(&OLD_KEY),
                    "{label}"
                );
            }
            Expected::GatewayCommits => {
                let action = gateway
                    .handle_renew_confirm::<256>(&frame, &mut gateway_se, NOW)
                    .unwrap_or_else(|e| panic!("{label}: {e:?}"));
                match action {
                    SigilAction::Transmit { dest, payload, .. } => {
                        assert_eq!(dest, SENSOR_MAC, "{label}");
                        assert_eq!(
                            payload[FRAME_TYPE_OFFSET],
                            FrameType::RenewCommitConfirmed as u8,
                            "{label}"
                        );
                        commit = payload;
                    }
                    _ => panic!("{label}: gateway Final must transmit the CommitConfirmed"),
                }
                // Commit transition consumed the await-confirm variant (the
                // provider context stash is zeroized by the swap) and kept
                // the cached CommitConfirmed for idempotent retransmission.
                match gateway.get_pending(&SENSOR_MAC).unwrap().state() {
                    PendingState::RenewGatewayCommitSent { cached } => {
                        assert_eq!(cached.as_slice(), commit.as_slice(), "{label}");
                    }
                    _ => panic!("{label}: gateway pending must keep CommitSent for reTX"),
                }
                // Session committed at Final: rotated key, fresh counters
                // (Confirm used only an old-key rx; CommitConfirmed uses new
                // g2s counter 0, hence tx 1).
                let session = gateway.get(&SENSOR_MAC).unwrap();
                assert_ne!(session.session_key(), Some(&OLD_KEY), "{label}");
                assert_eq!(session.rx_counter, 0, "{label}");
                assert_eq!(session.tx_counter, 1, "{label}");
            }
            Expected::GatewayRetransmitsCommit => {
                let action = gateway
                    .handle_renew_confirm::<256>(&frame, &mut gateway_se, NOW)
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
                        PendingState::RenewGatewayCommitSent { .. }
                    ),
                    "{label}"
                );
            }
            Expected::SensorCommits => {
                let action = sensor
                    .continue_renew::<256>(&frame, &mut sensor_se, NOW)
                    .unwrap_or_else(|e| panic!("{label}: {e:?}"));
                match action {
                    SigilAction::Success { peer } => assert_eq!(peer, GW_MAC, "{label}"),
                    _ => panic!("{label}: sensor commit must return Success"),
                }
                // Rotated session mirrors the gateway's directional halves;
                // CommitConfirmed consumed new g2s counter 0, hence rx 1.
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
                assert_eq!(sensor_session.tx_counter, 0, "{label}");
                assert_eq!(sensor_session.rx_counter, 1, "{label}");
                assert!(
                    sensor.get_pending(&GW_MAC).is_none(),
                    "{label}: sensor pending must clear at commit"
                );
            }
            Expected::SensorDuplicateCommitRejected => {
                let result = sensor.continue_renew::<256>(&frame, &mut sensor_se, NOW);
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
fn renew_entry_guards_reject_without_mutation() {
    // Entry guards of the sensor `start_renew` and the gateway
    // `handle_renew_request`: each rejection must leave the session
    // counters and any pending state exactly as they were.
    use PendingKind as K;

    // No session for the peer: nothing to renew from.
    let mut mgr = test_manager_with_mac::<16>(SENSOR_MAC);
    assert_eq!(
        mgr.start_renew::<256>(GW_MAC, NOW),
        Err(SigilError::UnknownSession { peer: GW_MAC })
    );

    // Wrong role: renew is sensor-initiated only.
    let mut mgr = test_manager_with_mac::<16>(SENSOR_MAC);
    mgr.insert(
        Session::new_active(
            GW_MAC,
            [2u8; 33],
            material(),
            SessionRole::Gateway,
            RESUME_PSK,
            NOW + 86_400,
            NOW,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        mgr.start_renew::<256>(GW_MAC, NOW),
        // Renew is sensor-initiated: a gateway-role session is a static
        // role/config mismatch.
        Err(SigilError::WrongRole { peer: GW_MAC })
    );

    // Expired session key: renew requires an active key (resume is the
    // recovery path after expiry).
    let mut mgr = test_manager_with_mac::<16>(SENSOR_MAC);
    mgr.insert(
        Session::new_active(
            GW_MAC,
            [2u8; 33],
            material(),
            SessionRole::Sensor,
            RESUME_PSK,
            100,
            0,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        mgr.start_renew::<256>(GW_MAC, NOW),
        Err(SigilError::SessionExpired { peer: GW_MAC })
    );

    // Existing pending: rejected without rolling the TX counter back or
    // advancing it a second time.
    let mut mgr = sensor_manager();
    assert!(matches!(
        mgr.start_renew::<256>(GW_MAC, NOW).unwrap(),
        SigilAction::Transmit { .. }
    ));
    assert_eq!(mgr.get(&GW_MAC).unwrap().tx_counter, 1);
    assert_eq!(
        mgr.start_renew::<256>(GW_MAC, NOW),
        Err(SigilError::PendingAlreadyExists { peer: GW_MAC })
    );
    assert_eq!(
        mgr.get(&GW_MAC).unwrap().tx_counter,
        1,
        "rejected restart must not touch the TX counter"
    );

    // Pending-table saturation: the capacity pre-check fires before the
    // request is built or the TX counter advances (no rollback needed).
    let mut mgr: SessionManager<2> = test_manager_with_mac(SENSOR_MAC);
    mgr.insert(
        Session::new_active(
            GW_MAC,
            [2u8; 33],
            DirectionalMaterial::symmetric_for_test(OLD_KEY, OLD_PREFIX),
            SessionRole::Sensor,
            RESUME_PSK,
            NOW + 86_400,
            NOW,
        )
        .unwrap(),
    )
    .unwrap();
    let other_a: PeerId = [0xA1u8; 17];
    let other_b: PeerId = [0xB1u8; 17];
    mgr.insert_pending(
        other_a,
        PendingHandshake::new_renew_sensor(other_a, RENEW_TIMEOUT_MS, NOW),
    )
    .unwrap();
    mgr.insert_pending(
        other_b,
        PendingHandshake::new_renew_sensor(other_b, RENEW_TIMEOUT_MS, NOW),
    )
    .unwrap();
    assert_eq!(
        mgr.start_renew::<256>(GW_MAC, NOW),
        // Pending-table saturation is a pending-domain capacity error,
        // distinct from session/admission saturation.
        Err(SigilError::PendingTableFull)
    );
    assert_eq!(
        mgr.get(&GW_MAC).unwrap().tx_counter,
        0,
        "capacity rejection must not advance the TX counter"
    );

    // Gateway request guard: unlike install, renew has no stale-commit
    // replacement — a request while any renew pending exists (including the
    // post-commit recovery state) is rejected; the host recovers by calling
    // cancel_pending explicitly.
    let request = {
        let mut sensor = sensor_manager();
        transmitted(sensor.start_renew::<256>(GW_MAC, NOW).unwrap())
    };
    for kind in [K::GatewayAwaitConfirm, K::GatewayCommitSent] {
        let mut gateway: SessionManager<16> = test_manager_with_mac(GW_MAC);
        let before = kind.insert(&mut gateway, SENSOR_MAC);
        assert_eq!(
            gateway.handle_renew_request::<256>(
                &request,
                &mut MockSecureElement::default(),
                &mut MockRandom::new(),
                NOW,
                LIFETIME,
            ),
            Err(SigilError::PendingAlreadyExists { peer: SENSOR_MAC }),
            "{} must block a new renew request",
            kind_name(&kind)
        );
        kind.assert_preserved(&gateway, &SENSOR_MAC, &before);
    }

    // Host abort policy: cancelling a renew pending frees the peer for a
    // fresh attempt (renew is retriable after an explicit cancel).
    let mut mgr = sensor_manager();
    assert!(matches!(
        mgr.start_renew::<256>(GW_MAC, NOW).unwrap(),
        SigilAction::Transmit { .. }
    ));
    mgr.cancel_pending(&GW_MAC).unwrap();
    assert!(mgr.get_pending(&GW_MAC).is_none());
    assert!(matches!(
        mgr.start_renew::<256>(GW_MAC, NOW).unwrap(),
        SigilAction::Transmit { .. }
    ));
}

#[test]
fn renew_commit_confirmed_counter_must_be_zero() {
    // The CommitConfirmed is the first frame under the new g2s key and must
    // carry counter 0; any other counter is a replay. The rejected frame
    // must not consume the sensor recovery state or rotate the key.
    let mut sensor = sensor_manager();
    let mut gateway = gateway_manager();
    let mut sensor_se = MockSecureElement::default();
    let mut gateway_se = MockSecureElement::default();
    let mut gateway_rng = MockRandom::new();

    // Real flow up to the sensor FinalSent recovery state and the gateway
    // CommitConfirmed.
    let request = transmitted(sensor.start_renew::<256>(GW_MAC, NOW).unwrap());
    let challenge = transmitted(
        gateway
            .handle_renew_request::<256>(&request, &mut gateway_se, &mut gateway_rng, NOW, LIFETIME)
            .unwrap(),
    );
    let confirm = transmitted(
        sensor
            .continue_renew::<256>(&challenge, &mut sensor_se, NOW)
            .unwrap(),
    );
    let commit = transmitted(
        gateway
            .handle_renew_confirm::<256>(&confirm, &mut gateway_se, NOW)
            .unwrap(),
    );

    // Staged g2s material read from the tagged FinalSent state (crate
    // internal, mirroring the production commit path).
    let staged = match sensor.get_pending(&GW_MAC).unwrap().state() {
        PendingState::RenewSensorFinalSent { keys, .. } => keys.clone(),
        _ => panic!("sensor pending must be RenewSensorFinalSent"),
    };
    let replayed = aead::build_commit_confirmed_frame::<256>(
        &GW_MAC,
        FrameType::RenewCommitConfirmed,
        &staged.g2s_key,
        &staged.g2s_prefix,
        1,
    )
    .unwrap();

    assert_eq!(
        sensor.continue_renew::<256>(&replayed, &mut sensor_se, NOW),
        Err(SigilError::Replay {
            peer: GW_MAC,
            expected: 0,
            received: 1,
        }),
        "CommitConfirmed counters other than 0 are replays"
    );

    // Fail-atomic: the recovery state, its cached Final, and the old key all
    // survive the rejected counter.
    assert!(matches!(
        sensor.get_pending(&GW_MAC).unwrap().state(),
        PendingState::RenewSensorFinalSent { .. }
    ));
    assert_eq!(sensor.get(&GW_MAC).unwrap().session_key(), Some(&OLD_KEY));

    // The genuine counter-0 CommitConfirmed still commits afterwards.
    assert!(matches!(
        sensor.continue_renew::<256>(&commit, &mut sensor_se, NOW).unwrap(),
        SigilAction::Success { peer } if peer == GW_MAC
    ));
    assert!(sensor.get_pending(&GW_MAC).is_none());
}
