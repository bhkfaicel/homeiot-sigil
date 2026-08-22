//! Dev-only footprint report for pipeline-exchanged types and every
//! [`PendingState`] variant payload.
//!
//! # Purpose
//! This suite **prints** measured byte sizes (run with `--nocapture`) so a
//! checked-in measurement note can record reproducible numbers. It is
//! reporting tooling only: it asserts nothing and introduces no new approved
//! bounds — regression bounds stay owned by the `type_size_bounds` suites
//! next to each module, following the crate-level footprint contract in
//! `src/lib.rs`.
//!
//! # Measurement basis
//! Sizes come from [`size_of`] on the **host test target** in the two-role
//! configuration (this suite compiles only when both role features are
//! enabled, which is also the only configuration where every [`PendingState`]
//! variant exists). Mono-role builds compile strictly fewer role-exclusive
//! variants, so their totals can only be equal or smaller. Per-variant rows
//! show the **sum of the field-type sizes**, which excludes inter-field
//! padding: exact padded variant layouts are compiler-defined, so the
//! authoritative per-slot costs are the printed [`PendingState`] /
//! [`PendingHandshake`] totals. As with every host measurement, target layout
//! may differ; final flash / RAM / stack budgets remain host-firmware-owned.
//!
//! # Reproduce
//! ```bash
//! cargo test --locked --all-features footprint_report -- --nocapture
//! ```

// The crate is `no_std`; the unit-test harness links `std` on the host,
// which provides the printing macros used by this dev-only report.
extern crate std;

// Pull the printing macro into scope (`no_std` builds have an empty macro
// prelude even under `cfg(test)`); same pattern as the measurement suites.
use std::println;

use core::mem::{align_of, size_of};

use crate::core::event::{SigilAction, SigilEvent};
use crate::core::manager::SessionManager;
use crate::core::pending::{
    CachedWire, InstallGatewayStaged, Nonce16Stash, P256ContextStash, PendingHandshake,
    PendingState, ResumePskStash,
};
use crate::core::session::{DirectionalMaterial, Session};

/// Prints one aligned `name = bytes` row of the report.
fn row(name: &str, bytes: usize) {
    println!("    {name:<48} {bytes:>5} B");
}

/// Prints a section header of the report.
fn section(title: &str) {
    println!("\n[{title}]");
}

#[test]
fn footprint_report_prints_pipeline_type_sizes() {
    // Section 1: types exchanged through the public processing pipeline and
    // the manager value itself (the dominant static-RAM allocation).
    section("pipeline-exchanged types (host target, two-role build)");
    row("SessionManager<2>", size_of::<SessionManager<2>>());
    row("SessionManager<128>", size_of::<SessionManager<128>>());
    row("Session", size_of::<Session>());
    row("SigilEvent<200, 256>", size_of::<SigilEvent<200, 256>>());
    row("SigilAction<256>", size_of::<SigilAction<256>>());
    row("PendingHandshake", size_of::<PendingHandshake>());
    println!(
        "    {:<48} {:>5} B",
        "PendingHandshake align",
        align_of::<PendingHandshake>()
    );
    row("PendingState", size_of::<PendingState>());
    println!(
        "    {:<48} {:>5} B",
        "PendingState align",
        align_of::<PendingState>()
    );

    // Section 2: component primitives that pending-state payloads compose
    // from. These are the levers when right-sizing storage (for example the
    // cached retransmission frame or a secret stash).
    section("pending state components");
    let keys = size_of::<DirectionalMaterial>();
    let staged = size_of::<InstallGatewayStaged>();
    let psk32 = size_of::<ResumePskStash>();
    let ctx32 = size_of::<P256ContextStash>();
    let nonce16 = size_of::<Nonce16Stash>();
    let cached = size_of::<CachedWire>();
    row("DirectionalMaterial", keys);
    row("InstallGatewayStaged", staged);
    row("ResumePskStash (SecretBytes<32>)", psk32);
    row("P256ContextStash (SecretBytes<32>)", ctx32);
    row("Nonce16Stash (SecretBytes<16>)", nonce16);
    row("CachedWire (Vec<u8, 128>)", cached);
    println!(
        "    {:<48} {:>5} B",
        "CachedWire align",
        align_of::<CachedWire>()
    );

    // Section 3: per-variant nominal payload sums. Sums are computed from the
    // measured components above (never hardcoded), exclude inter-field
    // padding, and are labeled with the role feature that compiles them.
    section("per-PendingState variant nominal payload sums");
    let pk = size_of::<[u8; 33]>();
    let u32_ = size_of::<u32>();

    println!("  sensor-role variants:");
    row("InstallSensorAwaitChallenge { sensor_nonce }", nonce16);
    row(
        "InstallSensorFinalSent { keys, resume_psk, .. }",
        keys + psk32 + pk + u32_ + cached,
    );
    row("RenewSensorAwaitChallenge (unit)", 0);
    row("RenewSensorFinalSent { keys, .. }", keys + u32_ + cached);
    row("ResumeSensorAwaitChallenge { sensor_nonce }", nonce16);
    row("ResumeSensorFinalSent { keys, .. }", keys + u32_ + cached);

    println!("  gateway-role variants:");
    row("InstallGatewayAwaitConfirm(InstallGatewayStaged)", staged);
    row("InstallGatewayCommitSent { cached }", cached);
    row(
        "RenewGatewayAwaitConfirm { p256_context, .. }",
        ctx32 + pk + u32_,
    );
    row("RenewGatewayCommitSent { cached }", cached);
    row("ResumeGatewayAwaitConfirm { keys, .. }", keys + u32_);
    row("ResumeGatewayCommitSent { cached }", cached);

    println!(
        "\nNote: nominal sums exclude padding; authoritative slot costs are \
         the PendingState / PendingHandshake totals above."
    );
}
