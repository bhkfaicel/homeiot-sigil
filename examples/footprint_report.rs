//! Dev-only footprint capture for the public pipeline-exchanged types.
//!
//! Prints host-target [`size_of`] values for the public types exchanged
//! through the processing pipeline (`SessionManager<N>`, `Session`,
//! `SigilEvent`, `SigilAction`) under the **feature configuration this run
//! was built with**, so per-configuration rows of the checked-in footprint
//! report `docs/footprint-report.md` can be regenerated with one command per
//! configuration:
//!
//! ```bash
//! cargo run --locked --no-default-features --features sensor \
//!   --example footprint_report
//! cargo run --locked --no-default-features --features gateway \
//!   --example footprint_report
//! cargo run --locked --features sensor,gateway --example footprint_report
//! ```
//!
//! The crate-private pending-handshake internals (`PendingHandshake`,
//! `PendingState`, variant payloads) are measured by the unit-test suite
//! `src/core/pending/tests/footprint_report.rs`, which additionally breaks
//! sizes down per state variant. As with every host measurement, target
//! layout may differ: final flash / RAM / stack budgets remain
//! host-firmware-owned (crate-level footprint contract in `src/lib.rs`).
//!
//! This is reporting tooling only: it asserts nothing and defines no bounds.

extern crate sigil;

// Session types exist only in session configurations; the manufacturing-only
// `wire` contract keeps this example compilable as an empty program.
#[cfg(feature = "session")]
fn main() {
    use core::mem::size_of;

    use sigil::core::event::{SigilAction, SigilEvent};
    use sigil::core::manager::SessionManager;
    use sigil::core::session::Session;

    println!(
        "configuration: sensor={} gateway={}",
        cfg!(feature = "sensor"),
        cfg!(feature = "gateway")
    );
    println!(
        "SessionManager<2>   = {:>6} B",
        size_of::<SessionManager<2>>()
    );
    println!(
        "SessionManager<128> = {:>6} B",
        size_of::<SessionManager<128>>()
    );
    println!("Session             = {:>6} B", size_of::<Session>());
    println!(
        "SigilEvent<200,256> = {:>6} B",
        size_of::<SigilEvent<200, 256>>()
    );
    println!(
        "SigilAction<256>    = {:>6} B",
        size_of::<SigilAction<256>>()
    );
}

#[cfg(not(feature = "session"))]
fn main() {
    println!("session features disabled: nothing to measure");
}
