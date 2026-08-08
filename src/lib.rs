#![no_std]

#[cfg(not(any(feature = "sensor", feature = "gateway")))]
compile_error!("sigil requires at least one role feature: `sensor` or `gateway`");

// Core non-blocking session module (always available)
pub mod core;

#[cfg(test)]
extern crate alloc;
