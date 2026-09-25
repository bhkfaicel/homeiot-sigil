#!/usr/bin/env bash
# Local / CI entrypoint for the complete project gate.
# Runs the repository helper checks, the authoritative locked feature-matrix
# test gate, and the embedded-target cross-checks.
set -euo pipefail
cd "$(dirname "$0")/.."
bash scripts/check-version-sync.sh
bash scripts/test-resolve-cargo-registry.sh
bash scripts/test-release-branch-name.sh
# Feature clippy matrix first (fail-fast): a lint-only regression must surface
# in minutes, before the multi-minute test matrix runs. The shared CI gate
# (faicel/central_ci) lints with the default features (sensor) only and
# without --locked/--all-targets, so the strict lint coverage for the supported
# feature configurations is enforced here, on the crate side, through the
# test_command input.
cargo clippy --locked --all-features --all-targets -- -D warnings
cargo clippy --locked --no-default-features --features sensor -- -D warnings
cargo clippy --locked --no-default-features --features gateway -- -D warnings
# Authoritative feature-matrix gate: asserts the approved diagnostic for the
# unsupported empty feature set and runs the locked test suites for the wire,
# sensor, gateway, sensor,gateway, ota, sensor,ota, gateway,ota, usbserial,
# gateway,usbserial, and all-features configurations. The matrix logic is
# owned exclusively by that script; never duplicate it here.
bash scripts/test-feature-matrix.sh
# Strict documentation gate: broken intra-doc links fail the release docs.
RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps --all-features
# Embedded-target cross-checks (locked for reproducibility). The CI container
# image may ship without these std targets; rustup target add is idempotent.
rustup target add thumbv6m-none-eabi armv7-unknown-linux-gnueabihf
cargo check --locked --target thumbv6m-none-eabi --no-default-features --features sensor
cargo check --locked --target armv7-unknown-linux-gnueabihf --no-default-features --features gateway
# OTA tiers on their real targets: the constrained sensor build must carry NO
# sender code (receive half only), and the gateway build the send half.
cargo check --locked --target thumbv6m-none-eabi --no-default-features --features sensor,ota
cargo check --locked --target armv7-unknown-linux-gnueabihf --no-default-features --features gateway,ota
# USB-serial tier on its real targets: usbserial alone is what the SAMD21 head
# firmware compiles, and the gateway host links it with the gateway role.
cargo check --locked --target thumbv6m-none-eabi --no-default-features --features usbserial
cargo check --locked --target armv7-unknown-linux-gnueabihf --no-default-features --features gateway,usbserial
