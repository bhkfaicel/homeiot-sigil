#!/usr/bin/env bash
# Authoritative feature-matrix gate for the sigil crate.
#
# Documented feature configuration disposition:
#   - empty (no features): UNSUPPORTED. Rejected at compile time by the
#     deliberate compile_error! diagnostic in src/lib.rs; this gate asserts
#     that the empty configuration fails ONLY with that approved diagnostic.
#   - wire:                SUPPORTED. Manufacturing-only contract; its test
#                          run legitimately contains only the factory_cert
#                          tests.
#   - sensor:              SUPPORTED. Single-role session build.
#   - gateway:             SUPPORTED. Single-role session build.
#   - sensor,gateway:      SUPPORTED. Explicit two-role composition.
#   - ota:                 SUPPORTED. Shared OTA wire tier (codec + manifest
#                          digest) without any protocol engine.
#   - sensor,ota:          SUPPORTED. Adds the OTA receive half.
#   - gateway,ota:         SUPPORTED. Adds the OTA send half.
#   - usbserial:           SUPPORTED. USB-serial link tier to the SAMD21
#                          radio head (plain framing + secured channel).
#   - gateway,usbserial:   SUPPORTED. Gateway host build consuming the head.
#   - --all-features:      SUPPORTED. Future-facing superset gate (covers the
#                          dual-role build with both OTA halves and the
#                          usbserial tier).
#
# Fixture disposition: no separate feature-matrix fixture files exist and
# none are required. Every supported configuration is exercised end-to-end
# by the locked per-configuration suites this script invokes below (the
# adjacent manager architecture-contract tests included); for intentionally
# unsupported configurations, the empty-set compile_error! diagnostic
# asserted here is the sole compile-fail authority.
#
# The script exits non-zero if any supported configuration fails its locked
# test suite, or if the unsupported empty configuration succeeds or fails with
# anything other than the approved diagnostic.
set -euo pipefail
cd "$(dirname "$0")/.."

# Distinctive substring of the approved compile_error! message in src/lib.rs.
readonly EMPTY_FEATURE_DIAGNOSTIC="no supported feature configuration selected"

# Print the number of cargo error lines that are neither the approved
# empty-feature diagnostic nor cargo's own failure summary lines. The trailing
# `|| true` keeps pipefail from aborting when an intermediate grep stage
# selects no lines at all (which means zero unexpected errors).
count_unexpected_error_lines() {
    grep -E '^error' \
        | grep -v -F "$EMPTY_FEATURE_DIAGNOSTIC" \
        | grep -v -E '^error: (aborting due to|could not compile)' \
        | wc -l \
        | tr -d ' ' || true
}

# Run a cargo command that is expected to fail compilation, and assert the
# failure carries the approved empty-feature diagnostic and no other error.
expect_approved_failure() {
    local description="$1"
    shift
    local output=""
    local status=0
    output="$("$@" 2>&1)" || status=1

    if [ "$status" -eq 0 ]; then
        printf 'feature-matrix: FAIL: %s unexpectedly succeeded; the empty feature set must be rejected\n' \
            "$description" >&2
        printf '%s\n' "$output" >&2
        exit 1
    fi
    if ! printf '%s\n' "$output" | grep -q -F "$EMPTY_FEATURE_DIAGNOSTIC"; then
        printf 'feature-matrix: FAIL: %s failed without the approved diagnostic\n' "$description" >&2
        printf '%s\n' "$output" >&2
        exit 1
    fi
    local unexpected=0
    unexpected="$(printf '%s\n' "$output" | count_unexpected_error_lines)"
    if [ "$unexpected" -ne 0 ]; then
        printf 'feature-matrix: FAIL: %s produced %s error line(s) besides the approved diagnostic\n' \
            "$description" "$unexpected" >&2
        printf '%s\n' "$output" >&2
        exit 1
    fi
    printf 'feature-matrix: OK: %s rejected with the approved diagnostic only\n' "$description"
}

# Run a cargo command for a supported configuration and require success.
expect_supported() {
    local description="$1"
    shift
    printf 'feature-matrix: RUN: %s\n' "$description"
    if ! "$@"; then
        printf 'feature-matrix: FAIL: %s did not pass\n' "$description" >&2
        exit 1
    fi
    printf 'feature-matrix: OK: %s\n' "$description"
}

# Unsupported configuration: the empty feature set must fail with only the
# approved diagnostic, both as a library check and as a test run.
expect_approved_failure \
    "empty feature check" \
    cargo check --locked --no-default-features
expect_approved_failure \
    "empty feature test" \
    cargo test --locked --no-default-features

# Supported configurations: full locked test suites must pass.
expect_supported \
    "wire tests" \
    cargo test --locked --no-default-features --features wire
expect_supported \
    "sensor tests" \
    cargo test --locked --no-default-features --features sensor
expect_supported \
    "gateway tests" \
    cargo test --locked --no-default-features --features gateway
expect_supported \
    "sensor,gateway tests" \
    cargo test --locked --no-default-features --features sensor,gateway
expect_supported \
    "ota shared-tier tests" \
    cargo test --locked --no-default-features --features ota
expect_supported \
    "sensor,ota tests" \
    cargo test --locked --no-default-features --features sensor,ota
expect_supported \
    "gateway,ota tests" \
    cargo test --locked --no-default-features --features gateway,ota
expect_supported \
    "usbserial shared-tier tests" \
    cargo test --locked --no-default-features --features usbserial
expect_supported \
    "gateway,usbserial tests" \
    cargo test --locked --no-default-features --features gateway,usbserial
expect_supported \
    "all-features tests" \
    cargo test --locked --all-features

printf 'feature-matrix: every configuration behaved as documented\n'
