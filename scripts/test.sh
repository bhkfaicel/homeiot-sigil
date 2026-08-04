#!/usr/bin/env bash
# Local / CI entrypoint for unit tests.
# Also enforces Cargo.toml ↔ CHANGELOG.md version sync and CI helper unit tests.
set -euo pipefail
cd "$(dirname "$0")/.."
bash scripts/check-version-sync.sh
bash scripts/test-resolve-cargo-registry.sh
bash scripts/test-release-branch-name.sh
cargo test -- --nocapture
