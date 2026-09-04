#!/usr/bin/env bash
# Run cargo-deny against deny.toml (advisories, licenses, bans, sources).
# Local wrapper for the dependency-policy gate that CI executes through
# faicel/central_ci (enable_deny input, on by default).
# Requires cargo-deny on PATH (provided by ci-rust-embedded >= 1.0.3).
set -euo pipefail
cd "$(dirname "$0")/.."
cargo deny check
