#!/usr/bin/env bash
# Fail if Cargo.toml [package].version does not match the latest CHANGELOG.md entry.
# Keep aligned with faicel/central_ci scripts/check-version-sync.sh
#
# Usage:
#   ./scripts/check-version-sync.sh
#   CRATE_ROOT=/path/to/crate ./scripts/check-version-sync.sh
set -euo pipefail

if [[ -n "${CRATE_ROOT:-}" ]]; then
  ROOT="$(cd "${CRATE_ROOT}" && pwd)"
else
  ROOT="$(cd "$(dirname "$0")/.." && pwd)"
fi

CARGO_TOML="${ROOT}/Cargo.toml"
CHANGELOG="${ROOT}/CHANGELOG.md"

if [[ ! -f "${CARGO_TOML}" ]]; then
  echo "error: missing ${CARGO_TOML}" >&2
  exit 1
fi
if [[ ! -f "${CHANGELOG}" ]]; then
  echo "error: missing ${CHANGELOG}" >&2
  exit 1
fi

CARGO_VERSION="$(
  sed -n 's/^version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "${CARGO_TOML}" | head -n 1
)"
if [[ -z "${CARGO_VERSION}" ]]; then
  echo "error: could not read version from ${CARGO_TOML}" >&2
  exit 1
fi

CHANGELOG_VERSION="$(
  sed -n 's/^##[[:space:]]*\[\([0-9][^]]*\)\].*/\1/p' "${CHANGELOG}" | head -n 1
)"
if [[ -z "${CHANGELOG_VERSION}" ]]; then
  echo "error: could not read latest ## [version] heading from ${CHANGELOG}" >&2
  exit 1
fi

if [[ "${CARGO_VERSION}" != "${CHANGELOG_VERSION}" ]]; then
  cat >&2 <<EOF
error: version mismatch between Cargo.toml and CHANGELOG.md

  Cargo.toml   version = "${CARGO_VERSION}"
  CHANGELOG.md latest  = [${CHANGELOG_VERSION}]

Bump both to the same version before merge/publish.
  - Edit version in Cargo.toml
  - Add/update the top ## [x.y.z] section in CHANGELOG.md
EOF
  exit 1
fi

echo "version sync OK: ${CARGO_VERSION} (Cargo.toml == CHANGELOG.md)"
