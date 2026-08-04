#!/usr/bin/env bash
# Unit tests for CI helper scripts (registry selection, version sync prerequisites).
set -euo pipefail
cd "$(dirname "$0")/.."

RESOLVE=scripts/resolve-cargo-registry.sh
chmod +x "$RESOLVE"

fail=0
assert_eq() {
  local got="$1" want="$2" label="$3"
  if [[ "$got" != "$want" ]]; then
    echo "FAIL: $label (got='$got' want='$want')"
    fail=1
  else
    echo "ok: $label"
  fi
}

assert_eq "$("$RESOLVE" "v1.0.6")" "forgejo" "stable tag → forgejo"
assert_eq "$("$RESOLVE" "v1.0.6-rc")" "forgejorc" "rc tag → forgejorc"
assert_eq "$("$RESOLVE" "v1.0.6-rc.1")" "forgejorc" "legacy rc.N tag → forgejorc"
assert_eq "$("$RESOLVE" "v1.2.3")" "forgejo" "plain semver → forgejo"

if [[ "$fail" -ne 0 ]]; then
  echo "resolve-cargo-registry tests failed"
  exit 1
fi
echo "All resolve-cargo-registry tests passed"
