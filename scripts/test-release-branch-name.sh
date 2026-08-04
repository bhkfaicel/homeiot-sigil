#!/usr/bin/env bash
# Unit tests for scripts/release-branch-name.sh
set -euo pipefail
cd "$(dirname "$0")/.."

SCRIPT=scripts/release-branch-name.sh
chmod +x "$SCRIPT"

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

assert_eq "$("$SCRIPT" "1.0.8")" "release/1.0" "1.0.8 → release/1.0"
assert_eq "$("$SCRIPT" "1.0.0")" "release/1.0" "1.0.0 → release/1.0"
assert_eq "$("$SCRIPT" "2.3.1")" "release/2.3" "2.3.1 → release/2.3"
assert_eq "$("$SCRIPT" "0.1.0")" "release/0.1" "0.1.0 → release/0.1"

if "$SCRIPT" "1.0.8-rc" 2>/dev/null; then
  echo "FAIL: should reject -rc versions"
  fail=1
else
  echo "ok: rejects -rc versions"
fi

if "$SCRIPT" "not-a-version" 2>/dev/null; then
  echo "FAIL: should reject invalid versions"
  fail=1
else
  echo "ok: rejects invalid versions"
fi

if [[ "$fail" -ne 0 ]]; then
  echo "release-branch-name tests failed"
  exit 1
fi
echo "All release-branch-name tests passed"
