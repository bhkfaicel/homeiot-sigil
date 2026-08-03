#!/usr/bin/env bash
# Resolve which Forgejo Cargo registry to publish to for a given git tag.
#
# Usage: resolve-cargo-registry.sh <tag_name>
# Prints: forgejorc (unstable / homeiot-rc) or forgejo (stable / homeiot)
#
# Convention: any tag containing "-rc" is a prerelease published to forgejorc;
# all other v* tags are stable and published to forgejo.
set -euo pipefail

TAG_NAME="${1:?usage: resolve-cargo-registry.sh <tag_name>}"

if [[ "$TAG_NAME" == *-rc* ]]; then
  echo "forgejorc"
else
  echo "forgejo"
fi
