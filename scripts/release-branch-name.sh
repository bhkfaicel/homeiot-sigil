#!/usr/bin/env bash
# Derive the maintenance branch name for a stable SemVer version.
#
# Usage: release-branch-name.sh <version>
# Example: release-branch-name.sh 1.0.8  →  prints release/1.0
#
# The branch tracks the X.Y line for hotfixes (1.0.1, 1.0.2, …) while `dev`
# continues toward the next minor/major.
set -euo pipefail

VERSION="${1:?usage: release-branch-name.sh <version>}"

if [[ "$VERSION" == *-rc* ]]; then
  echo "error: expected a stable version (no -rc): got '${VERSION}'" >&2
  exit 1
fi

# Accept X.Y or X.Y.Z (optional pre-release/build metadata already rejected via -rc check).
if [[ ! "$VERSION" =~ ^([0-9]+)\.([0-9]+)(\.[0-9]+)?$ ]]; then
  echo "error: version '${VERSION}' is not X.Y or X.Y.Z" >&2
  exit 1
fi

MAJOR="${BASH_REMATCH[1]}"
MINOR="${BASH_REMATCH[2]}"
echo "release/${MAJOR}.${MINOR}"
