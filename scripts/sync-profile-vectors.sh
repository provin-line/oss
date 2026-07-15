#!/usr/bin/env bash
# Sync the provin PROFILE conformance vectors byte-exact from the profile spec
# and regenerate the sha256 manifest that conformance's drift test pins.
#
# Two spec repos, two syncs, on purpose. dPLaaX owns the wire and its vectors
# (sync-spec-vectors.sh → vectors/dplaax); the provin profile owns what a claim
# ASSERTS and its vectors land here (vectors/provin). Mixing them into one
# directory would let a profile vector look like a protocol norm — the exact
# confusion the two repositories exist to end.
#
# The sync is push-based and deliberate (same policy as vc/contexts): run it
# when adopting a spec change, commit the vendored diff, and let the manifest
# test prove the copies were not edited in place.
#
# Usage: scripts/sync-profile-vectors.sh [path-to-provin.profile.spec]
set -euo pipefail

SPEC="${1:-$(dirname "$0")/../../provin.profile.spec}"
DST="$(cd "$(dirname "$0")/.." && pwd)/conformance/vectors/provin"

if [ ! -d "$SPEC/vectors" ]; then
  echo "profile spec vectors not found at $SPEC/vectors" >&2
  exit 1
fi

mkdir -p "$DST"
rm -f "$DST"/*.json "$DST/MANIFEST.sha256"
cp "$SPEC"/vectors/*.json "$DST"/

(
  cd "$DST"
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -- *.json > MANIFEST.sha256
  else
    sha256sum -- *.json > MANIFEST.sha256
  fi
)

echo "synced $(find "$DST" -name '*.json' | wc -l | tr -d ' ') profile vectors from $SPEC/vectors"
