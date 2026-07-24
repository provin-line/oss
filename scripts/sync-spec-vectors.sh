#!/usr/bin/env bash
# Sync the dplaax conformance vectors byte-exact from the spec repo and
# regenerate the sha256 manifest that conformance's drift test pins.
# The sync is push-based and deliberate (same policy as vc/contexts): run it
# when adopting a spec change, commit the vendored diff, and let the manifest
# test prove the copies were not edited in place.
#
# Usage: scripts/sync-spec-vectors.sh [path-to-dplaax.spec]
set -euo pipefail

SPEC="${1:-$(dirname "$0")/../../dplaax.spec}"
DST="$(cd "$(dirname "$0")/.." && pwd)/conformance/vectors/dplaax"

if [ ! -d "$SPEC/vectors" ]; then
  echo "spec vectors not found at $SPEC/vectors" >&2
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

echo "synced $(find "$DST" -name '*.json' | wc -l | tr -d ' ') vectors from $SPEC/vectors"
