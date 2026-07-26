#!/usr/bin/env bash
#
# Drive one record from HTTP push ingest to a VERIFIED audit verdict through the
# running quickstart stack (see README §2) — the separated topology:
# `network` (registry) + `pipeline` (data plane) as two independent
# processes. Assumes `docker compose up --build` is already healthy. Requires
# the `provin` CLI, node, bash, openssl, curl, and `docker compose` on PATH
# (for pulling the pipeline's external-key export out of the `provisioned`
# volume — see README §2c).
#
# Usage: walkthrough.sh [--provin <path>] [--registry <url>] [--pipeline-url <url>] [--provider <url>]

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
ossroot="$(cd "$here/../../.." && pwd)"
quickstartdir="$(cd "$here/.." && pwd)"

provin=""
registry="http://localhost:8443"
pipeline_url="http://localhost:8444"
provider="http://localhost:3000"
secret="${OAUTH_JWT_SECRET:-quickstart-dev-secret-change-me}"
workdir="$(mktemp -d)"

while [ $# -gt 0 ]; do
	case "$1" in
		--provin)       provin="$2"; shift 2 ;;
		--registry)     registry="$2"; shift 2 ;;
		--pipeline-url) pipeline_url="$2"; shift 2 ;;
		--provider)     provider="$2"; shift 2 ;;
		*) echo "walkthrough: unknown arg $1" >&2; exit 2 ;;
	esac
done

if [ -z "$provin" ]; then
	provin="$workdir/provin"
	echo "→ building provin CLI"
	(cd "$ossroot" && go build -o "$provin" ./cmd/provin)
fi

owner="did:dplaax:poc.dplaax.dev:org:acme"
pipeline="$owner:pipeline:readings"
process="$pipeline:process:s1"
key="$workdir/acme-owner.jwk"

echo "① bootstrap token → owner init"
bootstrap="$("$here/mint-bootstrap-token.sh" --owner "$owner" --secret "$secret" --issuer http://auth-provider:3000)"
"$provin" owner init --did "$owner" --key "$key" --registry "$registry" --token "$bootstrap"

echo "② DID grant → real JWT"
token="$(node "$here/did-token.mjs" --key "$key" --did "$owner" --provider "$provider" --client quickstart)"

echo "③ pipeline + process create (external-key mode — the pipeline's own local keys, never the registry's)"
extkeys="$workdir/pipeline-external-keys.json"
(cd "$quickstartdir" && docker compose cp network:/provisioned/pipeline-external-keys.json "$extkeys")
"$provin" pipeline create --did "$pipeline" --owner-key "$key" --registry "$registry" --token "$token" --external-key "$extkeys"
"$provin" process  create --did "$process"  --owner-key "$key" --registry "$registry" --token "$token" --external-key "$extkeys"

# ListAuditStatuses, raw.
audit_list() {
	curl -fsS -X POST "$registry/dplaax.audit.v1.AuditService/ListAuditStatuses" \
		-H "Authorization: Bearer $token" -H "Content-Type: application/json" \
		-d '{"pageSize":50}'
}

# Print the head that is BOTH absent from the pre-push snapshot AND verified on
# the overall verdict and all three axes; exit 1 when there is none yet, so the
# caller can keep polling.
#
# Structural JSON rather than grep, deliberately. Matching CONFIDENCE_VERIFIED
# anywhere in a fifty-entry response says nothing about which record produced
# it, nor whether every axis passed — a stale verdict from an earlier run
# satisfies it. A walkthrough that can report success without proving the thing
# it advertises is worse than no walkthrough: it is how README §2f shipped an
# instruction that had never been executed.
new_verified_head() {
	node -e '
const fs = require("fs");
const before = new Set((JSON.parse(fs.readFileSync(process.argv[1], "utf8")).entries ?? []).map(e => e.headHash));
let s = "";
process.stdin.on("data", d => (s += d)).on("end", () => {
  const V = "CONFIDENCE_VERIFIED";
  for (const e of JSON.parse(s).entries ?? []) {
    if (before.has(e.headHash)) continue;
    const lc = e.status?.linearChain;
    if (!lc) continue;
    const ax = lc.axes ?? {};
    if (lc.confidence === V && ax.dataIntegrity === V && ax.signerAuthenticity === V && ax.chainConsistency === V) {
      console.log(e.headHash);
      process.exit(0);
    }
  }
  process.exit(1);
});' "$1"
}

echo "④ HTTP push ingest (via pipeline, not network — network carries no data plane)"
# Snapshot first: the verdict accepted below must belong to the record this run
# pushed, not to one an earlier run left behind.
before="$workdir/heads-before.json"
audit_list > "$before"
curl -fsS -o /dev/null -w "  push status: %{http_code}\n" -X POST "$pipeline_url/ingest/src/push" \
	-H "Authorization: Bearer $token" -H "Content-Type: application/json" \
	-d '{"sensor":"temp-01","celsius":21.5}'

echo "⑤ audit verdict for THAT record — overall plus all three axes"
head_hash=""
for _ in $(seq 1 15); do
	if head_hash="$(audit_list | new_verified_head "$before")"; then
		echo "  ✅ VERIFIED — $head_hash"
		break
	fi
	head_hash=""
	sleep 1
done
if [ -z "$head_hash" ]; then
	echo "  ✗ no NEW fully-VERIFIED verdict after 15s — inspect: docker compose logs network pipeline" >&2
	audit_list >&2
	exit 1
fi

# The registry namespace the quickstart's DIDs live under, taken from the owner
# DID rather than repeated as a literal.
ns="$(printf '%s' "$owner" | cut -d: -f3)"

echo "⑥ export an offline evidence bundle for that head (README §2f)"
bundle="$workdir/bundle"
# --allow-loopback: the --*-base overrides point DID resolution at localhost,
# and the SSRF guard on those fetches is fail-closed. Without it the issuers do
# not resolve, signer-authenticity and chain-consistency come back
# indeterminate, and export correctly refuses to write the archive.
export_out="$("$provin" bundle export --head "$head_hash" --out "$bundle" \
	--registry "$registry" --token "$token" \
	--allow-loopback \
	--did-base         "$ns=$registry" \
	--vc-resolver-base "$ns=$registry" \
	--audit-base       "$ns=$registry")"
printf '%s\n' "$export_out"

# Both anchors, not just the head: --head anchors what data flowed, --digest
# anchors the whole archive including the authority documents. Verifying only
# the head would leave the stronger anchor unexercised — and an unexercised
# documented flag is how README §2f came to ship two defects.
digest="$(printf '%s\n' "$export_out" | sed -n 's/^bundle digest: *//p')"
if [ -z "$digest" ]; then
	echo "could not parse the bundle digest out of export's output" >&2
	exit 1
fi

echo "⑦ verify the bundle offline — what a relying party actually does"
"$provin" bundle verify --bundle "$bundle" --head "$head_hash" --digest "$digest"
echo "  ✅ bundle verifies offline against $head_hash and $digest"
