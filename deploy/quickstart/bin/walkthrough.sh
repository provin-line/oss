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
# KNOWN GAP (README's own callout): the published policy-verifier image's
# declared authorization surface predates the separated topology's new wire
# calls (ReportEmitHealth, RetainPayload), so step ⑤ below currently never
# observes VERIFIED and this script exits 1 after its poll budget — a
# provin.auth (private repo) policy-declaration gap, not a bug here.
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

echo "④ HTTP push ingest (via pipeline, not network — network carries no data plane)"
curl -fsS -o /dev/null -w "  push status: %{http_code}\n" -X POST "$pipeline_url/ingest/src/push" \
	-H "Authorization: Bearer $token" -H "Content-Type: application/json" \
	-d '{"sensor":"temp-01","celsius":21.5}'

echo "⑤ audit verdict (polling for VERIFIED)"
for _ in $(seq 1 15); do
	body="$(curl -fsS -X POST "$registry/dplaax.audit.v1.AuditService/ListAuditStatuses" \
		-H "Authorization: Bearer $token" -H "Content-Type: application/json" -d '{"pageSize":10}')"
	if printf '%s' "$body" | grep -q CONFIDENCE_VERIFIED; then
		echo "  ✅ VERIFIED"
		printf '%s\n' "$body"
		exit 0
	fi
	sleep 1
done

echo "  ✗ no VERIFIED verdict after 15s — inspect: docker compose logs network pipeline (see this script's KNOWN GAP note, top)" >&2
exit 1
