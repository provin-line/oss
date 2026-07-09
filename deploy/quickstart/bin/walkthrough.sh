#!/usr/bin/env bash
#
# Drive one record from HTTP push ingest to a VERIFIED audit verdict through the
# running quickstart stack (see README §2). Assumes `docker compose up --build`
# is already healthy. Requires the `provin` CLI, node, bash, openssl, curl.
#
# Usage: walkthrough.sh [--provin <path>] [--registry <url>] [--provider <url>]

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
ossroot="$(cd "$here/../../.." && pwd)"

provin=""
registry="http://localhost:8443"
provider="http://localhost:3000"
secret="${OAUTH_JWT_SECRET:-quickstart-dev-secret-change-me}"
workdir="$(mktemp -d)"

while [ $# -gt 0 ]; do
	case "$1" in
		--provin)   provin="$2"; shift 2 ;;
		--registry) registry="$2"; shift 2 ;;
		--provider) provider="$2"; shift 2 ;;
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

echo "③ pipeline + process create"
"$provin" pipeline create --did "$pipeline" --owner-key "$key" --registry "$registry" --token "$token"
"$provin" process  create --did "$process"  --owner-key "$key" --registry "$registry" --token "$token"

echo "④ HTTP push ingest"
curl -fsS -o /dev/null -w "  push status: %{http_code}\n" -X POST "$registry/ingest/src/push" \
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

echo "  ✗ no VERIFIED verdict after 15s — inspect: docker compose logs node" >&2
exit 1
