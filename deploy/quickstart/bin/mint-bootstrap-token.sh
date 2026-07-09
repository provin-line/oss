#!/usr/bin/env bash
#
# Mint a short-lived HS256 bootstrap JWT for the quickstart's first-owner
# registration. This solves the chicken-and-egg: RegisterOwner is L1-gated
# (dids:register), but the auth.provider's DID grant can only issue a token for
# an ALREADY-registered owner DID — so the very first registration has no token
# to present. The quickstart shares one HS256 secret between the provider and
# the policy-verifier (a dev simplification), so we mint a token signed with the
# same secret directly, scoped to register:dids only, and use it for one
# `provin owner init`. After that the owner is resolvable and the normal DID
# grant path takes over.
#
# This is dev/evaluation only. A production JWKS/RS256 provider has no shared
# secret to mint against — see the README "first-owner bootstrap" note for the
# production options.
#
# Usage:
#   mint-bootstrap-token.sh --owner <owner-did> [--secret <s>] [--issuer <iss>] [--ttl <sec>]
# The secret defaults to $OAUTH_JWT_SECRET; the issuer to $OAUTH_JWT_ISSUER.

set -euo pipefail

owner=""
secret="${OAUTH_JWT_SECRET:-}"
issuer="${OAUTH_JWT_ISSUER:-}"
ttl=600

while [ $# -gt 0 ]; do
	case "$1" in
		--owner)  owner="$2"; shift 2 ;;
		--secret) secret="$2"; shift 2 ;;
		--issuer) issuer="$2"; shift 2 ;;
		--ttl)    ttl="$2"; shift 2 ;;
		*) echo "mint-bootstrap-token: unknown arg $1" >&2; exit 2 ;;
	esac
done

if [ -z "$owner" ]; then
	echo "mint-bootstrap-token: --owner <owner-did> is required" >&2
	exit 2
fi
if [ -z "$secret" ]; then
	echo "mint-bootstrap-token: no secret (pass --secret or set OAUTH_JWT_SECRET)" >&2
	exit 2
fi

# base64url without padding, from stdin.
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

now="$(date +%s)"
exp="$((now + ttl))"

header='{"alg":"HS256","typ":"JWT"}'
# scope is action-first (`${action}:${resourceType}`) — the policy-verifier's
# ResourceActionScopeRuleCollector matches "register:dids" to the (dids,
# register) request. A no-scope token would be allowed for the whole surface;
# scoping it to register:dids keeps the bootstrap token least-privilege.
payload="$(printf '{"sub":"%s","scope":"register:dids","iat":%s,"exp":%s,"iss":"%s"}' \
	"$owner" "$now" "$exp" "$issuer")"

h="$(printf '%s' "$header"  | b64url)"
p="$(printf '%s' "$payload" | b64url)"
sig="$(printf '%s' "$h.$p" | openssl dgst -sha256 -hmac "$secret" -binary | b64url)"

printf '%s.%s.%s\n' "$h" "$p" "$sig"
