# P0-6 TLS closure — evidence record (2026-07-15)

The P0-6 debate closed **Conditional-Close**: the TLS mechanism was implemented
and had no blocking defect, but neither participant could run anything —
"Go binary arch mismatch (exit 139) + docker daemon 権限なし" — so every
"確認済み" in that round was read, not run. The eight closure conditions exist to
convert that reading into execution. This records the execution.

**The environment constraint no longer holds.** Go builds and tests run here, and
the Docker daemon is reachable. That is what made these conditions checkable at
all, and it is why they are worth checking: the very first actual boot found a
quickstart that had never started (see #6).

## Condition-by-condition

| # | Condition | Result |
| --- | --- | --- |
| 1 | `make lint` / `go test ./...` / `go test -race ./...` green on a supported toolchain | **PASS** — `LINT_RC=0`; `TEST_RC=0` (89 pkgs, 0 fail); `RACE_RC=0` (89 pkgs, 0 fail) |
| 2 | Explicit `MinVersion = tls.VersionTLS12` + version-floor test | **PASS** — `core.TLSConfig.LoadServerTLS` pins it; `TestLoadServerTLS_EnforcesTheFloorOnTheWire` drives real handshakes (1.0/1.1 fail, 1.2/1.3 negotiate ≥ floor) |
| 3 | Early `LoadX509KeyPair` preflight + negative cert tests | **PASS** — preflight runs before any store/transport in `main`; `TestLoadServerTLS_FailsClosedOnBadMaterial` covers unreadable cert, unreadable key, invalid PEM, mismatched pair; `TestStandalone_BadCertificateFailsBootBeforeSideEffects` proves from OUTSIDE the process that boot dies with no data directory created |
| 4 | Native-TLS route integration | **PASS** — `TestNativeTLS_RouteIntegration` serves the real `BuildHandler` mux (+ metrics gate) over TLS: HTTP/2 via ALPN, plain-HTTP refused on the TLS port, `/healthz` `/readyz` `/metrics`, `/did` resolution after an authenticated `RegisterOwner`, SAN mismatch refused vs matching SAN accepted |
| 5 | Standalone actual-boot smoke | **PASS** — `TestStandalone_ActualBootOverTLS` builds the binary, boots it from a real config file with an ephemeral cert against an embedded broker: `serving mode = direct-tls`, readiness over HTTPS, a served request, `SIGTERM` → `shutdown complete`, exit 0 |
| 6 | Quickstart actual-boot smoke on the intended cleartext dev profile | **PASS, after fixing two defects it exposed** — see below |
| 7 | Endpoint migration matrix | **PASS** — the seven surfaces are enumerated and pinned (`TestTLSEndpointMatrix_IsComplete`), and `core.RequireHTTPSEndpoints` warns at boot for each config-supplied `http://` URL on a TLS posture |
| 8 | CHANGELOG / migration note | **PASS** — `CHANGELOG.md` (P0-6 closure + Fixed), `network/pkg/core/reference.conf` (TLS floor, stdlib cipher dependency), `SECURITY.md` (transport claim boundary, cipher default, `allow-cleartext` non-claim), `docs/architecture/deployment.md` + `.ja.md` (floor, preflight/restart rotation, endpoint matrix) |

## What #6 found

The ledger's sequence ran as written:

```text
docker compose config --quiet    → RC=0
docker compose up --build --wait → RC=0, "node-1 Healthy"
deploy/quickstart/bin/walkthrough.sh → RC=1, connection refused
```

The stack reported ready while the node had **never booted**:
`docker compose logs node | grep -c "listening on"` = 0, `State: restarting`,
no published port. Two independent defects, both predating this work
(reproduced at `bf03095`, the very commit the P0-6 debate reviewed):

1. **The quickstart's node config never parsed** — a defect in the HOCON library
   then in use, not a malformed config. gurkankaymak/hocon v1.2.23 violates the
   spec ("anything between `//` or `#` and the next newline is considered a
   comment and ignored"): a `#` comment containing `//` swallows the FOLLOWING
   line, so comment TEXT changes the parsed document. Here the swallowed line was
   `service-endpoints {` — an opening brace vanished, so the parser rejected the
   file's final `}` as a stray. `docker compose config` validates the compose
   file, not the node config the container reads, so static checking could never
   have caught it.

   Chasing it to the root mattered twice over. The same defect had **silently
   deleted three reference defaults** (`auth.opa.base-url`, `auth.cedar.base-url`,
   `registry.service-endpoints` all nil) in files that parse perfectly — stopping
   at "the quickstart config is malformed" would have left those gone. And the
   defect turned out to be unfixable by upgrade: v1.2.23 is that library's
   latest, every recent version reproduces it, and the upstream report (#27) has
   been open since 2022. The config layer now uses `o3co/go.hocon`, a full
   Lightbend-spec implementation, which handles every shape correctly — including
   the quickstart config in its original, never-booted form. The comments keep
   their URLs.

2. **`up --wait` could not tell a crash-loop from a healthy node.** The node
   service had no healthcheck, so `restart: on-failure` kept a never-booting
   container "running" and the stack declared itself ready.

Fixed: the parser is replaced (`hoconconfig` package doc records why);
`TestShippedConfigsParse` parses every shipped `.conf` with the parser the
binaries use; `TestReferenceDefaultsSurviveURLComments` pins the silent-drop
regression; the node service gained a `/readyz` healthcheck.

After the fixes, the full sequence:

```text
docker compose config --quiet    → RC=0
docker compose up --build --wait → RC=0; node Started → Waiting → Healthy
                                    (docker inspect: healthy, failing streak 0)
deploy/quickstart/bin/walkthrough.sh → RC=0
  owner init → DID grant → pipeline+process issue → HTTP push (202)
  → audit verdict: ✅ VERIFIED
     dataIntegrity / signerAuthenticity / chainConsistency = CONFIDENCE_VERIFIED
docker compose down -v           → RC=0
```

That walkthrough is also the first end-to-end run of the ForkW-1 Multikey / W3C
proof shape through a real deployment stack.

## Scope

This is the TLS transport posture. It is not a claim about the outbound side:
resolver/auth-provider SSRF, redirect and DNS-rebinding hardening, and cache and
freshness bounds are P1-A, exactly as the ledger allocated them. "HTTPS" here
means this listener's hop is confidential and authenticated to its certificate —
it does not mean a fetch target is trusted, reachable, or fresh.

## Provenance

- Ledger: `.tmp/provin-p0-6-decision-ledger.md` (Conditional-Close, 8 conditions)
- Repo state: the ForkW-1 line (`3d28823`..) plus this closure work
