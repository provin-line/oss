package main

import (
	"os/exec"
	"strings"
	"testing"
)

// The architectural promise of this binary (package doc, main.go): cmd/pipeline
// is a data-plane CLIENT of the registry — it carries NO in-process registry
// and mounts NO ConnectRPC service of its own. This guard pins that on the
// PRODUCTION import graph (mirrors cmd/network's depsguard_test.go and
// pipeline/runtime's depsguard_test.go, which pin the same rule's other two
// edges), banning:
//
//  1. internal/netcompose — the control-plane composition root (main.go's own
//     /metrics doc comment already names this off-limits).
//  2. any OTHER cmd/ deployment root — no binary ever links another binary's
//     package main tree; cmd/network and cmd/standalone are today's concrete
//     siblings this catches, but the check is general so a future cmd/* added
//     the same way is caught too.
//  3. anything under network/pkg/services/... that is not one of the ALLOWED
//     families isAllowedNetworkPkgDep documents below — in particular every
//     service's handler package (proto<->domain conversion + the Connect
//     error mapping that IS "serving the RPC"), every service's persistence
//     package (auditor/filestore, chainmanager/store, didregistry/store,
//     payloadresolver/filestore, payloadresolver/memstore, payloadresolver/
//     storehandler, schemaregistry/store, tlogservice/mirrorstore,
//     vcresolver/filestore, vcresolver/memstore — enumerated here as of this
//     writing; isAllowedNetworkPkgDep bans them structurally, not by name, so
//     a persistence package added under a NEW service subpackage name is
//     caught too), and every service's ROOT package (a service's root
//     package is where its Service/handler-facing surface lives — see e.g.
//     network/pkg/services/schemaregistry/service.go).
//
// Run `go list -deps ./cmd/pipeline | grep 'network/pkg'` to see the current
// closure this test was derived from.
func TestProdDeps_NoRegistryServerCodeInPipelineBinary(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps",
		"github.com/provin-line/oss/cmd/pipeline",
	).CombinedOutput()
	if err != nil {
		t.Skipf("go list unavailable: %v\n%s", err, out)
	}
	const module = "github.com/provin-line/oss/"
	for _, line := range strings.Split(string(out), "\n") {
		dep := strings.TrimSpace(line)
		if dep == "" {
			continue
		}

		switch {
		case dep == module+"internal/netcompose":
			t.Errorf("cmd/pipeline production deps include %q — this binary must not carry the control-plane composition root (main.go's own /metrics doc names this off-limits)", dep)

		case strings.HasPrefix(dep, module+"cmd/") && dep != module+"cmd/pipeline":
			t.Errorf("cmd/pipeline production deps include %q — a data-plane node must never link another deployment root's package main tree", dep)

		case strings.HasPrefix(dep, module+"network/pkg/services/") && !isAllowedNetworkPkgDep(dep):
			t.Errorf("cmd/pipeline production deps include %q — a data-plane node must not carry registry SERVE-side code (handler/persistence/service-root); only a service's /client (or /wirecontract) may cross this boundary", dep)
		}
	}
}

// isAllowedNetworkPkgDep reports whether dep (a
// github.com/provin-line/oss/network/pkg/services/... import path) is one of
// the families this binary is allowed to carry. Every family is a WIRE-CLIENT
// concern — proto/connect stub + the shared shape both ends of the wire
// derive from — never a handler, a persistence backend, or a service's
// Service-implementation root. chainmanager used to be a documented exception
// here (its op name and signed-view builder lived on the service root, so
// reportclient — and transitively this binary — had to compile in the whole
// Service implementation to reach them); it now gets the SAME wirecontract
// leaf split auditor/payloadresolver/tlogservice already had (see
// chainmanager/wirecontract's package doc), so the exception is gone.
func isAllowedNetworkPkgDep(dep string) bool {
	const svcPrefix = "github.com/provin-line/oss/network/pkg/services/"
	rest := strings.TrimPrefix(dep, svcPrefix)
	parts := strings.SplitN(rest, "/", 2)
	svc := parts[0]
	sub := ""
	if len(parts) == 2 {
		sub = strings.SplitN(parts[1], "/", 2)[0]
	}

	// chainmanager names its client package "reportclient" (ReportEmitHealth
	// is the only op cmd/pipeline calls), not "client" like the other four
	// split services — so it needs its own branch rather than falling into
	// the generic sub == "client" check below. wireauth is its second allow:
	// the L2 AuthProof signing/verification leaf every OTHER service's client
	// (auditor/client, payloadresolver/client, tlogservice/client) also
	// imports directly, so it is a genuine cross-service wire-contract
	// sibling, not chainmanager-root-only code — see e.g.
	// auditor/client/client.go's own import of it. wirecontract is its third
	// allow, mirroring every other service's leaf. The service ROOT and every
	// other subpackage (store — subscription/allow-list persistence; infra —
	// transport operators; emithealth — health store; handler; evidence;
	// peerclient) are banned, same as every other service's
	// non-client/non-wirecontract subpackages.
	if svc == "chainmanager" {
		switch sub {
		case "wireauth", "reportclient", "wirecontract":
			return true
		default:
			return false
		}
	}

	// Every other service (auditor, didregistry, payloadresolver,
	// schemaregistry, signer, tlogservice, vcresolver): only its leaf /client
	// (the production network client cmd/pipeline actually calls) and
	// /wirecontract (the request/response shape both client and handler
	// derive the signed view from — no persistence, no serving logic) may
	// cross into this binary. Their /handler, any persistence package
	// (filestore, memstore, mirrorstore, store, storehandler), the service
	// ROOT package itself, and any other internal subpackage are all banned.
	return sub == "client" || sub == "wirecontract"
}
