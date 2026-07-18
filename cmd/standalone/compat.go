package main

import (
	"github.com/provin-line/oss/internal/httpserve"
	"github.com/provin-line/oss/internal/netcompose"
)

// Transitional aliases: cmd/standalone is deprecated and removed in a later
// PR in this recomposition series; these keep its remaining files and tests
// (written against the pre-extraction names) compiling against the extracted
// internal/netcompose (control-plane composition, this task) and
// internal/httpserve (shared HTTP/2 serving plumbing, a prior task) packages.
//
// Every alias below is used by at least one remaining cmd/standalone file or
// test; several go beyond netcompose's rename table because a remaining file
// or test references the pre-extraction name directly (a plain function/type
// alias resolves these with no call-site edit) rather than only through
// BuildHandler's parameters. See the task report for the full accounting.
type (
	readinessCheck              = netcompose.ReadinessCheck
	loopMetrics                 = netcompose.LoopMetrics
	strippedPublishHealthSource = netcompose.StrippedPublishHealthSource
	// schemaGetter: dataplane.go's dataPlaneDeps.SchemaGetter field keeps this
	// exact (unqualified) type name — aliasing here avoids touching that
	// field's declaration.
	schemaGetter = netcompose.SchemaGetter
)

var (
	// internal/netcompose (this task's extraction).
	BuildHandler       = netcompose.BuildHandler
	newDIDResolution   = netcompose.NewDIDResolution
	nodeDIDOf          = netcompose.NodeDIDOf
	buildAuditRunner   = netcompose.BuildAuditRunner
	buildBatchResolver = netcompose.BuildBatchResolver
	chainOperator      = netcompose.ChainOperator
	evidenceStoreCheck = netcompose.EvidenceStoreCheck
	natsCheck          = netcompose.NATSCheck
	pdpCheck           = netcompose.PDPCheck
	newCachedReadiness = netcompose.NewCachedReadiness
	maybeMountMetrics  = netcompose.MaybeMountMetrics
	newByRefHealthGate = netcompose.NewByRefHealthGate
	endpointURLs       = netcompose.EndpointURLs

	// Below this line: not in the task brief's rename table, but a remaining
	// cmd/standalone file or test references the pre-extraction name directly
	// (not only through a BuildHandler parameter), so extending compat.go is
	// the only way to keep it compiling without an unrelated signature change.
	//
	// registryBaseURL: the brief marks this "keep unexported", but
	// server_test.go (TestRegistryBaseURL_HitAndFallback,
	// TestRegistryBaseURL_ClosedFallbackInPrivateMode) calls it directly as a
	// unit under its old name — an unexported cross-package identifier cannot
	// be aliased at all, so it was exported as netcompose.RegistryBaseURL.
	// Flagged in the task report as a deviation from the brief's explicit text.
	registryBaseURL = netcompose.RegistryBaseURL
	// hostOnly: readiness_test.go (TestHostOnly) calls it directly.
	hostOnly = netcompose.HostOnly
	// buildMetricsHandler, withMetrics: metrics_test.go calls both directly
	// (not only through maybeMountMetrics).
	buildMetricsHandler = netcompose.BuildMetricsHandler
	withMetrics         = netcompose.WithMetrics
	// resolveSchemaRefAtBoot: dataplane.go's resolveSchema closure and two
	// tests (schemaresolver_test.go, schema_e2e_test.go) call it directly.
	resolveSchemaRefAtBoot = netcompose.ResolveSchemaRefAtBoot
	// outerRequestCapBytes: relocated from cmd/standalone/main.go into
	// internal/netcompose/server.go (it sizes against maxProofRequestBytes /
	// maxDocumentRequestBytes, which stay unexported/internal to that file);
	// main.go and main_test.go keep calling it under the old name.
	outerRequestCapBytes = netcompose.OuterRequestCapBytes
	// bearerInterceptor: relocated from cmd/standalone/dataplane.go into
	// internal/netcompose/batchresolver.go (its other caller, peerFetcher.Fetch,
	// moved there); dataplane.go's VC-store client wiring keeps calling it
	// under the old name.
	bearerInterceptor = netcompose.BearerInterceptor

	// internal/httpserve (a prior task's extraction; consolidated here from
	// cmd/standalone/main.go, which previously carried this same two-var block).
	buildServer = httpserve.BuildServer
	http2Server = httpserve.HTTP2Server
)
