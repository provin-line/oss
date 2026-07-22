package main

import (
	"github.com/provin-line/oss/internal/httpserve"
	"github.com/provin-line/oss/internal/netcompose"
)

// Transitional aliases: cmd/standalone is deprecated and removed in a later
// PR in this recomposition series; these keep its remaining files compiling
// against the extracted internal/netcompose (control-plane composition) and
// internal/httpserve (shared HTTP/2 serving plumbing) packages.
//
// Every alias below is used by at least one remaining cmd/standalone
// production file or test. Extended strictly by compile error — see the task
// report for the full accounting.
type (
	readinessCheck = netcompose.ReadinessCheck
	// loopMetrics: metrics_test.go's handler-family assertions keep this exact
	// (unqualified) type name. pipeline/runtime defines its own equivalent
	// alias (LoopMetrics) for the moved dataplane.go — the two are independent
	// aliases onto the same netcompose type, not a shared symbol.
	loopMetrics = netcompose.LoopMetrics
	// strippedPublishHealthSource: main.go's byRefSources slice keeps this
	// exact (unqualified) type name.
	strippedPublishHealthSource = netcompose.StrippedPublishHealthSource
)

var (
	// internal/netcompose (the control-plane composition).
	BuildHandler       = netcompose.BuildHandler
	newDIDResolution   = netcompose.NewDIDResolution
	nodeDIDOf          = netcompose.NodeDIDOf
	buildAuditRunner   = netcompose.BuildAuditRunner
	buildBatchResolver = netcompose.BuildBatchResolver
	chainOperator      = netcompose.ChainOperator
	evidenceStoreCheck = netcompose.EvidenceStoreCheck
	natsCheck          = netcompose.NATSCheck
	pdpCheck           = netcompose.PDPCheck
	maybeMountMetrics  = netcompose.MaybeMountMetrics
	newByRefHealthGate = netcompose.NewByRefHealthGate
	endpointURLs       = netcompose.EndpointURLs
	// buildMetricsHandler, withMetrics: metrics_test.go calls both directly
	// (not only through maybeMountMetrics).
	buildMetricsHandler = netcompose.BuildMetricsHandler
	withMetrics         = netcompose.WithMetrics

	// outerRequestCapBytes: relocated from cmd/standalone/main.go into
	// internal/netcompose/server.go (it sizes against maxProofRequestBytes /
	// maxDocumentRequestBytes, which stay unexported/internal to that file);
	// main.go and main_test.go keep calling it under the old name.
	outerRequestCapBytes = netcompose.OuterRequestCapBytes

	// internal/httpserve (shared HTTP/2 serving plumbing).
	buildServer = httpserve.BuildServer
	http2Server = httpserve.HTTP2Server
)
