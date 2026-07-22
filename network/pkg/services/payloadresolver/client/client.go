// Package client is the production network client for the payload services:
// ResolvePayload dereferences a by-reference payload by content address from a
// publisher's serving boundary; Retain streams THIS node's own produced bytes
// to its own PayloadStoreService for later by-reference serving. One type,
// both directions — mirrors vcresolver/client's "one type, both directions of
// the same service" precedent. Both directions sign in-band with wireauth (as
// a configured node identity); ResolvePayload streams the response and caps
// the assembled size (dialing whichever serving boundary is passed per call,
// since it fetches from arbitrary publishers), while Retain streams the
// request to a FIXED endpoint (Config.StoreEndpoint — this node's own control
// plane, unlike ResolvePayload's arbitrary per-call target).
//
// It imports the generated client, connect, crypto, and the payloadresolver
// service's wirecontract LEAF (for the RetainPayload op name + signed-view
// builder shared with storehandler, so the two derivations cannot drift —
// mirrors auditor/client importing auditor's wirecontract leaf for the same
// reason; PR3b Task 2 moved these out of the payloadresolver service root so
// this client never pulls in the root's store/handler domain logic) — never
// the payloadresolver service root itself, and never pipeline/ (AGENTS.md
// layer rule: network and pipeline interact only over the wire). The
// compile-time assertion that *Resolver satisfies pipeline's PayloadResolver
// seam lives in the consumer (cmd/standalone), exactly as vcresolver/client
// keeps its chainwalk.CredentialResolver assertion there.
package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/crypto"
	chainpb "github.com/provin-line/oss/gen/go/dplaax/chain/v1"
	payloadpb "github.com/provin-line/oss/gen/go/dplaax/payload/v1"
	"github.com/provin-line/oss/gen/go/dplaax/payload/v1/payloadpbconnect"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/wireauth"
	"github.com/provin-line/oss/network/pkg/services/payloadresolver/wirecontract"
)

// opResolvePayload MUST match the publisher verifier's signed view.
const opResolvePayload = "ResolvePayload"

// Fetch-budget defaults, applied when Config leaves them non-positive. They are
// imposed on every fetch INDEPENDENT of the caller's context, because a
// consuming loop passes the process-lifetime context (no per-fetch deadline),
// and an untrusted serving boundary must not be able to pin that loop forever.
const (
	// DefaultMaxBytes caps an assembled payload — a memory-safety bound, since
	// the client buffers the whole payload to verify it against the content
	// address.
	DefaultMaxBytes = 64 << 20 // 64 MiB
	// DefaultFetchTimeout bounds one whole fetch (dial + every chunk). Generous
	// enough for a large payload over a slow-but-honest link.
	DefaultFetchTimeout = 2 * time.Minute
	// DefaultIdleTimeout bounds the gap between received chunks (and between the
	// request and the first chunk) — the trickle defense: a slow steady stream
	// trips idle even when the total budget is generous.
	DefaultIdleTimeout = 30 * time.Second
	// DefaultRetainChunkSize is Retain's outbound frame size when
	// Config.RetainChunkSize is left non-positive — sized well under the
	// server's default max-retain-chunk-size (1 MiB), and matching the sibling
	// PayloadService handler's own chunk-size convention (payloadresolver/
	// handler.chunkSize) for consistency across this domain's read and write
	// sides.
	DefaultRetainChunkSize = 256 << 10 // 256 KiB
)

var (
	// ErrNotFound reports a definitive miss: the serving boundary authoritatively
	// holds no payload at the content address (a publisher that agreed to
	// by-reference delivery and cannot serve a payload it emitted has broken its
	// retention obligation). Distinguished for observability; the consuming runtime
	// treats it the same as any other fetch failure (a liveness failure).
	ErrNotFound = errors.New("payloadresolver/client: payload not found")
	// ErrFetchTimeout reports that a fetch exceeded the total per-fetch budget
	// (Config.FetchTimeout). A liveness failure, distinguished for observability.
	ErrFetchTimeout = errors.New("payloadresolver/client: fetch exceeded total budget")
	// ErrFetchStalled reports that a fetch made no progress within the idle budget
	// (Config.IdleTimeout) — the malicious-trickle / no-response defense. A
	// liveness failure, distinguished for observability.
	ErrFetchStalled = errors.New("payloadresolver/client: fetch stalled (idle budget exceeded)")
)

// Config configures a Resolver. Signer/SignerDID/HTTPClient are required; the
// three fetch bounds fall back to their Default* when non-positive.
//
// StoreEndpoint and RetainChunkSize serve Retain only (ResolvePayload dials
// whichever serving boundary is passed per call and never reads either).
type Config struct {
	// Signer signs each call's wireauth proof as SignerDID.
	Signer    crypto.Signer
	SignerDID string
	// HTTPClient dials the serving boundary; supply an SSRF-guarded client, e.g.
	// core.URLGuard.HTTPClient().
	HTTPClient connect.HTTPClient
	// MaxBytes caps the assembled payload (<=0 → DefaultMaxBytes).
	MaxBytes int
	// FetchTimeout bounds one whole fetch (<=0 → DefaultFetchTimeout).
	FetchTimeout time.Duration
	// IdleTimeout bounds the gap between received chunks (<=0 → DefaultIdleTimeout).
	IdleTimeout time.Duration
	// StoreEndpoint is the base URL of THIS node's OWN PayloadStoreService —
	// Retain's fixed target. Unlike ResolvePayload's per-call upstreamEndpoint
	// (which dials arbitrary publishers), a node retains only its own produced
	// payloads with its own control-plane surface, so the target is fixed at
	// construction (mirrors auditor/client.Config.BaseURL). Required for
	// Retain; unused by ResolvePayload.
	StoreEndpoint string
	// RetainChunkSize bounds one outbound Retain frame (<=0 →
	// DefaultRetainChunkSize). Keep it at or under the server's configured
	// max-retain-chunk-size, or every frame trips the server's per-chunk read
	// cap (ResourceExhausted).
	RetainChunkSize int
	// Bearer, if non-empty, is presented as the Authorization: Bearer header
	// on every Retain call ONLY. RetainPayload is mounted behind L1 authz IN
	// ADDITION to the L2 wireauth proof (wirecontract.OpRetainPayload)
	// Retain already signs. It deliberately does NOT apply to ResolvePayload:
	// that RPC dials arbitrary publisher-supplied endpoints (upstreamEndpoint
	// is a per-call argument, never this node's own control plane), so
	// presenting this node's L1 credential there would leak it to a
	// potentially untrusted third party — see Retain's own doc for how this
	// is enforced (a dedicated client bound to StoreEndpoint, never HTTPClient
	// wrapped for arbitrary dialing). Empty presents no header on Retain
	// either. Convention mirrors internal/netcompose.BearerInterceptor,
	// replicated here rather than imported (a leaf client package must not
	// import the composition root).
	Bearer string
}

// Resolver is a node's handle to a PayloadService/PayloadStoreService pair:
// one signing identity, both directions. ResolvePayload dials any serving
// boundary passed to it, over the bare httpClient (no bearer — see
// retainClient's doc); Retain dials Config.StoreEndpoint via retainClient,
// its OWN pre-built client instance.
type Resolver struct {
	signer          crypto.Signer
	signerDID       string
	httpClient      connect.HTTPClient
	maxBytes        int
	fetchTimeout    time.Duration
	idleTimeout     time.Duration
	storeEndpoint   string
	retainChunkSize int
	// retainClient is Retain's OWN ConnectRPC client, built once in New and
	// bound to storeEndpoint with the L1 bearer interceptor attached — NEVER
	// httpClient re-wrapped, and never shared with ResolvePayload's per-call
	// client construction. ResolvePayload dials whichever endpoint a caller
	// passes (an arbitrary, potentially untrusted publisher); if the bearer
	// interceptor were attached to httpClient itself, or if Retain built its
	// client from httpClient the way ResolvePayload does, this node's L1
	// credential would be presented to every publisher ResolvePayload ever
	// fetches from — a bearer leak. nil when Config.StoreEndpoint is empty
	// (Retain rejects that case before ever touching this field).
	retainClient payloadpbconnect.PayloadStoreServiceClient
}

// New returns a Resolver from cfg, applying the Default* bounds for any
// non-positive value.
func New(cfg Config) *Resolver {
	maxBytes := cfg.MaxBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	fetchTimeout := cfg.FetchTimeout
	if fetchTimeout <= 0 {
		fetchTimeout = DefaultFetchTimeout
	}
	idleTimeout := cfg.IdleTimeout
	if idleTimeout <= 0 {
		idleTimeout = DefaultIdleTimeout
	}
	retainChunkSize := cfg.RetainChunkSize
	if retainChunkSize <= 0 {
		retainChunkSize = DefaultRetainChunkSize
	}
	var retainClient payloadpbconnect.PayloadStoreServiceClient
	if cfg.StoreEndpoint != "" {
		retainClient = payloadpbconnect.NewPayloadStoreServiceClient(cfg.HTTPClient, cfg.StoreEndpoint,
			connect.WithInterceptors(bearerInterceptor(cfg.Bearer)))
	}
	return &Resolver{
		signer:          cfg.Signer,
		signerDID:       cfg.SignerDID,
		httpClient:      cfg.HTTPClient,
		maxBytes:        maxBytes,
		fetchTimeout:    fetchTimeout,
		idleTimeout:     idleTimeout,
		storeEndpoint:   cfg.StoreEndpoint,
		retainChunkSize: retainChunkSize,
		retainClient:    retainClient,
	}
}

// bearerInterceptor sets the L1 PDP Authorization bearer on every outgoing
// call. An empty token sets no header. The header key/value convention
// mirrors internal/netcompose.BearerInterceptor exactly — duplicated rather
// than imported, since this client package must stay independent of the
// composition root (AGENTS.md layer rule) — but the mechanism cannot be a
// plain connect.UnaryInterceptorFunc the way auditor/client's and
// reportclient's are: RetainPayload is CLIENT-STREAMING, and
// UnaryInterceptorFunc's WrapStreamingClient is documented as a no-op ("has
// no effect on streaming RPCs") — attaching one here would silently never
// set the header. retainBearerInterceptor implements the full
// connect.Interceptor instead, setting the header on the stream's
// RequestHeader before the caller ever sends a frame. Only ever attached to
// retainClient (see its doc) — never to a client ResolvePayload builds.
func bearerInterceptor(token string) connect.Interceptor {
	return retainBearerInterceptor{token: token}
}

type retainBearerInterceptor struct{ token string }

func (i retainBearerInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		if i.token != "" && req.Spec().IsClient {
			req.Header().Set("Authorization", "Bearer "+i.token)
		}
		return next(ctx, req)
	}
}

// WrapStreamingClient sets the header on the connection returned by next,
// before returning it to the caller — i.e. before Send can ever be called,
// so the header always reaches the server with (or ahead of) the first frame.
func (i retainBearerInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		conn := next(ctx, spec)
		if i.token != "" {
			conn.RequestHeader().Set("Authorization", "Bearer "+i.token)
		}
		return conn
	}
}

// WrapStreamingHandler is a no-op: this interceptor is only ever attached to
// retainClient, a CLIENT, and is never mounted on a handler.
func (i retainBearerInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return next
}

// ResolvePayload fetches and assembles the payload bytes held at contentHash on
// the serving boundary at upstreamEndpoint. It streams the response and aborts
// if the assembled size exceeds the configured cap (before the overflowing
// chunk is retained). A remote NotFound becomes ErrNotFound; any
// other transport failure is returned as-is (a liveness failure the runtime
// turns into a rejected/errored/dropped event). It never returns nil bytes with
// a nil error.
//
// The returned bytes carry NO trust — the caller's binding gate (sha256(payload)
// == the credential's outputHash) is the sole integrity check, so this client
// does not itself re-hash.
func (r *Resolver) ResolvePayload(parent context.Context, upstreamEndpoint, contentHash string) ([]byte, error) {
	ap, err := r.proof(opResolvePayload, map[string]any{"content_hash": contentHash})
	if err != nil {
		return nil, err
	}

	// Per-fetch budgets, imposed independent of the caller's context: the caller
	// passes the process-lifetime context, so an untrusted serving boundary that
	// trickles or stalls must be bounded here, or it head-of-line-blocks every
	// later event on this (sequential) subscription. A total budget bounds the
	// whole fetch; an idle budget bounds the gap between chunks (the trickle
	// defense — nonempty 1-byte chunks that never trip the byte cap still trip
	// idle). Caller cancellation still wins (parent is the root).
	ctx, cancel := context.WithCancelCause(parent)
	defer cancel(nil)
	if r.fetchTimeout > 0 {
		total := time.AfterFunc(r.fetchTimeout, func() { cancel(ErrFetchTimeout) })
		defer total.Stop()
	}
	// Serialized idle watchdog: a SINGLE goroutine owns the timing decision,
	// reading a lastProgress mark the receive loop updates. Deliberately not a
	// time.Reset-per-chunk timer — an AfterFunc callback can fire while a chunk is
	// being processed, cancelling a fetch that just made progress. Arming before
	// the first Receive covers a server that opens the stream but never sends a
	// byte. Progress is tracked as a MONOTONIC duration since `start` (not a wall
	// clock reading), so an NTP/VM clock step during a fetch cannot postpone stall
	// detection or falsely abort an active transfer. lastProgress's zero value is
	// the correct "no progress since start" mark, so no initial Store is needed.
	start := time.Now()
	var lastProgress atomic.Int64 // nanoseconds since start (monotonic)
	if r.idleTimeout > 0 {
		done := make(chan struct{})
		defer close(done)
		go func() {
			tick := r.idleTimeout / 2
			if tick <= 0 {
				tick = r.idleTimeout
			}
			t := time.NewTicker(tick)
			defer t.Stop()
			for {
				select {
				case <-done:
					return
				case <-ctx.Done():
					return
				case <-t.C:
					if time.Since(start)-time.Duration(lastProgress.Load()) > r.idleTimeout {
						cancel(ErrFetchStalled)
						return
					}
				}
			}
		}()
	}

	svc := payloadpbconnect.NewPayloadServiceClient(r.httpClient, upstreamEndpoint)
	stream, err := svc.ResolvePayload(ctx, connect.NewRequest(&payloadpb.ResolvePayloadRequest{
		AuthProof:   ap,
		ContentHash: contentHash,
	}))
	if err != nil {
		return nil, r.mapFetchErr(ctx, err)
	}
	defer stream.Close()
	var buf []byte
	for stream.Receive() {
		lastProgress.Store(int64(time.Since(start))) // progress — restart the idle clock (monotonic)
		chunk := stream.Msg().GetChunk()
		// Reject empty chunks: a well-behaved server only frames non-empty slices
		// of a non-empty payload, and forbidding them makes the max-bytes cap a
		// real ITERATION bound — every accepted frame adds >= 1 byte, so the loop
		// cannot exceed maxBytes iterations. Without this, an untrusted upstream
		// (the exact by-reference threat model) could stream endless zero-length
		// frames, never tripping the byte cap, and hang the consuming subscription
		// goroutine indefinitely (head-of-line blocking every later event).
		if len(chunk) == 0 {
			return nil, fmt.Errorf("payloadresolver/client: serving boundary at %s streamed an empty chunk for %s (protocol violation)", upstreamEndpoint, contentHash)
		}
		if len(buf)+len(chunk) > r.maxBytes {
			return nil, fmt.Errorf("payloadresolver/client: payload at %s exceeds max-bytes %d", contentHash, r.maxBytes)
		}
		buf = append(buf, chunk...)
	}
	if err := stream.Err(); err != nil {
		return nil, r.mapFetchErr(ctx, err)
	}
	return buf, nil
}

// mapFetchErr routes every fetch-error exit (the stream-open error AND the
// receive-loop end) through one cause-aware mapper: when the derived context was
// cancelled by a per-fetch budget, the budget sentinel wins over the raw stream
// error (a caller-context cancellation, whose cause is the parent's rather than
// a budget, and any other transport failure fall through to mapRemoteErr). err
// is never nil here — the caller checks that first.
func (r *Resolver) mapFetchErr(ctx context.Context, err error) error {
	switch context.Cause(ctx) {
	case ErrFetchTimeout:
		return fmt.Errorf("payloadresolver/client: fetch exceeded %s total budget: %w", r.fetchTimeout, ErrFetchTimeout)
	case ErrFetchStalled:
		return fmt.Errorf("payloadresolver/client: fetch made no progress within %s idle budget: %w", r.idleTimeout, ErrFetchStalled)
	default:
		return mapRemoteErr(err)
	}
}

// proof signs op over fields as the configured identity and converts the
// wireauth.Proof to the wire AuthProof (issued_at as canonical second-precision
// UTC RFC 3339 — the exact form the publisher's strict codec accepts). Shared
// by ResolvePayload (op = opResolvePayload) and Retain (op =
// wirecontract.OpRetainPayload).
func (r *Resolver) proof(op string, fields map[string]any) (*chainpb.AuthProof, error) {
	nonce, err := wireauth.NewNonce()
	if err != nil {
		return nil, fmt.Errorf("payloadresolver/client: nonce: %w", err)
	}
	p, err := wireauth.Sign(r.signer, r.signerDID, op, fields, nonce, time.Now())
	if err != nil {
		return nil, fmt.Errorf("payloadresolver/client: sign %s: %w", op, err)
	}
	return &chainpb.AuthProof{
		SignerDid: p.SignerDID,
		Nonce:     p.Nonce,
		IssuedAt:  p.IssuedAt.UTC().Format(time.RFC3339),
		Signature: p.Signature,
	}, nil
}

// Retain streams rd's bytes to THIS node's own PayloadStoreService
// (Config.StoreEndpoint) as ownerDID, declaring size bytes up front. It signs
// the metadata frame (owner_did + declared_size) with wireauth via the SAME
// op + field builder the storehandler verifies (wirecontract.OpRetainPayload
// / RetainPayloadFields — the two derivations cannot drift), splits rd into
// Config.RetainChunkSize frames, and returns the server-recomputed content
// address.
//
// size MUST equal the exact number of bytes rd yields: the server enforces
// this as a commitment, not a hint — a short or long stream is rejected
// (InvalidArgument / ResourceExhausted), never silently truncated or padded
// (see storehandler). Any Connect error the server returns is returned as-is
// (no swallowing), mirroring auditor/client.RegisterEvidence: the caller sees
// the real code (e.g. PermissionDenied for an owner_did that does not match
// the signing identity, ResourceExhausted for a size beyond the server's
// quota).
func (r *Resolver) Retain(parent context.Context, rd io.Reader, ownerDID string, size uint64) (string, error) {
	if r.storeEndpoint == "" {
		return "", fmt.Errorf("payloadresolver/client: Retain requires Config.StoreEndpoint")
	}
	ap, err := r.proof(wirecontract.OpRetainPayload, wirecontract.RetainPayloadFields(ownerDID, size))
	if err != nil {
		return "", err
	}

	// A locally-derived, cancellable context: an early return (e.g. a Read
	// error) tears down the outbound HTTP/2 stream instead of leaking it — the
	// server's blocked Receive unblocks via this cancellation rather than
	// hanging until the caller's own (possibly process-lifetime) ctx expires.
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	// r.retainClient, never a fresh client over r.httpClient: see its doc on
	// why Retain must not share ResolvePayload's arbitrary-endpoint dialing
	// (bearer leak).
	stream := r.retainClient.RetainPayload(ctx)
	if err := stream.Send(&payloadpb.RetainPayloadRequest{
		Frame: &payloadpb.RetainPayloadRequest_Metadata{Metadata: &payloadpb.RetainPayloadMetadata{
			OwnerDid:     ownerDID,
			DeclaredSize: size,
			AuthProof:    ap,
		}},
	}); err != nil {
		// Per connect's ClientStreamForClient.Send doc: if the server already
		// returned an error (e.g. an L1 interceptor rejecting before the first
		// frame is even consumed), Send wraps io.EOF — CloseAndReceive below
		// unmarshals the real error. Any OTHER send error is a genuine
		// transport failure. Mirrors the chunk-send handling below.
		if !errors.Is(err, io.EOF) {
			return "", fmt.Errorf("payloadresolver/client: send metadata frame: %w", err)
		}
	}

	buf := make([]byte, r.retainChunkSize)
	for {
		n, rerr := rd.Read(buf)
		if n > 0 {
			if serr := stream.Send(&payloadpb.RetainPayloadRequest{
				Frame: &payloadpb.RetainPayloadRequest_Chunk{Chunk: buf[:n]},
			}); serr != nil {
				// Per connect's ClientStreamForClient.Send doc: if the server
				// already returned an error, Send wraps io.EOF — CloseAndReceive
				// below unmarshals the real error. Any OTHER send error is a
				// genuine transport failure.
				if errors.Is(serr, io.EOF) {
					break
				}
				return "", fmt.Errorf("payloadresolver/client: send chunk: %w", serr)
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				break
			}
			return "", fmt.Errorf("payloadresolver/client: read payload: %w", rerr)
		}
	}

	resp, err := stream.CloseAndReceive()
	if err != nil {
		return "", err
	}
	return resp.Msg.GetContentAddress(), nil
}

// mapRemoteErr maps a remote NotFound to ErrNotFound (a broken publisher
// retention obligation, distinguished for observability); any other failure is
// returned as-is for the runtime to treat as a liveness failure.
func mapRemoteErr(err error) error {
	if connect.CodeOf(err) == connect.CodeNotFound {
		return fmt.Errorf("%w: %v", ErrNotFound, err)
	}
	return err
}
