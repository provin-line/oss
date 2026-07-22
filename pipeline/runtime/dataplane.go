package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/pipeline/chained"
	jsonataconv "github.com/provin-line/oss/pipeline/chained/converter/jsonata"
	"github.com/provin-line/oss/pipeline/chained/filter"
	jsonatafilter "github.com/provin-line/oss/pipeline/chained/filter/jsonata"
	"github.com/provin-line/oss/pipeline/contract"
	"github.com/provin-line/oss/pipeline/provenance"
	"github.com/provin-line/oss/pipeline/provenance/vcdid"
	"github.com/provin-line/oss/pipeline/provenance/verifycount"
	"github.com/provin-line/oss/pipeline/sink"
	sinkconsole "github.com/provin-line/oss/pipeline/sink/console"
	sinkfile "github.com/provin-line/oss/pipeline/sink/file"
	"github.com/provin-line/oss/pipeline/source/aggregate"
	"github.com/provin-line/oss/pipeline/source/ingest"
	"github.com/provin-line/oss/pipeline/transport"
	"github.com/provin-line/oss/pipeline/transport/envelopecodec"
	natstransport "github.com/provin-line/oss/pipeline/transport/nats"
	"github.com/provin-line/oss/resolver"
	"github.com/provin-line/oss/tlog"
	"github.com/provin-line/oss/tlog/filelog"
	"github.com/provin-line/oss/tlog/memlog"
	"github.com/provin-line/oss/vc"
	"github.com/provin-line/oss/wireprofile"
)

// Deps are the cross-plane dependencies a data plane needs beyond its own
// keystore: the shared DID resolver (sink loops verify upstream credentials through it)
// and an optional sink Writer override. They are zero for a source-only node — a
// source loop uses neither.
type Deps struct {
	Resolver resolver.Resolver
	// SinkWriter, when non-nil, overrides every sink loop's config-selected
	// delivery surface — the test seam (assert on a buffer instead of a real
	// surface). Deployment leaves it nil: each loop's writer comes from its
	// sink.output config (console default, file per path).
	SinkWriter sink.Writer
	// VCStore is the node's local VC store (the local *vcresolver.Service StoreVC seam).
	// Consuming loops (sink, chained) store every verified ingress credential through it,
	// populating the unresolved pool for the async chain-audit path (D-17f-1, D-17f-7).
	// Nil is a boot error for any consuming loop; a source-only node needs none.
	VCStore IngressStorer
	// AuditQueue registers each consumed head for async audit (slice-17h, D-17h-2). Nil
	// disables registration (a node/test without the audit runner); main always wires it.
	AuditQueue AuditRegistrar
	// Receipts records the emit-time consumed-set receipt for an aggregate's own emission
	// (slice-17o), enabling emit-locus source-commitment self-audit. Nil (with AuditQueue)
	// leaves an aggregate broadcast-only (no self-audit); main always wires it.
	Receipts ReceiptWriter
	// SchemaResolver refines the consuming loops' data-integrity axis with schema
	// content-hash resolution (credential.schema-ref). Nil leaves schema references
	// shape-checked only. main wires the local registry bridge.
	SchemaResolver vc.SchemaResolver
	// SchemaGetter resolves a producing loop's config schema-ref against the
	// registry at boot (fail-closed). Nil is a boot error for any loop that
	// declares a non-empty schema-ref; a loop without one needs none.
	SchemaGetter SchemaGetter
	// PayloadStore, when non-nil, retains each producing loop's payload before
	// publishing so a by-reference subscriber can later fetch it (the publisher
	// half of by-reference delivery). Nil leaves producing loops inline-only.
	PayloadStore PayloadRetainStore
	// PayloadResolver dereferences a by-reference ingress payload by content
	// address (the consumer half). Required for any consuming loop whose config
	// declares payload-delivery = by-reference (the runtime fails closed
	// otherwise); nil is fine for inline loops.
	PayloadResolver contract.PayloadResolver
	// CredentialPublisher, when non-nil, is the remote VC-store client producing
	// loops (and receipt/emission registrars) wrap their signer with so each
	// issued credential is published there (fail-closed round-trip check) before
	// it is emitted downstream. Nil is the same semantics as an unconfigured
	// vc-store-endpoint today: no publication. cmd/standalone's runtimewiring.go
	// constructs the concrete client (moved out of this package — the
	// construction imports network/pkg/services/vcresolver/client).
	CredentialPublisher CredentialPublisher
}

// PayloadRetainStore retains a producing loop's payload bytes keyed by their
// content address, recording ownerDID (the producing pipeline) for serving
// authorization. *payloadresolver.Service satisfies it.
type PayloadRetainStore interface {
	Store(ctx context.Context, payload []byte, ownerDID string) (string, error)
}

// payloadWiring carries the by-reference seams the loop builders apply: a
// producer-side retain store (bound per loop to its output pipeline DID) and a
// consumer-side resolver. Both nil unless the node is wired for by-reference.
type payloadWiring struct {
	store    PayloadRetainStore
	resolver contract.PayloadResolver
}

// retainerFor binds the retain store to a producing loop's output pipeline DID —
// the owner whose allow-list gates who may fetch the served payload. Returns nil
// when no store is wired (an inline-only node).
func (pw payloadWiring) retainerFor(ownerDID string) transport.PayloadRetainer {
	if pw.store == nil {
		return nil
	}
	return boundRetainer{store: pw.store, owner: ownerDID}
}

type boundRetainer struct {
	store PayloadRetainStore
	owner string
}

func (r boundRetainer) Retain(ctx context.Context, payload []byte) (string, error) {
	return r.store.Store(ctx, payload, r.owner)
}

// strippedPublisherFor binds a producing loop's dual-emit stripped-form
// publisher to conn's export-seam subject for the loop's output subject —
// the sibling of retainerFor, and the wiring half of the export-seam-mode
// spec's D-6 posture
// ("serve ⇒ retain ⇒ dual-emit is one capability unit, no per-loop opt-out"):
// returns nil when no PayloadStore is wired (an inline-only node, same
// condition retainerFor gates on), else a Publisher bound to
// wireprofile.ByReferenceSubjectPrefix+subject — the EXACT subject
// network/pkg/services/chainmanager exports for a by-reference subscription
// of this loop's output (subjectForMode), so a serving node's dual-emit and
// its chainmanager's export grant always agree on the wire subject without
// duplicating the prefix convention. wireprofile is the shared leaf both
// sides depend on (network/ and pipeline/ never import each other, AGENTS.md
// rule 2); chainmanager.ByReferenceSubjectPrefix is a const alias of the
// same value.
func (pw payloadWiring) strippedPublisherFor(conn *natstransport.Conn, subject string) transport.Publisher {
	if pw.store == nil {
		return nil
	}
	return conn.Publisher(wireprofile.ByReferenceSubjectPrefix + subject)
}

// parseDelivery maps a config payload-delivery token to its contract value.
// This reads a CONFIG field, whose default is inline (in-org expectation), so
// the EMPTY string maps to inline here — deliberately NOT via
// contract.ParsePayloadDelivery, which maps "" to by-reference (the wire
// negotiation default). The config loader also defaults an absent key to
// "inline", so "" reaches here only from a directly-constructed LoopConfig; both
// paths must agree that unset means inline. Any malformed non-empty value (the
// loader already rejects these) falls back to inline defensively.
func parseDelivery(s string) contract.PayloadDelivery {
	if s == "" {
		return contract.DeliveryInline
	}
	d, err := contract.ParsePayloadDelivery(s)
	if err != nil {
		return contract.DeliveryInline
	}
	return d
}

// Runtime is the node's set of running pipeline loops over one shared nats
// connection. It owns the connection's lifecycle, split across two calls
// (PR3b Task 7): Run starts the loops, waits for them to drain on context
// cancellation, and returns — it no longer closes anything itself. Close
// (called ONLY after Run has returned) then releases the shared connection
// and every durable custody log's file handle (the 17a Conn-owns-teardown
// contract, realized at node level, now a caller-driven step instead of
// Run's own tail).
//
// Why the split: a composition root that custodies durable logs to a
// mirror registry (cmd/pipeline's shipper — see pipeline/transport/
// tlogship) needs a window AFTER every loop/aggregate has drained but
// BEFORE the logs' file handles close, to flush each log's tail one last
// time. Run used to close the logs the instant loops drained, leaving no
// such window; Close gives a caller that window by making log/conn teardown
// an explicit, separately-timed step. cmd/standalone, which has no
// post-drain step of its own, calls Close immediately after Run returns —
// identical timing to Run's old self-closing behavior.
type Runtime struct {
	conn       *natstransport.Conn // nil when there are zero loops
	loops      []*transport.Loop
	aggregates []*aggregate.Process // self-triggered aggregate processes (contract.Process)
	// metrics is the per-loop metrics wiring the /metrics bridge polls; one
	// entry per constructed loop/aggregate, in construction order.
	metrics []LoopMetrics
	// tlogs is the emission-log registry (log id = producing output subject →
	// log) that BuildHandler mounts the TlogService over.
	tlogs map[string]tlog.Log
	// tlogClosers releases the durable logs' file handles at teardown (the
	// memlog fallback has nothing to close).
	tlogClosers []io.Closer
	// custodyLogs is the custody-log registry (D6): every DURABLE local log
	// this runtime opened (emission, sink-receipt, sink-reject), each labelled
	// with its log id and the issuer identity whose key signs its checkpoints.
	// Unlike tlogs (the TlogService READ surface), this INCLUDES sink-reject
	// logs — the mirror shipper (wired in a later task) must custody every
	// durable local log to the registry, reject logs included. Memlog
	// fallbacks (empty TlogDir/RejectLogDir, the unit-test seam) are never
	// custodied: nothing durable to ship.
	custodyLogs []CustodyLog
	// pushBindings are the HTTP ingest surfaces of push-enabled source loops
	// (push-ingress = true): cmd/standalone's BuildHandler mounts one apipush
	// adapter per binding, read through PushBindings(). The bound publishers
	// ride the shared conn — no separate teardown path.
	pushBindings []PushBinding
}

// Tlogs returns the emission-log registry (log id = producing output subject
// -> log). cmd/standalone's BuildHandler mounts the TlogService over it.
func (r *Runtime) Tlogs() map[string]tlog.Log { return r.tlogs }

// CustodyLog is one durable local log the mirror shipper custodies to the
// registry: the live handle, its log id, and the issuer identity whose key
// signs its checkpoints (the shipper signs MirrorLogSegment wireauth proofs
// as this SAME identity — D-T3: checkpoint signer == wireauth signer).
type CustodyLog struct {
	LogID  string
	Log    tlog.Log
	Signer IssuerConfig
}

// CustodyLogs returns every durable local log this runtime opened —
// emission logs, sink-receipt logs, and sink-reject logs alike — each
// labelled with its log id and signer identity. Unlike Tlogs() (the
// TlogService READ surface), this INCLUDES sink-reject logs: they are
// deliberately absent from Tlogs (custody-only, never served over reads),
// but the mirror shipper must still custody them to the registry like every
// other durable log. Memlog fallbacks (empty TlogDir/RejectLogDir, the
// unit-test seam) are never entered here — nothing durable to ship. Order
// follows construction (cfg.Loops order) and is not a contract — a consumer
// wanting a stable order sorts by LogID itself.
func (r *Runtime) CustodyLogs() []CustodyLog { return r.custodyLogs }

// PushBindings returns the HTTP ingest surfaces of every push-enabled source
// loop. cmd/standalone's mountPushRoutes mounts one apipush adapter per
// binding under /ingest/<name>/.
func (r *Runtime) PushBindings() []PushBinding { return r.pushBindings }

// Metrics returns the per-loop metrics wiring, one entry per constructed
// loop/aggregate in construction order. cmd/standalone's /metrics bridge
// polls these.
func (r *Runtime) Metrics() []LoopMetrics { return r.metrics }

// Loops returns every constructed transport loop (source, sink, chained), in
// construction order. cmd/standalone wires these into the by-reference
// advertisement health gate (D-5) alongside Aggregates.
func (r *Runtime) Loops() []*transport.Loop { return r.loops }

// Aggregates returns every constructed aggregate process, in construction
// order. cmd/standalone wires these into the by-reference advertisement
// health gate (D-5) alongside Loops.
func (r *Runtime) Aggregates() []*aggregate.Process { return r.aggregates }

// Conn returns the runtime's shared NATS connection, or nil for a zero-loop
// runtime that never dialed. cmd/standalone wires Conn().Healthy into the
// /readyz NATS check.
func (r *Runtime) Conn() *natstransport.Conn { return r.conn }

// PushBinding is one push-enabled source loop's HTTP ingest surface: the loop
// name (already validated as a URL-safe segment at config load), a Publisher on
// the loop's ingress subject over the shared data-plane connection, and the
// loop's subscription-readiness latch. Build produces the bindings;
// cmd/standalone's BuildHandler mounts one apipush adapter per binding at
// /ingest/<name>/.
type PushBinding struct {
	Name      string
	Publisher transport.Publisher
	Ready     <-chan struct{}
}

// readySubscriber decorates a transport.Subscriber with a readiness latch that
// closes when Subscribe returns without error — the Subscriber contract confirms
// the subscription with the broker before returning, so the latch is exactly
// "the loop can now receive". cmd/standalone's push route gates on it: core NATS
// silently drops a publish with no subscriber, so a 202 before the latch would be
// a lie.
type readySubscriber struct {
	transport.Subscriber
	once  sync.Once
	ready chan struct{}
}

func newReadySubscriber(s transport.Subscriber) *readySubscriber {
	return &readySubscriber{Subscriber: s, ready: make(chan struct{})}
}

// Subscribe implements transport.Subscriber, latching readiness on success.
func (r *readySubscriber) Subscribe(handler func(data []byte)) error {
	err := r.Subscriber.Subscribe(handler)
	if err == nil {
		r.once.Do(func() { close(r.ready) })
	}
	return err
}

// Ready returns the latch channel (closed once the subscription is confirmed).
func (r *readySubscriber) Ready() <-chan struct{} { return r.ready }

// Build assembles the node's pipeline loops from cfg. When no loops are
// configured it returns a no-op runner WITHOUT dialing nats, so an
// empty/absent pipeline config never requires a live broker (it does not
// regress the HTTP-only deployment). Otherwise it requires cfg.NATS to be
// populated (a runtime.Config is, by construction, NATS-or-nothing — the
// caller's transport selection is its own concern; see cmd/standalone's
// runtimeConfigFrom, which maps a non-NATS transport to zero mapped loops)
// and dials once as the node account, then builds one loop per config entry
// over that shared connection, dispatching on role: a source loop signs
// FirstDrop credentials with keyStore; a sink loop verifies upstream
// credentials through deps.Resolver and delivers consumed events to its
// config-selected output surface (sink.output; deps.SinkWriter overrides for
// tests).
func Build(ctx context.Context, cfg *Config, keyStore keystore.KeyStore, deps Deps) (*Runtime, error) {
	if len(cfg.Loops) == 0 {
		return &Runtime{}, nil
	}
	if cfg.NATS.URL == "" {
		return nil, fmt.Errorf("runtime: data-plane loops require nats configuration (empty NATS URL)")
	}

	conn, err := natstransport.Connect(ctx, natstransport.Config{
		URL:         cfg.NATS.URL,
		AccountSeed: cfg.NATS.AccountSeed,
		ConnectWait: cfg.NATS.ConnectWait,
	})
	if err != nil {
		return nil, fmt.Errorf("runtime: data-plane nats connect: %w", err)
	}

	dp := &Runtime{conn: conn, tlogs: map[string]tlog.Log{}}
	builder := vc.NewBuilder(keyStore)
	// newEmission builds one producing loop's emission log and registers it
	// under its log id (the output subject). Durable + checkpoint-armed when
	// TlogDir is set (the node path); in-memory otherwise (unit-test seam).
	// The directory derives from sha256(log id), NOT the loop name: a loop
	// rename must not fork the durable log while the id consumers reconcile
	// against is unchanged.
	newEmission := func(loopName, subject string, issuer IssuerConfig) (tlog.Log, error) {
		var l tlog.Log
		if cfg.TlogDir == "" {
			l = memlog.New()
		} else {
			sum := sha256.Sum256([]byte(subject))
			dir := filepath.Join(cfg.TlogDir, hex.EncodeToString(sum[:]))
			fl, err := filelog.New(dir, filelog.WithCheckpointSigner(filelog.CheckpointSigner{
				Signer:             keyStore,
				SignerDID:          issuer.DID,
				KeyID:              issuer.KeyID,
				VerificationMethod: issuer.VerificationMethod,
				LogID:              subject,
			}))
			if err != nil {
				return nil, fmt.Errorf("runtime: loop %q: emission log: %w", loopName, err)
			}
			slog.Info("runtime: durable loop log opened", "loop", loopName, "log_id", subject, "dir", dir)
			dp.tlogClosers = append(dp.tlogClosers, fl)
			dp.custodyLogs = append(dp.custodyLogs, CustodyLog{LogID: subject, Log: fl, Signer: issuer})
			l = fl
		}
		dp.tlogs[subject] = l
		return l, nil
	}
	// newRejectLog builds one archival sink loop's durable reject log under
	// RejectLogDir/sha256(log id) (data-dir/evidence/sink-rejects/<hash>).
	// In-memory when RejectLogDir is empty (unit-test seam; memlog cannot sign —
	// Checkpoint stays ErrUnsignedLog there, unchanged).
	//
	// Identity (D-T3, DECIDED): archival sinks are already REQUIRED to carry a
	// receipt issuer (config.go's Kind==archival && !Receipt.Issue boot error), so
	// the reject log is armed with that SAME signer — the sink's mandatory receipt
	// issuer — giving its checkpoint the stable custody identity
	// `sink-reject:<receipt-issuer-process-DID>` (the logident predicate's
	// KindSinkReject shape, one line below KindSinkReceipt's own
	// `sink-receipt:<DID>`).
	//
	// Directory keying now MATCHES newEmission: sha256(log id), not the raw
	// loop name. Identity and storage co-move — a same-DID restart resolves to
	// the same directory (continuity preserved for the normal case), and a
	// receipt-DID CHANGE resolves to a fresh directory (a new identity gets a
	// fresh log, consistent with the spec's D-T1 identity-rollover principle),
	// so historical rejects are never silently re-signed under a new owner.
	// (Previously the directory stayed keyed by loop NAME even after the
	// identity above was signed: a receipt-DID change across a restart with
	// the volume retained reopened the SAME directory under a NEW signer, and
	// every subsequent checkpoint re-signed all prior rejects as the new
	// DID's evidence — a P1 custody hole this rekeying closes.)
	newRejectLog := func(loopName string, issuer IssuerConfig) (sink.RejectLog, error) {
		if cfg.RejectLogDir == "" {
			return &sinkRejectLog{log: memlog.New()}, nil
		}
		logID := "sink-reject:" + issuer.DID
		sum := sha256.Sum256([]byte(logID))
		dir := filepath.Join(cfg.RejectLogDir, hex.EncodeToString(sum[:]))
		fl, ferr := filelog.New(dir, filelog.WithCheckpointSigner(filelog.CheckpointSigner{
			Signer:             keyStore,
			SignerDID:          issuer.DID,
			KeyID:              issuer.KeyID,
			VerificationMethod: issuer.VerificationMethod,
			LogID:              logID,
		}))
		if ferr != nil {
			return nil, fmt.Errorf("runtime: loop %q: reject log: %w", loopName, ferr)
		}
		dp.tlogClosers = append(dp.tlogClosers, fl)
		dp.custodyLogs = append(dp.custodyLogs, CustodyLog{LogID: logID, Log: fl, Signer: issuer})
		slog.Info("runtime: sink reject log opened", "loop", loopName, "dir", dir, "log_id", logID)
		return &sinkRejectLog{log: fl}, nil
	}
	// publisher is deps.CredentialPublisher verbatim: nil means no
	// vc-store-endpoint was configured (cmd/standalone's runtimewiring.go
	// constructs the concrete client and leaves this nil when
	// pipeCfg.VCStoreEndpoint is empty) — the same semantics Build enforced
	// itself before the VC-client construction moved out to the composition
	// root.
	publisher := deps.CredentialPublisher
	// Consuming loops (sink, chained) share one verifier (over the node's resolver) and one
	// in-memory ingress store, built lazily on the first such loop so a source-only node
	// needs no resolver. ensureConsumer builds them once and fails closed without a resolver.
	// Full-chain verification is the async audit runner's job (slice-17h), not a real-time
	// per-loop verifier (slice-17j retired "full").
	var verifier *vc.Verifier
	var ingressStore contract.IngressVCStore
	ensureConsumer := func(loopName string) error {
		if verifier != nil {
			return nil
		}
		if deps.Resolver == nil {
			return fmt.Errorf("runtime: loop %q: consuming role requires a DID resolver", loopName)
		}
		if deps.VCStore == nil {
			return fmt.Errorf("runtime: loop %q: consuming role requires a VC store", loopName)
		}
		var vopts []vc.VerifierOption
		if deps.SchemaResolver != nil {
			vopts = append(vopts, vc.WithSchemaResolver(deps.SchemaResolver))
		}
		verifier = vc.NewVerifier(deps.Resolver, ed25519.Verifier{}, vopts...)
		ingressStore = &serviceIngressStore{store: deps.VCStore, audit: deps.AuditQueue}
		return nil
	}
	// resolveSchema turns a producing loop's config schema-ref short-form into the
	// full signed reference embedded in its issued credentials. Empty = none;
	// non-empty with no registry available, or an unregistered/deprecated schema,
	// is a boot error (fail-closed).
	resolveSchema := func(loopName, shortForm string) (vc.SchemaRef, error) {
		if shortForm == "" {
			return vc.SchemaRef{}, nil
		}
		if deps.SchemaGetter == nil {
			return vc.SchemaRef{}, fmt.Errorf("runtime: loop %q: schema-ref set but no schema registry is available", loopName)
		}
		ref, err := resolveSchemaRefAtBoot(ctx, deps.SchemaGetter, shortForm)
		if err != nil {
			return vc.SchemaRef{}, fmt.Errorf("runtime: loop %q: %w", loopName, err)
		}
		return ref, nil
	}
	pw := payloadWiring{store: deps.PayloadStore, resolver: deps.PayloadResolver}
	sinkWriters := newSinkWriters(deps.SinkWriter)
	for _, lc := range cfg.Loops {
		var loop *transport.Loop
		// lm collects this loop's metrics wiring; appended alongside the loop
		// handle on success. dualEmits mirrors strippedPublisherFor's gate (a
		// PayloadStore ⇒ every producing loop dual-emits, D-6).
		lm := LoopMetrics{Name: lc.Name, Role: lc.Role}
		dualEmits := pw.store != nil
		switch lc.Role {
		case RoleSource:
			// The loop's ingress subscription; push-enabled loops get a readiness
			// latch on it plus an HTTP binding publishing to the same subject —
			// HTTP ingest rides the exact NATS path NATS ingest uses.
			var sub transport.Subscriber = conn.Subscriber(lc.IngressSubject)
			if lc.Source.PushIngress {
				rs := newReadySubscriber(sub)
				sub = rs
				dp.pushBindings = append(dp.pushBindings, PushBinding{
					Name:      lc.Name,
					Publisher: conn.Publisher(lc.IngressSubject),
					Ready:     rs.Ready(),
				})
			}
			var schemaRef vc.SchemaRef
			if schemaRef, err = resolveSchema(lc.Name, lc.Source.SchemaRef); err == nil {
				var emission tlog.Log
				if emission, err = newEmission(lc.Name, lc.Source.OutputSubject, lc.Source.Issuer); err == nil {
					loop, err = buildSourceLoop(sub, conn, builder, publisher, emission, schemaRef, pw, lc)
				}
			}
		case RoleSink:
			var w sink.Writer
			if w, err = sinkWriters.writerFor(lc.Sink.Output); err != nil {
				err = fmt.Errorf("runtime: loop %q: %w", lc.Name, err)
			} else if err = ensureConsumer(lc.Name); err == nil {
				// Per-loop verify counting over the shared verifier (P1-2).
				vcnt := verifycount.New(verifier)
				lm.Verify = vcnt
				// A receipt-issuing sink (MAY production / MUST archival) registers each
				// receipt local-first (store → tlog → audit queue) before optional remote
				// publish — the emissionRegistrar ordering doctrine. Needs the audit
				// substrate; a receipt-configured sink without it is a wiring error.
				var receipts sink.ReceiptIssuer
				if lc.Sink.Receipt.Issue {
					receipts, err = buildSinkReceiptRegistrar(builder, deps.VCStore, deps.AuditQueue, publisher, newEmission, lc)
				}
				// Archival's reject-with-audit-log obligation: a durable reject log,
				// armed with the SAME receipt issuer identity (D-T3) — archival's
				// config validation already guarantees lc.Sink.Receipt.Issuer is
				// populated (Issue == true) whenever Kind == archival.
				var rejectLog sink.RejectLog
				if err == nil && lc.Sink.Kind == SinkArchival {
					rejectLog, err = newRejectLog(lc.Name, lc.Sink.Receipt.Issuer)
				}
				if err == nil {
					loop, err = buildSinkLoop(conn, vcnt, ingressStore, w, receipts, rejectLog, pw, lc)
				}
			}
		case RoleChained:
			if err = ensureConsumer(lc.Name); err == nil {
				vcnt := verifycount.New(verifier)
				lm.Verify = vcnt
				var schemaRef vc.SchemaRef
				if schemaRef, err = resolveSchema(lc.Name, lc.Chained.SchemaRef); err == nil {
					var emission tlog.Log
					if emission, err = newEmission(lc.Name, lc.Chained.OutputSubject, lc.Chained.Issuer); err == nil {
						loop, err = buildChainedLoop(conn, builder, publisher, vcnt, ingressStore, emission, schemaRef, pw, lc)
					}
				}
			}
		case RoleAggregate:
			// An aggregate is a consuming producer (verifies+stores N ingress inputs,
			// emits a FirstDrop) and implements contract.Process directly (it owns its
			// window timer), so it is tracked in dp.aggregates, not dp.loops.
			var agg *aggregate.Process
			if err = ensureConsumer(lc.Name); err == nil {
				vcnt := verifycount.New(verifier)
				lm.Verify = vcnt
				// Emit-locus self-audit (slice-17o): the aggregate registers each emitted head
				// (local store + receipt + queue + optional remote publish) BEFORE broadcasting.
				// Wired only when the audit substrate is present; nil leaves it broadcast-only.
				var registrar aggregate.EmissionRegistrar
				if deps.Receipts != nil && deps.AuditQueue != nil {
					registrar = &emissionRegistrar{
						local:     deps.VCStore,
						receipts:  deps.Receipts,
						audit:     deps.AuditQueue,
						publisher: publisher,
					}
				}
				var schemaRef vc.SchemaRef
				if schemaRef, err = resolveSchema(lc.Name, lc.Aggregate.SchemaRef); err == nil {
					var emission tlog.Log
					if emission, err = newEmission(lc.Name, lc.Aggregate.OutputSubject, lc.Aggregate.Issuer); err == nil {
						agg, err = buildAggregateProcess(conn, builder, vcnt, ingressStore, registrar, emission, schemaRef, pw, lc)
					}
				}
			}
			if err != nil {
				_ = conn.Close()
				return nil, err
			}
			dp.aggregates = append(dp.aggregates, agg)
			lm.Emits = agg
			if dualEmits {
				lm.Stripped = agg
			}
			dp.metrics = append(dp.metrics, lm)
			continue
		default:
			// The config layer fails closed on unknown/unsupported roles; this guards the
			// assembly seam against a role string that bypassed validation.
			_ = conn.Close()
			return nil, fmt.Errorf("runtime: loop %q: unsupported role %q", lc.Name, lc.Role)
		}
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		dp.loops = append(dp.loops, loop)
		// A source/chained transport.Loop is a producer; a sink is consume-only.
		if lc.Role != RoleSink {
			lm.Emits = loop
			if dualEmits {
				lm.Stripped = loop
			}
		}
		dp.metrics = append(dp.metrics, lm)
	}
	return dp, nil
}

// buildSourceLoop assembles one source (FirstDrop) loop: ingress Subscriber → ingest
// processor (vcdid signer over the keystore) → output Publisher, with a memlog
// emission log. The config layer has already validated that lc.Role is source. The
// caller supplies the ingress Subscriber (push-enabled loops wrap it with a
// readiness latch).
func buildSourceLoop(sub transport.Subscriber, conn *natstransport.Conn, builder *vc.Builder, publisher CredentialPublisher, emission tlog.Log, schema vc.SchemaRef, pw payloadWiring, lc LoopConfig) (*transport.Loop, error) {
	src := lc.Source
	if src.TransformationClaim == vc.ClaimAggregate {
		// An ingest source loop signs via SignFirstDrop (N=0, no consumed set); the
		// aggregate Source Process (pool/window + SignAggregateFirstDrop) is a later
		// slice with its own role/wiring. Fail with a legible boot error rather than
		// the raw vcdid "aggregate requires SourceRootCanonical" construction error.
		return nil, fmt.Errorf("runtime: loop %q: transformation-claim %q is not valid on an ingest source loop (the aggregate Source Process runtime is a separate slice)", lc.Name, vc.ClaimAggregate)
	}
	signer, err := vcdid.NewSigner(vcdid.Config{
		Builder:             builder,
		IssuerDID:           src.Issuer.DID,
		KeyID:               src.Issuer.KeyID,
		VerificationMethod:  src.Issuer.VerificationMethod,
		PipelineID:          src.PipelineID,
		ProcessID:           src.ProcessID,
		TransformationClaim: src.TransformationClaim,
		Schema:              schema,
	})
	if err != nil {
		return nil, fmt.Errorf("runtime: loop %q: source signer: %w", lc.Name, err)
	}
	// When a VC store is configured, publish each FirstDrop (no predecessor, so no upstream
	// hint) before it is emitted downstream — fail-closed (D-17e-3).
	var sourceSigner provenance.SourceSigner = signer
	if publisher != nil {
		sourceSigner = &publishingSigner{inner: signer, publisher: publisher}
	}
	proc, err := ingest.New(ingest.Config{Signer: sourceSigner})
	if err != nil {
		return nil, fmt.Errorf("runtime: loop %q: ingest processor: %w", lc.Name, err)
	}
	loop, err := transport.NewLoop(transport.LoopConfig{
		Behavior:          contract.ChainFirstDrop,
		Strategy:          contract.VerificationNone,
		Processor:         proc,
		Subscriber:        sub,
		Publisher:         conn.Publisher(src.OutputSubject),
		Codec:             envelopecodec.New(),
		Emission:          emission,
		PayloadRetainer:   pw.retainerFor(src.OutputSubject),
		StrippedPublisher: pw.strippedPublisherFor(conn, src.OutputSubject),
	})
	if err != nil {
		return nil, fmt.Errorf("runtime: loop %q: build loop: %w", lc.Name, err)
	}
	return loop, nil
}

// buildSinkLoop assembles one terminating sink loop: ingress Subscriber → sink
// processor (verify the upstream credential, enforce payload binding, write
// out-of-network) with NO Publisher/Codec/Emission (the ChainTerminating contract — the
// sink processor holds its own Codec). The config layer has validated lc.Sink.
func buildSinkLoop(conn *natstransport.Conn, verifier provenance.Verifier, store contract.IngressVCStore, writer sink.Writer, receipts sink.ReceiptIssuer, rejectLog sink.RejectLog, pw payloadWiring, lc LoopConfig) (*transport.Loop, error) {
	strategy, err := verificationStrategy(lc.Sink.VerificationStrategy)
	if err != nil {
		return nil, fmt.Errorf("runtime: loop %q: %w", lc.Name, err)
	}
	kind, err := sinkKind(lc.Sink.Kind)
	if err != nil {
		return nil, fmt.Errorf("runtime: loop %q: %w", lc.Name, err)
	}
	cfg := sink.Config{
		Strategy:         strategy,
		Kind:             kind,
		Codec:            envelopecodec.New(),
		Verifier:         verifier,
		Store:            store,
		Writer:           writer,
		UpstreamEndpoint: lc.Sink.UpstreamEndpoint,
		AllowIssuers:     lc.Sink.AllowIssuers,
		Receipts:         receipts,
		RejectLog:        rejectLog,
		PayloadDelivery:  parseDelivery(lc.Sink.PayloadDelivery),
		PayloadResolver:  pw.resolver,
	}
	proc, err := sink.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("runtime: loop %q: sink processor: %w", lc.Name, err)
	}
	loop, err := transport.NewLoop(transport.LoopConfig{
		Behavior:   contract.ChainTerminating,
		Strategy:   strategy,
		Processor:  proc,
		Subscriber: conn.Subscriber(lc.IngressSubject),
		// A terminating sink has no Publisher/Codec/Emission (NewLoop enforces this).
	})
	if err != nil {
		return nil, fmt.Errorf("runtime: loop %q: build loop: %w", lc.Name, err)
	}
	return loop, nil
}

// buildChainedLoop assembles one chained (relay) loop: ingress Subscriber → chained
// processor (verify the upstream credential, enforce payload binding, optionally
// filter/convert, re-sign a ChainPreserving credential linking the predecessor) → output
// Publisher, with a memlog emission log. It both consumes (verifier + store) and produces
// (signer + Publisher + Codec + Emission). The config layer has validated lc.Chained.
func buildChainedLoop(conn *natstransport.Conn, builder *vc.Builder, publisher CredentialPublisher, verifier provenance.Verifier, store contract.IngressVCStore, emission tlog.Log, schema vc.SchemaRef, pw payloadWiring, lc LoopConfig) (*transport.Loop, error) {
	cc := lc.Chained
	signer, err := vcdid.NewSigner(vcdid.Config{
		Builder:             builder,
		IssuerDID:           cc.Issuer.DID,
		KeyID:               cc.Issuer.KeyID,
		VerificationMethod:  cc.Issuer.VerificationMethod,
		PipelineID:          cc.PipelineID,
		ProcessID:           cc.ProcessID,
		TransformationClaim: cc.TransformationClaim,
		Schema:              schema,
	})
	if err != nil {
		return nil, fmt.Errorf("runtime: loop %q: chained signer: %w", lc.Name, err)
	}
	strategy, err := verificationStrategy(cc.VerificationStrategy)
	if err != nil {
		return nil, fmt.Errorf("runtime: loop %q: %w", lc.Name, err)
	}
	// When a VC store is configured, publish each ChainPreserving credential (passing the
	// upstream-endpoint as the predecessor-fetch hint) before downstream emit — fail-closed.
	var chainedSigner provenance.ChainedSigner = signer
	if publisher != nil {
		chainedSigner = &publishingSigner{inner: signer, publisher: publisher, upstreamEndpoint: cc.UpstreamEndpoint}
	}
	chainedCfg := chained.Config{
		Strategy:          strategy,
		IngressConformant: true,
		UpstreamEndpoint:  cc.UpstreamEndpoint,
		Codec:             envelopecodec.New(),
		Verifier:          verifier,
		Store:             store,
		Signer:            chainedSigner,
		PayloadDelivery:   parseDelivery(cc.PayloadDelivery),
		PayloadResolver:   pw.resolver,
	}
	// Converter/filters compile at boot — a malformed JSONata expression fails closed here.
	if cc.Converter != "" {
		conv, err := jsonataconv.New(cc.Converter)
		if err != nil {
			return nil, fmt.Errorf("runtime: loop %q: converter: %w", lc.Name, err)
		}
		chainedCfg.Converter = conv
	}
	if len(cc.Filters) > 0 {
		filt, err := jsonatafilter.New(cc.Filters)
		if err != nil {
			return nil, fmt.Errorf("runtime: loop %q: filters: %w", lc.Name, err)
		}
		chainedCfg.Filters = []filter.Filter{filt}
	}
	proc, err := chained.New(chainedCfg)
	if err != nil {
		return nil, fmt.Errorf("runtime: loop %q: chained processor: %w", lc.Name, err)
	}
	loop, err := transport.NewLoop(transport.LoopConfig{
		Behavior:          contract.ChainPreserving,
		Strategy:          strategy,
		Processor:         proc,
		Subscriber:        conn.Subscriber(lc.IngressSubject),
		Publisher:         conn.Publisher(cc.OutputSubject),
		Codec:             envelopecodec.New(),
		Emission:          emission,
		PayloadRetainer:   pw.retainerFor(cc.OutputSubject),
		StrippedPublisher: pw.strippedPublisherFor(conn, cc.OutputSubject),
	})
	if err != nil {
		return nil, fmt.Errorf("runtime: loop %q: build loop: %w", lc.Name, err)
	}
	return loop, nil
}

// buildAggregateProcess assembles one aggregate Source Process (slice-17l): a stateful
// pool+window process that verifies+stores N ingress inputs and, on each window tick,
// folds them into a provin:aggregate FirstDrop with a multi-source commitment. The claim
// and source-root canonical (JCS) are fixed by the role; the reference ManifestFold is
// wired. When a VC store is configured the signer publishes each issued FirstDrop
// (fail-closed), like a source. The config layer has validated lc.Role is aggregate.
func buildAggregateProcess(conn *natstransport.Conn, builder *vc.Builder, verifier provenance.Verifier, store contract.IngressVCStore, registrar aggregate.EmissionRegistrar, emission tlog.Log, schemaRef vc.SchemaRef, pw payloadWiring, lc LoopConfig) (*aggregate.Process, error) {
	ac := lc.Aggregate
	signer, err := vcdid.NewSigner(vcdid.Config{
		Builder:             builder,
		IssuerDID:           ac.Issuer.DID,
		KeyID:               ac.Issuer.KeyID,
		VerificationMethod:  ac.Issuer.VerificationMethod,
		PipelineID:          ac.PipelineID,
		ProcessID:           ac.ProcessID,
		TransformationClaim: vc.ClaimAggregate,
		SourceRootCanonical: vc.SourceRootCanonicalJCS,
		Schema:              schemaRef,
	})
	if err != nil {
		return nil, fmt.Errorf("runtime: loop %q: aggregate signer: %w", lc.Name, err)
	}
	cfg := aggregate.Config{
		Signer:    signer,
		Verifier:  verifier,
		Store:     store,
		Publisher: conn.Publisher(ac.OutputSubject),
		Codec:     envelopecodec.New(),
		Emission:  emission,
		Fold:      aggregate.ManifestFold{},
		Window:    ac.Window,
		// SelfAudit registers each emitted head (local store + receipt + queue + optional
		// remote publish) BEFORE broadcast (slice-17o). It subsumes the issued-VC remote
		// publish that source/chained loops do via publishingSigner — so the aggregate uses
		// the PLAIN signer and does not wrap it (the publish must follow self-audit, D-17o-3).
		SelfAudit: registrar,
		// The aggregate produces a FirstDrop head; retain its payload for by-reference
		// subscribers (bound to its own output pipeline DID as the serving owner).
		PayloadRetainer: pw.retainerFor(ac.OutputSubject),
		// Dual-emit the stripped form to the export seam's mode-scoped subject
		// (same serve ⇒ retain ⇒ dual-emit unit as the source/chained loops).
		StrippedPublisher: pw.strippedPublisherFor(conn, ac.OutputSubject),
	}
	// ac.VerificationStrategy is config-validated to "adjacent"; the aggregate runtime
	// declares VerificationAdjacent intrinsically, so it takes no strategy field.
	for _, ing := range ac.Ingresses {
		cfg.Ingress = append(cfg.Ingress, aggregate.Ingress{
			Subscriber:       conn.Subscriber(ing.Subject),
			UpstreamEndpoint: ing.UpstreamEndpoint,
			PayloadDelivery:  parseDelivery(ing.PayloadDelivery),
			PayloadResolver:  pw.resolver,
		})
	}
	proc, err := aggregate.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("runtime: loop %q: aggregate process: %w", lc.Name, err)
	}
	return proc, nil
}

// verificationStrategy maps a (config-validated) strategy token to its contract value.
// "adjacent" verifies the immediately preceding credential — the only ingress strategy
// (full-chain audit is the async audit runner's job, slice-17h; "full" was retired in 17j).
func verificationStrategy(s string) (contract.VerificationStrategy, error) {
	switch s {
	case StrategyAdjacent:
		return contract.VerificationAdjacent, nil
	default:
		return contract.VerificationUnknown, fmt.Errorf("unknown verification-strategy %q", s)
	}
}

// sinkKind maps a (config-validated) sink-kind token to its contract value.
func sinkKind(k string) (contract.SinkKind, error) {
	switch k {
	case SinkObservationOnly:
		return contract.SinkObservationOnly, nil
	case SinkProduction:
		return contract.SinkProduction, nil
	case SinkArchival:
		return contract.SinkArchival, nil
	default:
		return contract.SinkKindUnknown, fmt.Errorf("unknown sink.kind %q", k)
	}
}

// Run runs every loop until ctx is cancelled and waits for all of them to
// drain and return. A zero-loop runner returns immediately. It returns the
// first loop error, or nil on a clean drain — Run itself no longer touches
// the shared connection or any log handle; see Close and the Runtime doc for
// why that teardown moved out to a separate, caller-driven step (PR3b Task
// 7). Every caller MUST call Close after Run returns (whether cleanly or
// with an error) — Run's own drain is not a complete shutdown by itself
// anymore.
//
// Loops share a child context derived from ctx, so the first loop to fail (e.g. a
// boot-time Subscribe error) cancels its siblings and Run returns promptly — it does
// not block until an external cancellation arrives.
func (r *Runtime) Run(ctx context.Context) error {
	total := len(r.loops) + len(r.aggregates)
	if total == 0 {
		return nil
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	errs := make(chan error, total)
	// Loops and aggregates both implement contract.Process; run them uniformly. A
	// failure in any drains the siblings (cancel) instead of blocking on them.
	run := func(p contract.Process) {
		defer wg.Done()
		if err := p.Run(runCtx); err != nil {
			errs <- err
			cancel()
		}
	}
	for _, l := range r.loops {
		wg.Add(1)
		go run(l)
	}
	for _, a := range r.aggregates {
		wg.Add(1)
		go run(a)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// Close releases the shared nats connection and every durable custody log's
// file handle. Callers MUST NOT call Close until Run has returned (every
// loop and aggregate has drained) — closing earlier would race whichever
// loop is still consuming/producing through the connection or a log. A
// zero-loop runtime (conn is nil — see the conn field's doc) is a no-op.
//
// Close is safe to call more than once (including concurrently with itself
// only in the trivial sense of repeated sequential calls — it is not
// goroutine-safe against a concurrent first call): only the first call
// releases the connection and logs; every subsequent call is a no-op that
// returns nil. This lets independent teardown paths (e.g. a test's
// t.Cleanup alongside the production shutdown sequence) both call Close
// without racing on a double-close of the underlying conn/handles.
//
// See the Runtime doc for why this is a separate call from Run rather than
// Run's own tail: it gives a composition root with a post-drain step of its
// own (cmd/pipeline's mirror-shipper final flush) a window, between Run
// returning and Close being called, where every log handle is still open.
func (r *Runtime) Close() error {
	if r.conn == nil {
		return nil
	}
	closeErr := r.conn.Close()
	for _, c := range r.tlogClosers {
		if err := c.Close(); err != nil && closeErr == nil {
			closeErr = err
		}
	}
	r.conn = nil
	r.tlogClosers = nil
	return closeErr
}

// sinkWriters builds per-loop sink delivery writers from config. One console
// writer is shared (stdout is one stream), and file writers are shared per
// CLEANED path — two loops delivering to one file must go through one mutex or
// their lines could interleave. A non-nil override (deps.SinkWriter, the test
// seam) wins over all config.
type sinkWriters struct {
	override sink.Writer
	console  sink.Writer
	files    map[string]sink.Writer
}

func newSinkWriters(override sink.Writer) *sinkWriters {
	return &sinkWriters{override: override, files: map[string]sink.Writer{}}
}

// writerFor resolves one loop's delivery surface. The zero-value Output (typed
// construction without the config loader) means console — same default the
// loader applies. Unknown types fail closed: config validation catches them at
// load, so one here is a programming error surfaced loudly, not defaulted.
func (s *sinkWriters) writerFor(out SinkOutputConfig) (sink.Writer, error) {
	if s.override != nil {
		return s.override, nil
	}
	switch out.Type {
	case SinkOutputFile:
		key := filepath.Clean(out.Path)
		if w, ok := s.files[key]; ok {
			return w, nil
		}
		w, err := sinkfile.New(key)
		if err != nil {
			return nil, err
		}
		s.files[key] = w
		return w, nil
	case SinkOutputConsole, "":
		if s.console == nil {
			s.console = sinkconsole.New(os.Stdout)
		}
		return s.console, nil
	default:
		return nil, fmt.Errorf("unknown sink output type %q", out.Type)
	}
}
