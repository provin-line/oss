package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	natstest "github.com/nats-io/nats-server/v2/test"
	"github.com/nats-io/nkeys"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/keystore/filestore"
	"github.com/provin-line/oss/network/pkg/chainconfig"
	"github.com/provin-line/oss/network/pkg/pipelineconfig"
	natsop "github.com/provin-line/oss/network/pkg/services/chainmanager/infra/nats"
	"github.com/provin-line/oss/pipeline/sink"
	natstransport "github.com/provin-line/oss/pipeline/transport/nats"
	"github.com/provin-line/oss/resolver/local"
	"github.com/provin-line/oss/vc"
)

// The cross-node capstone DID lineage: an owner controlling a pipeline process. The
// source loop signs FirstDrop credentials as capIssuerDID; the sink loop resolves this
// lineage to verify them. capPipelineDID is the source's output subject == the granted
// cross-account subject the sink subscribes to.
const (
	capOwnerDID    = "did:dplaax:poc.dplaax.dev:org:acme"
	capPipelineDID = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:pipe"
	capIssuerDID   = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:pipe:process:src"
	capIngress     = "ingest.src"
)

func capSourceCfg() *pipelineconfig.Config {
	return &pipelineconfig.Config{Loops: []pipelineconfig.LoopConfig{{
		Name:           "src",
		Role:           pipelineconfig.RoleSource,
		IngressSubject: capIngress,
		Source: pipelineconfig.SourceConfig{
			OutputSubject: capPipelineDID,
			Issuer: pipelineconfig.IssuerConfig{
				DID: capIssuerDID, KeyID: string(keystore.KeyIDSigning),
				VerificationMethod: capIssuerDID + "#signing",
			},
			PipelineID:          "pipe",
			ProcessID:           "src",
			TransformationClaim: vc.ClaimConvert,
		},
	}}}
}

func capSinkCfg() *pipelineconfig.Config {
	return &pipelineconfig.Config{Loops: []pipelineconfig.LoopConfig{{
		Name:           "archive",
		Role:           pipelineconfig.RoleSink,
		IngressSubject: capPipelineDID,
		Sink: pipelineconfig.SinkConfig{
			Kind:                 pipelineconfig.SinkObservationOnly,
			VerificationStrategy: pipelineconfig.StrategyAdjacent,
			UpstreamEndpoint:     "https://acme.example/pipelines/pipe",
		},
	}}}
}

// captureWriter is an observable sink.Writer: it retains every delivered record so the
// capstone can assert what crossed the account boundary.
type captureWriter struct {
	mu   sync.Mutex
	recs []sink.Record
}

func (w *captureWriter) Write(_ context.Context, rec sink.Record) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.recs = append(w.recs, rec)
	return nil
}

func (w *captureWriter) records() []sink.Record {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]sink.Record(nil), w.recs...)
}

// capstone bundles the running two-node data plane's controls: inject pushes raw bytes
// onto the publisher source's ingress; writer captures what the subscriber sink wrote;
// pubObserved fires when the source's output lands on the publisher's own account
// (proof the source emitted, independent of cross-account delivery).
type capstone struct {
	inject      func([]byte)
	writer      *captureWriter
	pubObserved <-chan []byte
}

// setupCapstone builds two single-account nodes over one shared operator + embedded
// broker: a publisher running a 17b source loop and a subscriber running a 17c sink loop.
// When grant is true it establishes the cross-account grant directly (D-17c-6:
// AddExport on the publisher account, AddImport on the subscriber account) BEFORE any
// client connects (cold-account ordering). Both data planes run for the test's lifetime.
func setupCapstone(t *testing.T, grant bool) capstone {
	t.Helper()

	op, _ := nkeys.CreateOperator()
	opSeed, _ := op.Seed()
	opPub, _ := op.PublicKey()
	sharedDir := t.TempDir()

	pubAcc, _ := nkeys.CreateAccount()
	pubAccSeed, _ := pubAcc.Seed()
	pubAccPub, _ := pubAcc.PublicKey()
	subAcc, _ := nkeys.CreateAccount()
	subAccSeed, _ := subAcc.Seed()

	pubOp := capOperator(t, pubAccSeed, opSeed, sharedDir)
	subOp := capOperator(t, subAccSeed, opSeed, sharedDir)
	if grant {
		if _, err := pubOp.AddExport(capPipelineDID); err != nil {
			t.Fatalf("AddExport: %v", err)
		}
		if err := subOp.AddImport(capPipelineDID, pubAccPub, capPipelineDID); err != nil {
			t.Fatalf("AddImport: %v", err)
		}
	} else {
		// Publish bare accounts (so clients can connect) WITHOUT granting capPipelineDID:
		// an unrelated export/import the test never uses. Account JWTs are written only on
		// a mutation, and a connectable account is the precondition for a meaningful
		// "the grant — not topology — is why traffic crosses" negative.
		if _, err := pubOp.AddExport("chain.unrelated"); err != nil {
			t.Fatalf("AddExport(unrelated): %v", err)
		}
		if err := subOp.AddImport("chain.unrelated", pubAccPub, "chain.unrelated"); err != nil {
			t.Fatalf("AddImport(unrelated): %v", err)
		}
	}

	// Cold-account ordering: bridge the operator-written grants into the broker's
	// resolver, then start the broker, then connect clients (slice-16 invariant).
	mr := bridgeCapDir(t, sharedDir)
	natsSrv := natstest.RunServer(&server.Options{
		Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true,
		TrustedKeys: []string{opPub}, AccountResolver: mr,
	})
	t.Cleanup(natsSrv.Shutdown)
	url := natsSrv.ClientURL()

	// The source signs as capIssuerDID with a keystore key; the lineage resolver serves
	// that key so the sink can verify the proof.
	ks := filestore.New(t.TempDir())
	kp, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	if err := ks.SaveKeyPair(capIssuerDID, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: kp}); err != nil {
		t.Fatalf("save key: %v", err)
	}

	pubChain := &chainconfig.Config{
		Transport: chainconfig.TransportNATS,
		NATS:      chainconfig.NATSConfig{URL: url, AccountSeed: string(pubAccSeed)},
	}
	pubDP, err := buildDataPlane(context.Background(), pubChain, capSourceCfg(), ks, dataPlaneDeps{})
	if err != nil {
		t.Fatalf("build publisher data plane: %v", err)
	}

	res := local.New()
	res.Add(capProcessDoc(capIssuerDID, capOwnerDID, kp.PublicKey))
	res.Add(capOwnerDoc(capOwnerDID))
	writer := &captureWriter{}
	subChain := &chainconfig.Config{
		Transport: chainconfig.TransportNATS,
		NATS:      chainconfig.NATSConfig{URL: url, AccountSeed: string(subAccSeed)},
	}
	subDP, err := buildDataPlane(context.Background(), subChain, capSinkCfg(), filestore.New(t.TempDir()), dataPlaneDeps{
		Resolver:   res,
		SinkWriter: writer,
		VCStore:    dpVCStore(),
	})
	if err != nil {
		t.Fatalf("build subscriber data plane: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	pubDone := make(chan error, 1)
	subDone := make(chan error, 1)
	go func() { pubDone <- pubDP.Run(ctx) }()
	go func() { subDone <- subDP.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-pubDone
		<-subDone
	})

	// Injector + publisher-side observer on the publisher account (a separate conn).
	inj, err := natstransport.Connect(context.Background(), natstransport.Config{URL: url, AccountSeed: string(pubAccSeed)})
	if err != nil {
		t.Fatalf("injector connect: %v", err)
	}
	t.Cleanup(func() { _ = inj.Close() })
	observed := make(chan []byte, 8)
	if err := inj.Subscriber(capPipelineDID).Subscribe(func(b []byte) {
		select {
		case observed <- b:
		default:
		}
	}); err != nil {
		t.Fatalf("publisher-side observe: %v", err)
	}
	pub := inj.Publisher(capIngress)
	return capstone{
		inject:      func(p []byte) { _ = pub.Publish(p) },
		writer:      writer,
		pubObserved: observed,
	}
}

// TestCapstone_GrantedCrossNodeDelivery is the slice-17c capstone: with the grant in
// place, a real source loop on the publisher node signs a FirstDrop Envelope that
// crosses the account boundary to a real sink loop on the subscriber node, which
// verifies it (ConfidenceVerified) and writes it out.
func TestCapstone_GrantedCrossNodeDelivery(t *testing.T) {
	c := setupCapstone(t, true)
	const raw = `{"reading":42}`

	c.inject([]byte(raw))
	deadline := time.After(10 * time.Second)
	tick := time.NewTicker(150 * time.Millisecond)
	defer tick.Stop()
	for {
		if recs := c.writer.records(); len(recs) > 0 {
			rec := recs[0]
			if string(rec.Payload) != raw {
				t.Fatalf("payload: got %q want %q", rec.Payload, raw)
			}
			if rec.Verdict == nil || rec.Verdict.Overall != vc.ConfidenceVerified {
				t.Fatalf("verdict: got %+v want ConfidenceVerified", rec.Verdict)
			}
			if rec.Credential == nil || rec.Credential.Issuer() != capIssuerDID {
				t.Fatalf("issuer: got %v want %q", rec.Credential, capIssuerDID)
			}
			if pc := rec.Credential.PreviousCredential(); pc != "" {
				t.Fatalf("want FirstDrop origin (no predecessor), got %q", pc)
			}
			return
		}
		select {
		case <-tick.C:
			c.inject([]byte(raw)) // loops subscribe asynchronously; re-push until delivered
		case <-deadline:
			t.Fatal("sink did not receive the cross-node event")
		}
	}
}

// TestCapstone_UngrantedSubjectBlocked is the broker-is-last-line negative: without the
// grant the source still emits on its own account (publisher-side observe confirms it),
// but the broker does NOT route it cross-account, so the subscriber sink receives
// nothing — delivery requires the grant, not just topology.
func TestCapstone_UngrantedSubjectBlocked(t *testing.T) {
	c := setupCapstone(t, false)
	const raw = `{"reading":7}`

	// Drive until the source has emitted on the publisher account (proves the source
	// loop works), retrying injection while the loops come up.
	c.inject([]byte(raw))
	deadline := time.After(10 * time.Second)
	tick := time.NewTicker(150 * time.Millisecond)
	defer tick.Stop()
	emitted := false
	for !emitted {
		select {
		case <-c.pubObserved:
			emitted = true
		case <-tick.C:
			c.inject([]byte(raw))
		case <-deadline:
			t.Fatal("source loop never emitted on its own account (setup issue)")
		}
	}

	// The source emitted; without a grant the broker must not route it cross-account.
	time.Sleep(500 * time.Millisecond)
	if recs := c.writer.records(); len(recs) != 0 {
		t.Fatalf("ungranted: sink received %d record(s); cross-account delivery must be blocked", len(recs))
	}
}

// capOperator builds a production nats infra operator over the given account + trust
// seeds, writing account-claims JWTs to dir via the DirPublisher (slice-16 pattern).
func capOperator(t *testing.T, accSeed, trustSeed []byte, dir string) *natsop.Operator {
	t.Helper()
	o, err := natsop.New(natsop.Config{
		AccountSeed:   string(accSeed),
		TrustRootSeed: string(trustSeed),
		URL:           "nats://unused-in-e2e:4222",
		Publisher:     natsop.NewDirPublisher(dir),
	})
	if err != nil {
		t.Fatalf("natsop.New: %v", err)
	}
	return o
}

// bridgeCapDir loads every <accountPub>.jwt the operators wrote into a MemAccResolver so
// the embedded broker enforces the same grants the DirPublisher produced (slice-16).
func bridgeCapDir(t *testing.T, dir string) *server.MemAccResolver {
	t.Helper()
	mr := &server.MemAccResolver{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read shared dir: %v", err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".jwt") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := mr.Store(strings.TrimSuffix(e.Name(), ".jwt"), string(b)); err != nil {
			t.Fatalf("resolver store: %v", err)
		}
	}
	return mr
}

// capProcessDoc / capOwnerDoc build the issuer lineage: the process holds the #signing
// assertion key and is controlled by the owner; the owner is self-controlled. The
// vc.Verifier's controller walk follows process → owner (the owner is a structural
// ancestor), yielding ConfidenceVerified for a well-formed FirstDrop.
func capProcessDoc(processDID, owner string, pub []byte) *did.DIDDocument {
	vm, err := did.NewMultikeyVerificationMethod(processDID+"#signing", processDID, pub)
	if err != nil {
		panic(err) // a non-Ed25519 fixture key is a test bug
	}
	return did.New(did.DocumentFields{
		Context:            did.IssuedDocumentContexts(),
		ID:                 processDID,
		Controller:         owner,
		VerificationMethod: []did.VerificationMethod{vm},
		AssertionMethod:    []string{processDID + "#signing"},
	})
}

func capOwnerDoc(owner string) *did.DIDDocument {
	return did.New(did.DocumentFields{ID: owner, Controller: owner})
}
