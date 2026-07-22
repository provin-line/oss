package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/o3co/protobuf.interceptors/endpoint"

	"github.com/provin-line/oss/network/pkg/chainconfig"
	pipelineruntime "github.com/provin-line/oss/pipeline/runtime"
	"github.com/provin-line/oss/pipeline/transport/envelopecodec"
	natstransport "github.com/provin-line/oss/pipeline/transport/nats"
)

// TestPushIngest_Boot is the apipush capstone: a push-enabled source loop accepts an
// authenticated HTTP POST and emits a signed FirstDrop on its output subject whose
// input/output hash is the posted body's content address. It also pins the route
// policy: readiness gate (503 before the loop's subscription is confirmed — a 202'd
// publish before that would be silently lost by core NATS), 401 without a bearer,
// and the public health route flipping 503→200 across the latch.
func TestPushIngest_Boot(t *testing.T) {
	url, accSeed := dpAccountServer(t)
	chainCfg := &chainconfig.Config{
		Transport: chainconfig.TransportNATS,
		NATS:      chainconfig.NATSConfig{URL: url, AccountSeed: accSeed},
	}
	pipeCfg := dpPipelineCfg()
	pipeCfg.Loops[0].Source.PushIngress = true

	dp, err := pipelineruntime.Build(context.Background(), chainCfg, pipeCfg, dpKeyStore(t), pipelineruntime.Deps{})
	if err != nil {
		t.Fatalf("pipelineruntime.Build: %v", err)
	}
	if len(dp.PushBindings()) != 1 || dp.PushBindings()[0].Name != "src" {
		t.Fatalf("pushBindings = %+v, want one binding for loop src", dp.PushBindings())
	}

	// Mount exactly as BuildHandler does; the PDP allows (ingest, push).
	verifier := endpoint.NewStaticEndpoint([]endpoint.StaticRule{{Resource: "ingest", Action: "push"}})
	mux := http.NewServeMux()
	if err := mountPushRoutes(mux, dp.PushBindings(), verifier, 1<<20); err != nil {
		t.Fatalf("mountPushRoutes: %v", err)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	post := func(auth string, body string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/ingest/src/push", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		return resp
	}

	// Before dp.Run: the subscription is not confirmed — the readiness gate holds
	// push (authenticated!) and health at 503.
	if resp := post("Bearer tok", `{"a":1}`); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("push before readiness: got %d, want 503", resp.StatusCode)
	}
	if resp, err := srv.Client().Get(srv.URL + "/ingest/src/health"); err != nil {
		t.Fatal(err)
	} else if resp.Body.Close(); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("health before readiness: got %d, want 503", resp.StatusCode)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	runDone := make(chan error, 1)
	go func() { runDone <- dp.Run(ctx) }()

	// Readiness is observable: the public health route flips to 200.
	waitFor(t, 5*time.Second, func() bool {
		resp, err := srv.Client().Get(srv.URL + "/ingest/src/health")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, "health never turned 200 after dp.Run")

	// Observer on the loop's output subject (second connection, same account).
	obs, err := natstransport.Connect(context.Background(), natstransport.Config{URL: url, AccountSeed: accSeed})
	if err != nil {
		t.Fatalf("observer connect: %v", err)
	}
	defer obs.Close()
	got := make(chan []byte, 4)
	if err := obs.Subscriber(dpPipelineDID).Subscribe(func(b []byte) { got <- b }); err != nil {
		t.Fatalf("observer subscribe: %v", err)
	}

	// Unauthenticated → 401 before any gate; nothing published.
	if resp := post("", `{"a":1}`); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated push: got %d, want 401", resp.StatusCode)
	}

	// Authenticated push → 202 whose payload_hash matches the body's digest.
	const rawJSON = `{"lot_id":"L-42","weight_kg":120}`
	resp := post("Bearer tok", rawJSON)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("push: got %d, want 202", resp.StatusCode)
	}
	var accepted struct {
		PayloadHash string `json:"payload_hash"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&accepted); err != nil {
		t.Fatalf("decode 202 body: %v", err)
	}
	sum := sha256.Sum256([]byte(rawJSON))
	wantHash := "sha256:" + hex.EncodeToString(sum[:])
	if accepted.PayloadHash != wantHash {
		t.Fatalf("payload_hash = %q, want %q", accepted.PayloadHash, wantHash)
	}

	// The FirstDrop lands on the output subject; its input/output hash is the
	// posted body's content address (verbatim ingestion).
	var wire []byte
	select {
	case wire = <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("no envelope delivered on the output subject")
	}
	env, err := envelopecodec.New().UnmarshalEnvelope(wire)
	if err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if string(env.Payload) != rawJSON {
		t.Fatalf("payload: got %q want %q", env.Payload, rawJSON)
	}
	if env.Credential == nil || env.Credential.Proof() == nil {
		t.Fatal("envelope carries no signed credential")
	}
	subj, err := env.Credential.Subject()
	if err != nil {
		t.Fatalf("subject: %v", err)
	}
	if subj.InputHash != wantHash || subj.OutputHash != wantHash {
		t.Fatalf("credential hashes = %q / %q, want both %q", subj.InputHash, subj.OutputHash, wantHash)
	}

	cancel()
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("dp.Run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("data plane did not drain")
	}
}

// TestPushRoutes_PDPDenial403 pins the auth mapping: a bearer the PDP denies is 403
// (any Verify failure — the RPC interceptor likewise does not distinguish denial
// from outage), distinct from the 401 of a missing bearer. Also pins Retry-After
// on the readiness 503.
func TestPushRoutes_PDPDenial403(t *testing.T) {
	ready := make(chan struct{})
	close(ready)
	denyAll := endpoint.NewStaticEndpoint(nil) // no rules => every Verify fails
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) })
	h := pushRoutes(inner, denyAll, ready)

	req := httptest.NewRequest(http.MethodPost, "/push", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("PDP-denied push: got %d, want 403", rec.Code)
	}

	// Readiness 503 carries Retry-After (allowed but not ready).
	allow := endpoint.NewStaticEndpoint([]endpoint.StaticRule{{Resource: "ingest", Action: "push"}})
	h = pushRoutes(inner, allow, make(chan struct{}))
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/push", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer tok")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Errorf("not-ready push: got %d (Retry-After %q), want 503 with Retry-After", rec.Code, rec.Header().Get("Retry-After"))
	}
}

// waitFor polls cond until it returns true or the deadline passes.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.After(timeout)
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		if cond() {
			return
		}
		select {
		case <-tick.C:
		case <-deadline:
			t.Fatal(msg)
		}
	}
}
