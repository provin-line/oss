package commands_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/cmd/provin/internal/commands"
	chainpb "github.com/provin-line/oss/gen/go/dplaax/chain/v1"
	"github.com/provin-line/oss/gen/go/dplaax/chain/v1/chainpbconnect"
)

const (
	subscriberDID = "did:dplaax:poc.dplaax.dev:org:beta:pipeline:relay"
	publisherDID  = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:lot"
)

// fakeChainService records every Subscribe/UpdateAllowList request it
// receives, mirroring fakeSchemaService's recording-fake shape.
type fakeChainService struct {
	chainpbconnect.UnimplementedChainServiceHandler
	mu                   sync.Mutex
	subscribeCalls       []*chainpb.SubscribeRequest
	updateAllowListCalls []*chainpb.UpdateAllowListRequest
	subscriptionID       string
	subscribeErr         error
	updateAllowListErr   error
}

func (f *fakeChainService) Subscribe(_ context.Context, req *connect.Request[chainpb.SubscribeRequest]) (*connect.Response[chainpb.SubscribeResponse], error) {
	f.mu.Lock()
	f.subscribeCalls = append(f.subscribeCalls, req.Msg)
	f.mu.Unlock()
	if f.subscribeErr != nil {
		return nil, f.subscribeErr
	}
	return connect.NewResponse(&chainpb.SubscribeResponse{SubscriptionId: f.subscriptionID}), nil
}

func (f *fakeChainService) UpdateAllowList(_ context.Context, req *connect.Request[chainpb.UpdateAllowListRequest]) (*connect.Response[chainpb.UpdateAllowListResponse], error) {
	f.mu.Lock()
	f.updateAllowListCalls = append(f.updateAllowListCalls, req.Msg)
	f.mu.Unlock()
	if f.updateAllowListErr != nil {
		return nil, f.updateAllowListErr
	}
	return connect.NewResponse(&chainpb.UpdateAllowListResponse{}), nil
}

func (f *fakeChainService) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.subscribeCalls) + len(f.updateAllowListCalls)
}

// newChainNode stands up a bearer-gated ChainService fake over httptest.
func newChainNode(t *testing.T, fake *fakeChainService) *httptest.Server {
	t.Helper()
	path, h := chainpbconnect.NewChainServiceHandler(fake)
	mux := http.NewServeMux()
	mux.Handle(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			http.Error(w, "missing bearer", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	}))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// --- chain subscribe -----------------------------------------------------

func TestChainSubscribe_HappyPath(t *testing.T) {
	fake := &fakeChainService{subscriptionID: "sub-abc123"}
	srv := newChainNode(t, fake)
	var out bytes.Buffer

	err := commands.ChainSubscribe(context.Background(), env(srv, &out), commands.ChainSubscribeConfig{
		Subscriber: subscriberDID,
		Publisher:  publisherDID,
		Delivery:   "inline",
	})
	if err != nil {
		t.Fatalf("ChainSubscribe: %v", err)
	}
	if fake.callCount() != 1 {
		t.Fatalf("call count = %d, want 1", fake.callCount())
	}
	got := fake.subscribeCalls[0]
	if got.GetSubscriberDid() != subscriberDID || got.GetPublisherDid() != publisherDID {
		t.Errorf("subscriber/publisher pass-through mismatch: %+v", got)
	}
	want := "subscribed sub-abc123 (delivery requested: inline)\n"
	if out.String() != want {
		t.Errorf("output = %q, want %q", out.String(), want)
	}
}

// The delivery mode is passed through raw on the wire: an omitted flag must
// reach the server as an EMPTY string (never a client-invented default), and
// the CLI's own output must not claim the mode as server-confirmed (spec §6
// High-1) — SubscribeResponse carries only the id.
func TestChainSubscribe_DeliveryPassThrough(t *testing.T) {
	tests := []struct {
		name       string
		delivery   string
		wantWire   string
		wantOutput string
	}{
		{"omitted", "", "", "subscribed sub-1 (delivery requested: by-reference (protocol default))\n"},
		{"explicit inline", "inline", "inline", "subscribed sub-1 (delivery requested: inline)\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeChainService{subscriptionID: "sub-1"}
			srv := newChainNode(t, fake)
			var out bytes.Buffer
			err := commands.ChainSubscribe(context.Background(), env(srv, &out), commands.ChainSubscribeConfig{
				Subscriber: subscriberDID, Publisher: publisherDID, Delivery: tc.delivery,
			})
			if err != nil {
				t.Fatalf("ChainSubscribe: %v", err)
			}
			if got := fake.subscribeCalls[0].GetPayloadDelivery(); got != tc.wantWire {
				t.Errorf("wire payload_delivery = %q, want %q", got, tc.wantWire)
			}
			if out.String() != tc.wantOutput {
				t.Errorf("output = %q, want %q", out.String(), tc.wantOutput)
			}
		})
	}
}

func TestChainSubscribe_RPCErrorPropagates(t *testing.T) {
	fake := &fakeChainService{subscribeErr: connect.NewError(connect.CodeNotFound, errors.New("unknown publisher"))}
	srv := newChainNode(t, fake)
	err := commands.ChainSubscribe(context.Background(), env(srv, &bytes.Buffer{}), commands.ChainSubscribeConfig{
		Subscriber: subscriberDID, Publisher: publisherDID,
	})
	if err == nil || !strings.Contains(err.Error(), "unknown publisher") {
		t.Fatalf("RPC error: want the connect error surfaced, got %v", err)
	}
}

// --- chain set-allow -------------------------------------------------------

func TestChainSetAllow_FullReplacementPassesAllPatterns(t *testing.T) {
	fake := &fakeChainService{}
	srv := newChainNode(t, fake)
	var out bytes.Buffer

	err := commands.ChainSetAllow(context.Background(), env(srv, &out), commands.ChainSetAllowConfig{
		Pipeline: publisherDID,
		Patterns: []string{"did:dplaax:*:org:beta", "did:dplaax:*:org:gamma"},
	})
	if err != nil {
		t.Fatalf("ChainSetAllow: %v", err)
	}
	if fake.callCount() != 1 {
		t.Fatalf("call count = %d, want 1", fake.callCount())
	}
	got := fake.updateAllowListCalls[0]
	if got.GetPipelineDid() != publisherDID {
		t.Errorf("pipeline_did = %q, want %q", got.GetPipelineDid(), publisherDID)
	}
	rules := got.GetRules()
	if len(rules) != 2 || rules[0].GetPattern() != "did:dplaax:*:org:beta" || rules[1].GetPattern() != "did:dplaax:*:org:gamma" {
		t.Errorf("rules pass-through mismatch: %+v", rules)
	}
	want := "allow-list for " + publisherDID + " replaced (2 rules)\n"
	if out.String() != want {
		t.Errorf("output = %q, want %q", out.String(), want)
	}
}

// --clear replaces with zero rules — an explicit deny-all, not the absence
// of any rule argument.
func TestChainSetAllow_ClearSendsZeroRules(t *testing.T) {
	fake := &fakeChainService{}
	srv := newChainNode(t, fake)
	var out bytes.Buffer

	err := commands.ChainSetAllow(context.Background(), env(srv, &out), commands.ChainSetAllowConfig{
		Pipeline: publisherDID,
		Clear:    true,
	})
	if err != nil {
		t.Fatalf("ChainSetAllow: %v", err)
	}
	got := fake.updateAllowListCalls[0]
	if len(got.GetRules()) != 0 {
		t.Errorf("rules = %v, want zero rules", got.GetRules())
	}
	want := "allow-list for " + publisherDID + " replaced (0 rules)\n"
	if out.String() != want {
		t.Errorf("output = %q, want %q", out.String(), want)
	}
}

// Neither --pattern nor --clear is a usage error: an empty replacement must
// be an explicit operator decision, never a typo's side effect. No RPC is
// attempted (spec §6 Low-5) — the fake's zero call count is the proof.
func TestChainSetAllow_NoPatternNoClearIsUsageError(t *testing.T) {
	fake := &fakeChainService{}
	srv := newChainNode(t, fake)

	err := commands.ChainSetAllow(context.Background(), env(srv, &bytes.Buffer{}), commands.ChainSetAllowConfig{
		Pipeline: publisherDID,
	})
	if err == nil {
		t.Fatal("no --pattern and no --clear: want a usage error")
	}
	if fake.callCount() != 0 {
		t.Errorf("no --pattern and no --clear: RPC should not be attempted, calls=%d", fake.callCount())
	}
}

// --clear together with --pattern is a usage error (ambiguous intent). No
// RPC is attempted.
func TestChainSetAllow_ClearAndPatternIsUsageError(t *testing.T) {
	fake := &fakeChainService{}
	srv := newChainNode(t, fake)

	err := commands.ChainSetAllow(context.Background(), env(srv, &bytes.Buffer{}), commands.ChainSetAllowConfig{
		Pipeline: publisherDID,
		Clear:    true,
		Patterns: []string{"did:dplaax:*:org:beta"},
	})
	if err == nil {
		t.Fatal("--clear with --pattern: want a usage error")
	}
	if fake.callCount() != 0 {
		t.Errorf("--clear with --pattern: RPC should not be attempted, calls=%d", fake.callCount())
	}
}

func TestChainSetAllow_RPCErrorPropagates(t *testing.T) {
	fake := &fakeChainService{updateAllowListErr: connect.NewError(connect.CodeNotFound, errors.New("unknown pipeline"))}
	srv := newChainNode(t, fake)
	err := commands.ChainSetAllow(context.Background(), env(srv, &bytes.Buffer{}), commands.ChainSetAllowConfig{
		Pipeline: publisherDID,
		Patterns: []string{"did:dplaax:*:org:beta"},
	})
	if err == nil || !strings.Contains(err.Error(), "unknown pipeline") {
		t.Fatalf("RPC error: want the connect error surfaced, got %v", err)
	}
}
