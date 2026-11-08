package batchresolver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"strings"
	"testing"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/internal/netexcerpt"
	"github.com/provin-line/oss/vc"
)

// A log line of the batch resolver names an endpoint within
// netexcerpt.ValueLimit bytes and an error within netexcerpt.TextLimit bytes,
// both quoted, on one line, however long the endpoint a caller hinted or the
// error a peer answered.
func TestDrainOnce_LogsAnEndpointAndAnErrorWithinTheLimits(t *testing.T) {
	ctx := context.Background()
	longText := strings.Repeat("ab\n\xff", 64<<10)
	endpoint := "https://peer.example/" + strings.Repeat("p\n", 32<<10)
	for _, c := range []struct {
		name  string
		guard fakeGuard
		err   error
	}{
		{"terminal fetch error", fakeGuard{}, connect.NewError(connect.CodePermissionDenied, errors.New(longText))},
		{"refused endpoint", fakeGuard{deny: map[string]bool{endpoint: true}}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			pool, svc := newWiring()
			h := credOf(t, "sha256:"+strings.Repeat("a", 64))
			if _, err := svc.StoreVC(ctx, mustJSON(t, h), endpoint, 0); err != nil {
				t.Fatal(err)
			}
			fetch := &fakeFetcher{fn: func(context.Context, string, string) (*vc.PipelinePassCredential, error) {
				return nil, c.err
			}}
			var buf bytes.Buffer
			r, err := New(pool, svc, fetch, fakeDID{}, c.guard, okConfig(), WithLogger(log.New(&buf, "", 0)))
			if err != nil {
				t.Fatal(err)
			}
			if err := r.drainOnce(ctx); err != nil {
				t.Fatal(err)
			}
			lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
			if len(lines) != 1 {
				t.Fatalf("logged %d lines, want 1: %.200q", len(lines), buf.String())
			}
			if max := 160 + netexcerpt.ValueLimit + netexcerpt.TextLimit; len(lines[0]) > max {
				t.Errorf("log line of %d bytes, want at most %d: %.160q", len(lines[0]), max, lines[0])
			}
		})
	}
}

// A log line naming the issuer whose DID document gives no fetch endpoint
// names the issuer within netexcerpt.ValueLimit bytes and the resolver's
// error within netexcerpt.TextLimit bytes, on one line: StoreVC takes the
// issuer from the credential as it is.
func TestDrainOnce_LogsAnIssuerWithinTheLimit(t *testing.T) {
	ctx := context.Background()
	longText := strings.Repeat("ab\n\xff", 64<<10)
	pool, svc := newWiring()
	b, err := json.Marshal(map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            strings.Repeat("did:\n", 16<<10),
		"credentialSubject": map[string]any{"pipelineId": "p1", "processId": "proc1", "previousCredential": "sha256:" + strings.Repeat("c", 64)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.StoreVC(ctx, b, "", 0); err != nil {
		t.Fatal(err)
	}
	fetch := &fakeFetcher{fn: func(context.Context, string, string) (*vc.PipelinePassCredential, error) { return nil, notFound() }}
	var buf bytes.Buffer
	r, err := New(pool, svc, fetch, fakeDID{err: errors.New(longText)}, fakeGuard{}, okConfig(), WithLogger(log.New(&buf, "", 0)))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.drainOnce(ctx); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n") {
		if max := 160 + netexcerpt.ValueLimit + netexcerpt.TextLimit; len(line) > max {
			t.Errorf("log line of %d bytes, want at most %d: %.160q", len(line), max, line)
		}
	}
	if !strings.Contains(buf.String(), "endpoint derivation") {
		t.Errorf("the issuer's derivation was not logged: %.200q", buf.String())
	}
}
