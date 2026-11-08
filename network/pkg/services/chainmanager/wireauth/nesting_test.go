package wireauth_test

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/internal/jsondepth"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/wireauth"
)

// deep is depth arrays and objects, alternating, around a string.
func deep(depth int) any {
	var v any = "x"
	for i := range depth {
		if i%2 == 0 {
			v = []any{v}
		} else {
			v = map[string]any{"k": v}
		}
	}
	return v
}

// countingResolver counts the DIDs it is asked to resolve.
type countingResolver struct {
	mapResolver
	calls int
}

func (r *countingResolver) Resolve(ctx context.Context, d string) (*did.DIDDocument, error) {
	r.calls++
	return r.mapResolver.Resolve(ctx, d)
}

// The fields grammar is the gate of Sign and Verify. The view holds the fields
// one level down, so fields may nest at most jsondepth.Max-1 objects and
// arrays, the fields object counted: the gate refuses deeper fields with
// ErrInvalidView before anything recurses past the bound (held to a 64 MB
// stack, fields a million deep would exhaust it in the check, a fatal error),
// and Verify refuses them before it resolves the signer. What passes signs
// and verifies, the deep copy handed to the authorizer included. The refusal
// spells the path once and within a bound, so refusing fields at the bound
// takes little memory.
func TestFields_RefusedPastTheBoundAtTheGate(t *testing.T) {
	defer debug.SetMaxStack(debug.SetMaxStack(64 << 20))
	signer, pub := signerFor(t, subDID)
	resolver := &countingResolver{mapResolver: mapResolver{subDID: authDoc(subDID, pub)}}
	v := testVerifier(t, resolver)
	for _, depth := range []int{jsondepth.Max - 1, jsondepth.Max, 1000000} {
		fields := map[string]any{"k": deep(depth)}
		_, err := wireauth.Sign(signer, subDID, "Op", fields, "n1", at())
		if !errors.Is(err, wireauth.ErrInvalidView) || !strings.Contains(err.Error(), "nested deeper than") || len(err.Error()) > 1024 {
			t.Errorf("Sign, fields %d deep: %.200v (%d bytes), want ErrInvalidView for the nesting within 1 KiB", depth+1, err, len(fmt.Sprint(err)))
		}
		resolver.calls = 0
		if err := v.Verify(context.Background(), "Op", fields, wireauth.Proof{SignerDID: subDID, Nonce: "n1", IssuedAt: at(), Signature: []byte("x")}, nil); !errors.Is(err, wireauth.ErrInvalidView) || resolver.calls != 0 {
			t.Errorf("Verify, fields %d deep: %.200v, %d resolutions, want ErrInvalidView before resolving", depth+1, err, resolver.calls)
		}
	}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, _ = wireauth.Sign(signer, subDID, "Op", map[string]any{"k": deep(jsondepth.Max)}, "n1", at())
	runtime.ReadMemStats(&after)
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 16<<20 {
		t.Errorf("refusing fields past the bound allocated %d bytes", allocated)
	}
	fields := map[string]any{"k": deep(jsondepth.Max - 2)}
	proof, err := wireauth.Sign(signer, subDID, "Op", fields, "n3", at())
	if err != nil {
		t.Fatalf("Sign, fields %d deep: %v", jsondepth.Max-1, err)
	}
	var seen map[string]any
	authorize := func(_ string, _ *did.DIDDocument, f map[string]any) error { seen = f; return nil }
	if err := v.Verify(context.Background(), "Op", fields, proof, authorize); err != nil || seen == nil {
		t.Errorf("Verify, fields %d deep: %v, authorizer called: %v", jsondepth.Max-1, err, seen != nil)
	}
}
