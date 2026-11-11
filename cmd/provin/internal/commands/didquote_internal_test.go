package commands

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// A DID that does not parse is named within a bound, however long it is: an
// issuer the bundle export meets, a DID the org commands are given.
func TestUnparsableDIDIsNamedWithinABound(t *testing.T) {
	long := "did:dplaax:poc.dplaax.dev:org:" + strings.Repeat("x", 5000) + "!"
	ctx := context.Background()
	src := &wireConsumedSource{}
	for name, call := range map[string]func() error{
		"bundle export registry base": func() error { _, err := src.registryBase(long); return err },
		"bundle export #audit":        func() error { _, err := src.auditEndpoint(ctx, long); return err },
		"bundle export #vc-resolver":  func() error { _, err := src.vcResolverEndpoint(ctx, long); return err },
		"org owner DID":               func() error { _, err := orgOwnerDID(long); return err },
		"registry document resolver":  func() error { _, err := (&registryDocResolver{}).Resolve(ctx, long); return err },
	} {
		if err := call(); err == nil || len(err.Error()) > 500 || !strings.Contains(err.Error(), fmt.Sprintf("(%d bytes)", len(long))) {
			t.Errorf("%s: %.200v (%d bytes), want an error naming the DID's head and length", name, err, len(fmt.Sprint(err)))
		}
	}
}
