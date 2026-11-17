package bundle

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// A DID that does not parse is named within a bound, however long it is: one
// the export resolves, one it lays out a document path for.
func TestUnparsableDIDIsNamedWithinABound(t *testing.T) {
	long := "did:dplaax:poc.dplaax.dev:org:" + strings.Repeat("x", 64<<10) + "!"
	_, resolveErr := newRecordingResolver(nil).Resolve(context.Background(), long)
	_, pathErr := documentPath(long)
	for name, err := range map[string]error{
		"resolve":       resolveErr,
		"document path": pathErr,
	} {
		if err == nil || len(err.Error()) > 500 || !strings.Contains(err.Error(), fmt.Sprintf("(%d bytes)", len(long))) {
			t.Errorf("%s: %.200v (%d bytes), want an error naming the DID's head and length", name, err, len(fmt.Sprint(err)))
		}
	}
}
