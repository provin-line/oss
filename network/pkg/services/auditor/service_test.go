package auditor_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/network/pkg/services/auditor"
	"github.com/provin-line/oss/vc"
)

var validHash = "sha256:" + strings.Repeat("a", 64)

// GetStatus owns the domain logic: validate the content address, then read the store.
// A malformed hash is ErrInvalidArgument BEFORE any lookup; a well-formed miss is
// ErrNotFound; a hit returns the record verbatim.
func TestStatusService_GetStatus(t *testing.T) {
	store := auditor.NewMemStatusStore()
	svc := auditor.NewStatusService(store)
	ctx := context.Background()

	// Malformed → ErrInvalidArgument (checked before the store, so a primed store is moot).
	for _, bad := range []string{"", "not-a-hash", "sha256:short", "sha256:" + strings.Repeat("A", 64)} {
		if _, err := svc.GetStatus(ctx, bad); !errors.Is(err, auditor.ErrInvalidArgument) {
			t.Errorf("hash %q: err = %v, want ErrInvalidArgument", bad, err)
		}
	}

	// Well-formed but absent → ErrNotFound.
	if _, err := svc.GetStatus(ctx, validHash); !errors.Is(err, auditor.ErrNotFound) {
		t.Errorf("absent: err = %v, want ErrNotFound", err)
	}

	// Hit → record verbatim.
	want := auditor.AuditRecord{
		Overall:   vc.ConfidenceVerified,
		Scope:     auditor.AuditScope{LinearChain: true},
		AuditedAt: time.Unix(1700000000, 0).UTC(),
	}
	if err := store.Put(validHash, want); err != nil {
		t.Fatal(err)
	}
	got, err := svc.GetStatus(ctx, validHash)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if got.Overall != want.Overall || got.Scope != want.Scope || !got.AuditedAt.Equal(want.AuditedAt) {
		t.Errorf("GetStatus = %+v, want %+v", got, want)
	}
}
