package pagination_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/provin-line/oss/network/pkg/pagination"
)

func TestClampSize(t *testing.T) {
	cases := []struct {
		in      int32
		want    int
		wantErr bool
	}{
		{0, pagination.DefaultPageSize, false},
		{1, 1, false},
		{256, 256, false},
		{257, pagination.MaxPageSize, false}, // clamped, never an error
		{1 << 30, pagination.MaxPageSize, false},
		{-1, 0, true},
	}
	for _, c := range cases {
		got, err := pagination.ClampSize(c.in)
		if c.wantErr {
			if !errors.Is(err, pagination.ErrInvalidPageSize) {
				t.Errorf("ClampSize(%d): err=%v, want ErrInvalidPageSize", c.in, err)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("ClampSize(%d) = %d (err %v), want %d", c.in, got, err, c.want)
		}
	}
}

func TestToken_RoundTrip(t *testing.T) {
	cursor := "sha256:" + strings.Repeat("ab", 32) // cursors contain ':' — must survive
	tok := pagination.EncodeToken("svc.List", cursor, "2026-01-01T00:00:00Z", "")
	got, err := pagination.DecodeToken("svc.List", tok, "2026-01-01T00:00:00Z", "")
	if err != nil || got != cursor {
		t.Fatalf("round trip = %q (err %v), want %q", got, err, cursor)
	}
}

func TestToken_EmptyStartsFromBeginning(t *testing.T) {
	if got, err := pagination.DecodeToken("svc.List", "", "f1"); err != nil || got != "" {
		t.Fatalf("empty token = %q (err %v), want \"\"", got, err)
	}
}

func TestToken_ChangedFiltersRejected(t *testing.T) {
	tok := pagination.EncodeToken("svc.List", "cursor", "filterA")
	if _, err := pagination.DecodeToken("svc.List", tok, "filterB"); !errors.Is(err, pagination.ErrInvalidToken) {
		t.Fatalf("changed filters: err=%v, want ErrInvalidToken", err)
	}
}

// A continuation minted by one listing must never resume another: the same
// cursor value keys different listings (a hash is both a receipt page key
// and a successor page key).
func TestToken_CrossListingRejected(t *testing.T) {
	tok := pagination.EncodeToken("svc.ListA", "cursor", "f")
	if _, err := pagination.DecodeToken("svc.ListB", tok, "f"); !errors.Is(err, pagination.ErrInvalidToken) {
		t.Fatalf("cross-listing replay: err=%v, want ErrInvalidToken", err)
	}
}

func TestToken_MalformedRejected(t *testing.T) {
	for _, tok := range []string{"not-base64!!!", "AAAA", "djI6eDp5"} { // last decodes to "v2:x:y"
		if _, err := pagination.DecodeToken("svc.List", tok); !errors.Is(err, pagination.ErrInvalidToken) {
			t.Errorf("token %q: err=%v, want ErrInvalidToken", tok, err)
		}
	}
}
