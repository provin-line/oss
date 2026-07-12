package orgverify

import (
	"context"
	"errors"
	"testing"
)

// stubResolver is orgverify's own fake DNSResolver — never touches real DNS.
type stubResolver struct {
	records []string
	err     error
}

func (s *stubResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return s.records, s.err
}

func TestStubResolver_Implements(t *testing.T) {
	var _ DNSResolver = (*stubResolver)(nil)
}

func TestErrTypes(t *testing.T) {
	if !IsDNSReachabilityError(ErrDNSTimeout) {
		t.Error("ErrDNSTimeout should be reachability error")
	}
	if !IsDNSReachabilityError(ErrDNSServerFail) {
		t.Error("ErrDNSServerFail should be reachability error")
	}
	if IsDNSReachabilityError(ErrDNSNoRecords) {
		t.Error("ErrDNSNoRecords should NOT be reachability error (authoritative answer)")
	}
	wrapped := &dnsError{cause: ErrDNSTimeout, message: "wrap"}
	if !IsDNSReachabilityError(wrapped) {
		t.Error("wrapped ErrDNSTimeout should still be reachability error")
	}
	if IsDNSReachabilityError(errors.New("random")) {
		t.Error("random error should not be reachability error")
	}
}
