package orgverify

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
)

// DNSResolver looks up TXT records. Implemented by net.Resolver (via
// SystemDNSResolver) and by fakes in tests. The implementation MUST
// distinguish error categories so that Unreachable (reachability) and
// Missing (authoritative no-record) cases are classified correctly.
type DNSResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// Sentinel errors. Implementations should return one of these (or wrap them)
// so that error classification helpers can identify the failure mode.
var (
	ErrDNSTimeout    = errors.New("dns: timeout")
	ErrDNSServerFail = errors.New("dns: SERVFAIL")
	ErrDNSTransport  = errors.New("dns: transport error")
	ErrDNSNoRecords  = errors.New("dns: no records (NXDOMAIN or NOERROR+empty)")
)

type dnsError struct {
	cause   error
	message string
}

func (e *dnsError) Error() string { return e.message + ": " + e.cause.Error() }
func (e *dnsError) Unwrap() error { return e.cause }

// IsDNSReachabilityError reports whether err represents a DNS reachability
// problem (timeout, SERVFAIL, transport) — these classify as Unreachable.
// NXDOMAIN and NOERROR+empty are authoritative answers, not reachability
// failures, and classify as Missing.
func IsDNSReachabilityError(err error) bool {
	return errors.Is(err, ErrDNSTimeout) ||
		errors.Is(err, ErrDNSServerFail) ||
		errors.Is(err, ErrDNSTransport)
}

// IsDNSNoRecordsError reports whether err represents an authoritative
// no-records answer (NXDOMAIN or NOERROR+empty).
func IsDNSNoRecordsError(err error) bool {
	return errors.Is(err, ErrDNSNoRecords)
}

// SystemDNSResolver wraps net.Resolver and translates net.DNSError into the
// sentinel errors above.
type SystemDNSResolver struct {
	R *net.Resolver
}

// NewSystemDNSResolver returns a SystemDNSResolver using net.DefaultResolver.
func NewSystemDNSResolver() *SystemDNSResolver {
	return &SystemDNSResolver{R: net.DefaultResolver}
}

func (s *SystemDNSResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	r := s.R
	if r == nil {
		r = net.DefaultResolver
	}
	records, err := r.LookupTXT(ctx, name)
	if err != nil {
		return nil, classifyNetDNSError(err)
	}
	return records, nil
}

func classifyNetDNSError(err error) error {
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) {
		return &dnsError{cause: ErrDNSTransport, message: fmt.Sprintf("non-DNS error: %v", err)}
	}
	if dnsErr.IsTimeout {
		return &dnsError{cause: ErrDNSTimeout, message: dnsErr.Error()}
	}
	// IsNotFound covers both NXDOMAIN and NOERROR+empty answers.
	if dnsErr.IsNotFound {
		return &dnsError{cause: ErrDNSNoRecords, message: dnsErr.Error()}
	}
	// Heuristic: net.DNSError doesn't expose RCODE directly, but messages
	// containing "server misbehaving" map to SERVFAIL on most platforms.
	if strings.Contains(dnsErr.Err, "server misbehaving") {
		return &dnsError{cause: ErrDNSServerFail, message: dnsErr.Error()}
	}
	if dnsErr.IsTemporary {
		return &dnsError{cause: ErrDNSTransport, message: dnsErr.Error()}
	}
	return &dnsError{cause: ErrDNSTransport, message: dnsErr.Error()}
}
