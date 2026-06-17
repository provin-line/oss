// Package didresolver is the outbound, cross-registry DID resolver: given a
// did:dplaax DID it derives the owning registry's W3C resolution URL, fetches the
// document over an SSRF-guarded HTTP client, and returns the parsed
// *did.DIDDocument. It is the production replacement for the in-memory test
// resolvers, and its Resolve shape satisfies both wireauth.DIDResolver (the
// publisher-side verifier) and chainmanager.DIDResolver (the subscriber side).
package didresolver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/did/dplaax"
	"github.com/provin-line/oss/network/pkg/core"
)

// maxDocumentSize bounds the resolution response body: it is attacker-controlled
// (a hostile registry can return anything, and resolution may be triggered by an
// inbound proof's signer DID), so the body is read through an io.LimitReader and
// an over-cap response is an error rather than unbounded memory.
const maxDocumentSize = 1 << 20 // 1 MiB

var (
	// ErrDIDNotFound is returned when the registry has no such DID (HTTP 404).
	ErrDIDNotFound = errors.New("didresolver: DID not found")
	// ErrDIDIdentityMismatch is returned when the resolved document's id does not
	// equal the requested DID — a misconfigured or hostile base mapping returning
	// a substituted identity. Fail closed rather than trust it.
	ErrDIDIdentityMismatch = errors.New("didresolver: resolved document id does not match requested DID")
)

// Resolver resolves did:dplaax DIDs over HTTP against their owning registry.
type Resolver struct {
	client  *http.Client
	guard   *core.URLGuard
	baseURL func(registry string) (string, error)
}

// Option configures a Resolver.
type Option func(*Resolver)

// WithRegistryBaseURL overrides how a registry id maps to its base URL. The
// default is "https://" + registry (the dplaax contract: Registry is a domain
// name and resolution URLs derive from it). Tests point this at an httptest
// server; a deployment may map a registry id to a non-obvious endpoint.
func WithRegistryBaseURL(f func(registry string) (string, error)) Option {
	return func(r *Resolver) { r.baseURL = f }
}

// New returns a Resolver dialing through guard's SSRF-guarded HTTP client. A nil
// guard yields a strict default (fail-closed). The base-URL derivation defaults
// to https://{registry}.
func New(guard *core.URLGuard, opts ...Option) *Resolver {
	if guard == nil {
		guard = core.NewURLGuard()
	}
	r := &Resolver{
		client:  guard.HTTPClient(),
		guard:   guard,
		baseURL: func(registry string) (string, error) { return "https://" + registry, nil },
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Resolve fetches and parses the DID document for didStr. It returns
// ErrDIDNotFound for a registry miss and ErrDIDIdentityMismatch when the returned
// document's id differs from didStr; transport, status, size, and parse failures
// are wrapped. It does NOT validate the document's keys/relationships — that is
// the consumer's policy step (wireauth.ExtractPublicKey).
func (r *Resolver) Resolve(ctx context.Context, didStr string) (*did.DIDDocument, error) {
	d, err := dplaax.Parse(didStr)
	if err != nil {
		return nil, fmt.Errorf("didresolver: parse %q: %w", didStr, err)
	}
	url, err := r.resolutionURL(d)
	if err != nil {
		return nil, err
	}
	// Early typed SSRF rejection before dialing; the guarded client also re-guards
	// at dial time (DNS-rebinding), so this preflight is defense-in-depth.
	if err := r.guard.CheckURL(ctx, url); err != nil {
		return nil, fmt.Errorf("didresolver: endpoint rejected: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("didresolver: build request: %w", err)
	}
	req.Header.Set("Accept", "application/did+json")
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("didresolver: fetch %s: %w", didStr, err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, fmt.Errorf("%w: %s", ErrDIDNotFound, didStr)
	default:
		return nil, fmt.Errorf("didresolver: %s: unexpected status %d", didStr, resp.StatusCode)
	}
	// Bounded read: cap+1 so an exactly-cap body still fits and an over-cap body
	// is detected.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDocumentSize+1))
	if err != nil {
		return nil, fmt.Errorf("didresolver: read %s: %w", didStr, err)
	}
	if len(body) > maxDocumentSize {
		return nil, fmt.Errorf("didresolver: %s: document exceeds %d bytes", didStr, maxDocumentSize)
	}
	var doc did.DIDDocument
	if err := doc.UnmarshalJSON(body); err != nil {
		return nil, fmt.Errorf("didresolver: parse document for %s: %w", didStr, err)
	}
	if doc.ID() != didStr {
		return nil, fmt.Errorf("%w: got %q for %q", ErrDIDIdentityMismatch, doc.ID(), didStr)
	}
	return &doc, nil
}

// resolutionURL builds {base}/did/{accountType}/{accountID}/{resourcePath…}/did.json,
// the inverse of the W3C resolution handler's path parsing (segments after the
// registry, joined by "/").
func (r *Resolver) resolutionURL(d *dplaax.DID) (string, error) {
	base, err := r.baseURL(d.Registry)
	if err != nil {
		return "", fmt.Errorf("didresolver: base URL for registry %q: %w", d.Registry, err)
	}
	segs := append([]string{d.AccountType, d.AccountID}, d.ResourcePath...)
	return strings.TrimRight(base, "/") + "/did/" + strings.Join(segs, "/") + "/did.json", nil
}
