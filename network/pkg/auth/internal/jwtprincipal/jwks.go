package jwtprincipal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const (
	// jwksTTL bounds how long a fetched key set is trusted; after it the set is
	// refetched before any token is verified.
	jwksTTL = 10 * time.Minute
	// jwksGrace is how long past its TTL a key set still verifies tokens for the
	// key ids it holds while no fresher set can be fetched. It bounds how long a
	// withdrawn key stays trusted during an endpoint outage.
	jwksGrace = 30 * time.Minute
	// jwksMinRefetch is the shortest gap between two fetches. It caps the
	// request rate to the JWKS endpoint when tokens name unknown key ids.
	jwksMinRefetch = 30 * time.Second
	// jwksTimeout bounds a single fetch.
	jwksTimeout = 5 * time.Second
	// maxJWKSBytes caps the accepted response body.
	maxJWKSBytes = 1 << 20
)

// keyFetchClient is the HTTP client used to fetch the key set. Tests inject one
// that trusts their server's certificate.
type keyFetchClient = *http.Client

type jwksCache struct {
	url    string
	client *http.Client
	now    func() time.Time

	mu          sync.Mutex
	set         *jose.JSONWebKeySet
	fetchedAt   time.Time
	lastAttempt time.Time
	inflight    *flight
}

// flight is one running fetch that every waiting caller shares.
type flight struct {
	done chan struct{}
	err  error
}

var errRefetchLimited = errors.New("key set refetch rate-limited")

func newJWKSCache(url string, client *http.Client, now func() time.Time) *jwksCache {
	if client == nil {
		client = &http.Client{}
	}
	c := *client
	c.Timeout = jwksTimeout
	// A redirect would let the endpoint send the fetch (and the trust placed in
	// its answer) elsewhere; the redirect response is treated as a failure.
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &jwksCache{url: url, client: &c, now: now}
}

// key returns the verification key for a token header.
//
// A key set younger than jwksTTL is used as is. A missing key id or an expired
// set triggers one shared fetch, started at most every jwksMinRefetch. The fetch
// runs detached from the caller's context, so a caller that gives up neither
// fails it for the others nor spends the rate limit with a fetch that never
// completed. If the set is expired and the fetch fails or is rate-limited, the
// set still verifies tokens for the key ids it holds until jwksGrace after its
// expiry; an unknown key id is always refused.
func (c *jwksCache) key(ctx context.Context, h jose.Header) (any, error) {
	c.mu.Lock()
	now := c.now()
	if c.set != nil && now.Sub(c.fetchedAt) < jwksTTL {
		if k, ok := lookup(c.set, h); ok {
			c.mu.Unlock()
			return k, nil
		}
	}
	fl := c.inflight
	if fl == nil && (c.lastAttempt.IsZero() || now.Sub(c.lastAttempt) >= jwksMinRefetch) {
		fl = &flight{done: make(chan struct{})}
		c.inflight = fl
		c.lastAttempt = now
		go c.run(fl)
	}
	c.mu.Unlock()

	fetchErr := errRefetchLimited
	if fl != nil {
		select {
		case <-fl.done:
			fetchErr = fl.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	c.mu.Lock()
	set, age := c.set, c.now().Sub(c.fetchedAt)
	c.mu.Unlock()
	switch {
	case set == nil:
		return nil, fmt.Errorf("no key set available: %w", fetchErr)
	case age < jwksTTL:
	case fetchErr != nil && age < jwksTTL+jwksGrace:
	default:
		return nil, fmt.Errorf("key set expired: %w", fetchErr)
	}
	if k, ok := lookup(set, h); ok {
		return k, nil
	}
	return nil, fmt.Errorf("no verification key for kid %q", h.KeyID)
}

func (c *jwksCache) run(fl *flight) {
	ctx, cancel := context.WithTimeout(context.Background(), jwksTimeout)
	defer cancel()
	set, err := c.fetch(ctx)
	c.mu.Lock()
	if err == nil {
		c.set, c.fetchedAt = set, c.now()
	}
	c.inflight = nil
	c.mu.Unlock()
	if err != nil {
		fl.err = fmt.Errorf("fetch jwks: %w", err)
	}
	close(fl.done)
}

func (c *jwksCache) fetch(ctx context.Context) (*jose.JSONWebKeySet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxJWKSBytes {
		return nil, fmt.Errorf("response larger than %d bytes", maxJWKSBytes)
	}
	var set jose.JSONWebKeySet
	// The key set is the issuer's own document, not a protocol payload: no hashed
	// or signed canonical form is derived from it, and a duplicate member can only
	// change which of the issuer's own keys is read.
	// decoder-hygiene-exempt: see above.
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return &set, nil
}

// lookup picks the signing key a token header names. A token without a key id
// is accepted only when the set holds a single key. A key restricted to another
// use or algorithm is not selected.
func lookup(set *jose.JSONWebKeySet, h jose.Header) (any, bool) {
	var candidates []jose.JSONWebKey
	if h.KeyID == "" {
		if len(set.Keys) == 1 {
			candidates = set.Keys
		}
	} else {
		candidates = set.Key(h.KeyID)
	}
	for _, k := range candidates {
		if !k.Valid() || !k.IsPublic() {
			continue
		}
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		if k.Algorithm != "" && k.Algorithm != h.Algorithm {
			continue
		}
		return k.Key, true
	}
	return nil, false
}
