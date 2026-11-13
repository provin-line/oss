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
	interceptors "github.com/o3co/protobuf.interceptors"
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
	// lastErr is why the latest completed fetch failed, or nil if it succeeded
	// or no fetch has completed.
	lastErr error
	// inflight is the running fetch every waiting caller shares; it is closed
	// when the fetch completes.
	inflight chan struct{}
}

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
// completed. If the set is expired and the latest fetch failed, whether this
// call waited for it or found the next one rate-limited, the set still verifies
// tokens for the key ids it holds until jwksGrace after its expiry.
//
// A token for which no key of the set the latest fetch returned fits the header
// (by key id, algorithm and use; see lookup) is refused. When the latest fetch
// failed, the token is not judged instead: no set at all, a set past its grace,
// or a set with no key that fits is an error wrapping
// interceptors.ErrBackendUnavailable. A fetch fails for whatever reason it does
// not yield a key set, so one that retrying does not fix (a 404, a certificate
// the node does not trust) is reported as unavailable too: the Cedar endpoint
// lets a principal resolver only refuse a token or report that it cannot
// answer. A caller whose context ends while it waits for a fetch has not had its
// token judged either: that error wraps interceptors.ErrBackendUnavailable and
// the context's error, so the caller is told its own context ended.
func (c *jwksCache) key(ctx context.Context, h jose.Header) (any, error) {
	c.mu.Lock()
	now := c.now()
	if c.set != nil && now.Sub(c.fetchedAt) < jwksTTL {
		if k, ok := lookup(c.set, h); ok {
			c.mu.Unlock()
			return k, nil
		}
	}
	done := c.inflight
	if done == nil && (c.lastAttempt.IsZero() || now.Sub(c.lastAttempt) >= jwksMinRefetch) {
		done = make(chan struct{})
		c.inflight = done
		c.lastAttempt = now
		go c.run(done)
	}
	c.mu.Unlock()

	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
			return nil, fmt.Errorf("%w: waiting for the key set: %w", interceptors.ErrBackendUnavailable, ctx.Err())
		}
	}

	c.mu.Lock()
	set, age, fetchErr := c.set, c.now().Sub(c.fetchedAt), c.lastErr
	c.mu.Unlock()
	switch {
	case set == nil:
		return nil, unavailable("no key set available", fetchErr)
	case age < jwksTTL:
	case fetchErr != nil && age < jwksTTL+jwksGrace:
	default:
		return nil, unavailable("key set expired", fetchErr)
	}
	if k, ok := lookup(set, h); ok {
		return k, nil
	}
	if fetchErr != nil {
		return nil, unavailable(fmt.Sprintf("no verification key for kid %q", h.KeyID), fetchErr)
	}
	return nil, fmt.Errorf("no verification key for kid %q", h.KeyID)
}

// unavailable reports that the token could not be judged: what is missing, and
// why the latest fetch failed. It wraps interceptors.ErrBackendUnavailable but
// not the fetch's error, so the fetch's own timeout does not read as the
// caller's context ending.
func unavailable(what string, fetchErr error) error {
	return fmt.Errorf("%w: %s; the latest key set fetch failed: %v", interceptors.ErrBackendUnavailable, what, fetchErr)
}

func (c *jwksCache) run(done chan struct{}) {
	ctx, cancel := context.WithTimeout(context.Background(), jwksTimeout)
	defer cancel()
	set, err := c.fetch(ctx)
	c.mu.Lock()
	if err == nil {
		c.set, c.fetchedAt = set, c.now()
	}
	c.lastErr = err
	c.inflight = nil
	c.mu.Unlock()
	close(done)
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
	// The key set is the issuer's own document, not a protocol payload: no hashed
	// or signed canonical form is derived from it, and a duplicate member can only
	// change which of the issuer's own keys is read.
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	// decoder-hygiene-exempt: the issuer's own key set, see above.
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	if doc.Keys == nil {
		return nil, errors.New("decode: no keys member")
	}
	// A member this library cannot parse (an unsupported curve or key type) is
	// skipped so it cannot take the issuer's other keys down with it (RFC 7517 §5).
	var set jose.JSONWebKeySet
	for _, raw := range doc.Keys {
		var k jose.JSONWebKey
		// decoder-hygiene-exempt: one member of the key set decoded above.
		if err := json.Unmarshal(raw, &k); err != nil {
			continue
		}
		set.Keys = append(set.Keys, k)
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
