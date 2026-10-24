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

func (c *jwksCache) key(ctx context.Context, h jose.Header) (any, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	fresh := c.set != nil && now.Sub(c.fetchedAt) < jwksTTL
	if fresh {
		if k, ok := lookup(c.set, h); ok {
			return k, nil
		}
	}
	// Either the cached set expired or it lacks this key id.
	if !c.lastAttempt.IsZero() && now.Sub(c.lastAttempt) < jwksMinRefetch {
		return nil, errors.New("no verification key for token (key set refetch rate-limited)")
	}
	c.lastAttempt = now
	set, err := c.fetch(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch jwks: %w", err)
	}
	c.set, c.fetchedAt = set, now
	if k, ok := lookup(set, h); ok {
		return k, nil
	}
	return nil, fmt.Errorf("no verification key for kid %q", h.KeyID)
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
