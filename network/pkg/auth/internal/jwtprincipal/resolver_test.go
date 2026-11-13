package jwtprincipal

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	interceptors "github.com/o3co/protobuf.interceptors"
)

const (
	testIssuer   = "https://issuer.example"
	testAudience = "provin-network"
)

var testSecret = []byte("0123456789abcdef0123456789abcdef")

func hsToken(t *testing.T, secret []byte, claims jwt.Claims) string {
	t.Helper()
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: secret}, (&jose.SignerOptions{}).WithType("at+jwt"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := jwt.Signed(sig).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func validClaims(now time.Time) jwt.Claims {
	return jwt.Claims{
		Issuer:   testIssuer,
		Audience: jwt.Audience{testAudience},
		Subject:  "did:dplaax:alice",
		Expiry:   jwt.NewNumericDate(now.Add(time.Hour)),
		IssuedAt: jwt.NewNumericDate(now),
	}
}

func newHS(t *testing.T, now time.Time) Resolver {
	t.Helper()
	r, err := newResolver(Config{Issuer: testIssuer, Audience: testAudience, Secret: string(testSecret)}, nil, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestHS256_ReturnsSubject(t *testing.T) {
	now := time.Now()
	got, err := newHS(t, now).Principal(context.Background(), hsToken(t, testSecret, validClaims(now)))
	if err != nil || got != "did:dplaax:alice" {
		t.Fatalf("Principal = %q, %v", got, err)
	}
}

func TestHS256_Rejects(t *testing.T) {
	now := time.Now()
	mut := func(f func(*jwt.Claims)) string {
		c := validClaims(now)
		f(&c)
		return hsToken(t, testSecret, c)
	}
	cases := map[string]string{
		"wrong secret":   hsToken(t, []byte("ffffffffffffffffffffffffffffffff"), validClaims(now)),
		"expired":        mut(func(c *jwt.Claims) { c.Expiry = jwt.NewNumericDate(now.Add(-time.Hour)) }),
		"no exp":         mut(func(c *jwt.Claims) { c.Expiry = nil }),
		"no iat":         mut(func(c *jwt.Claims) { c.IssuedAt = nil }),
		"iat ahead":      mut(func(c *jwt.Claims) { c.IssuedAt = jwt.NewNumericDate(now.Add(time.Hour)) }),
		"not yet valid":  mut(func(c *jwt.Claims) { c.NotBefore = jwt.NewNumericDate(now.Add(time.Hour)) }),
		"wrong issuer":   mut(func(c *jwt.Claims) { c.Issuer = "https://evil.example" }),
		"wrong audience": mut(func(c *jwt.Claims) { c.Audience = jwt.Audience{"other"} }),
		"no audience":    mut(func(c *jwt.Claims) { c.Audience = nil }),
		"empty subject":  mut(func(c *jwt.Claims) { c.Subject = "" }),
		"garbage":        "not-a-jwt",
		"empty":          "",
		"alg none":       base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"x"}`)) + ".",
	}
	r := newHS(t, now)
	for name, tok := range cases {
		if got, err := r.Principal(context.Background(), tok); err == nil {
			t.Errorf("%s: accepted, principal %q", name, got)
		}
	}
}

// A token is accepted only as an access token: its typ header is at+jwt, in
// either spelling RFC 9068 gives (at+jwt or application/at+jwt) and in any
// case, a media type being case-insensitive. Any other typ, or none, is
// refused.
func TestPrincipal_RequiresTheAccessTokenType(t *testing.T) {
	now := time.Now()
	r := newHS(t, now)
	signed := func(opts *jose.SignerOptions) string {
		t.Helper()
		sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: testSecret}, opts)
		if err != nil {
			t.Fatal(err)
		}
		s, err := jwt.Signed(sig).Claims(validClaims(now)).Serialize()
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	for _, typ := range []string{"at+jwt", "application/at+jwt", "AT+JWT", "Application/At+Jwt"} {
		if _, err := r.Principal(context.Background(), signed((&jose.SignerOptions{}).WithType(jose.ContentType(typ)))); err != nil {
			t.Errorf("typ %q: refused: %v", typ, err)
		}
	}
	refused := map[string]*jose.SignerOptions{
		"no typ":              {},
		"typ JWT":             (&jose.SignerOptions{}).WithType("JWT"),
		"typ jwt":             (&jose.SignerOptions{}).WithType("jwt"),
		"typ application/jwt": (&jose.SignerOptions{}).WithType("application/jwt"),
		"typ empty":           (&jose.SignerOptions{}).WithType(""),
		"typ with parameters": (&jose.SignerOptions{}).WithType("at+jwt; v=1"),
		"typ another +jwt":    (&jose.SignerOptions{}).WithType("dpop+jwt"),
		"typ not ASCII":       (&jose.SignerOptions{}).WithType("appl\u0130cation/at+jwt"),
		"typ not a string":    (&jose.SignerOptions{}).WithHeader(jose.HeaderType, 1),
	}
	for name, opts := range refused {
		if got, err := r.Principal(context.Background(), signed(opts)); err == nil {
			t.Errorf("%s: accepted, principal %q", name, got)
		}
	}
}

func TestHS256_Leeway(t *testing.T) {
	now := time.Now()
	r := newHS(t, now)
	c := validClaims(now)
	c.Expiry = jwt.NewNumericDate(now.Add(-leeway / 2))
	if _, err := r.Principal(context.Background(), hsToken(t, testSecret, c)); err != nil {
		t.Errorf("token expired within leeway rejected: %v", err)
	}
	c.Expiry = jwt.NewNumericDate(now.Add(-2 * leeway))
	if _, err := r.Principal(context.Background(), hsToken(t, testSecret, c)); err == nil {
		t.Error("token expired beyond leeway accepted")
	}
	c = validClaims(now)
	c.IssuedAt = jwt.NewNumericDate(now.Add(leeway / 2))
	if _, err := r.Principal(context.Background(), hsToken(t, testSecret, c)); err != nil {
		t.Errorf("token issued ahead within leeway rejected: %v", err)
	}
}

func TestHS256_RejectsAsymmetricAlgorithm(t *testing.T) {
	now := time.Now()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sig, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, nil)
	tok, _ := jwt.Signed(sig).Claims(validClaims(now)).Serialize()
	if _, err := newHS(t, now).Principal(context.Background(), tok); err == nil {
		t.Error("ES256 token accepted by an HS256-only resolver")
	}
}

func TestSecretEncodings(t *testing.T) {
	raw := testSecret
	for enc, secret := range map[string]string{
		"":       string(raw),
		"utf8":   string(raw),
		"hex":    hex.EncodeToString(raw),
		"base64": base64.StdEncoding.EncodeToString(raw),
	} {
		now := time.Now()
		r, err := newResolver(Config{Issuer: testIssuer, Audience: testAudience, Secret: secret, SecretEncoding: enc}, nil, func() time.Time { return now })
		if err != nil {
			t.Fatalf("%q: %v", enc, err)
		}
		if _, err := r.Principal(context.Background(), hsToken(t, raw, validClaims(now))); err != nil {
			t.Errorf("%q: %v", enc, err)
		}
	}
}

func TestNew_RejectsBadConfig(t *testing.T) {
	ok := Config{Issuer: testIssuer, Audience: testAudience, Secret: string(testSecret)}
	with := func(f func(*Config)) Config { c := ok; f(&c); return c }
	cases := map[string]Config{
		"no issuer":          with(func(c *Config) { c.Issuer = "" }),
		"no audience":        with(func(c *Config) { c.Audience = "" }),
		"no key":             with(func(c *Config) { c.Secret = "" }),
		"both keys":          with(func(c *Config) { c.JWKSURL = "https://issuer.example/jwks" }),
		"short secret":       with(func(c *Config) { c.Secret = "short" }),
		"short decoded hex":  with(func(c *Config) { c.Secret = strings.Repeat("ab", 16); c.SecretEncoding = "hex" }),
		"bad hex":            with(func(c *Config) { c.Secret = strings.Repeat("zz", 32); c.SecretEncoding = "hex" }),
		"bad base64":         with(func(c *Config) { c.Secret = "!!!"; c.SecretEncoding = "base64" }),
		"unknown encoding":   with(func(c *Config) { c.SecretEncoding = "rot13" }),
		"http jwks":          with(func(c *Config) { c.Secret = ""; c.JWKSURL = "http://issuer.example/jwks" }),
		"jwks no host":       with(func(c *Config) { c.Secret = ""; c.JWKSURL = "https:///jwks" }),
		"jwks userinfo":      with(func(c *Config) { c.Secret = ""; c.JWKSURL = "https://u:p@issuer.example/jwks" }),
		"encoding with jwks": with(func(c *Config) { c.Secret = ""; c.JWKSURL = "https://issuer.example/jwks"; c.SecretEncoding = "hex" }),
	}
	for name, cfg := range cases {
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := New(ok); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
	if _, err := New(with(func(c *Config) { c.Secret = ""; c.JWKSURL = "https://issuer.example/jwks" })); err != nil {
		t.Errorf("valid jwks config rejected: %v", err)
	}
}

type jwksServer struct {
	*httptest.Server
	hits   atomic.Int32
	keys   atomic.Value // []jose.JSONWebKey
	fail   atomic.Bool
	status atomic.Int32                  // when set, every path answers with this status
	raw    atomic.Pointer[string]        // when set, /jwks answers with this body
	gate   atomic.Pointer[chan struct{}] // when set, /jwks blocks until it is closed
}

func newJWKSServer(t *testing.T, keys ...jose.JSONWebKey) *jwksServer {
	t.Helper()
	s := &jwksServer{}
	s.keys.Store(keys)
	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		if g := s.gate.Load(); g != nil {
			select {
			case <-*g:
			case <-r.Context().Done():
			}
		}
		if s.fail.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		if code := s.status.Load(); code != 0 {
			http.Error(w, http.StatusText(int(code)), int(code))
			return
		}
		switch r.URL.Path {
		case "/jwks":
			if raw := s.raw.Load(); raw != nil {
				_, _ = w.Write([]byte(*raw))
				return
			}
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: s.keys.Load().([]jose.JSONWebKey)})
		case "/redirect":
			http.Redirect(w, r, "/jwks", http.StatusFound)
		case "/huge":
			_, _ = w.Write([]byte(`{"keys":[],"pad":"` + strings.Repeat("a", maxJWKSBytes) + `"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func ecKey(t *testing.T, kid string) (*ecdsa.PrivateKey, jose.JSONWebKey) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k, jose.JSONWebKey{Key: &k.PublicKey, KeyID: kid, Algorithm: "ES256", Use: "sig"}
}

func esToken(t *testing.T, k *ecdsa.PrivateKey, kid string, c jwt.Claims) string {
	t.Helper()
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: k}, (&jose.SignerOptions{}).WithType("at+jwt").WithHeader("kid", kid))
	if err != nil {
		t.Fatal(err)
	}
	s, err := jwt.Signed(sig).Claims(c).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type clock struct{ now atomic.Value }

func (c *clock) Now() time.Time          { return c.now.Load().(time.Time) }
func (c *clock) Advance(d time.Duration) { c.now.Store(c.Now().Add(d)) }

func newJWKSResolver(t *testing.T, srv *jwksServer, path string, clk *clock) Resolver {
	t.Helper()
	r, err := newResolver(Config{Issuer: testIssuer, Audience: testAudience, JWKSURL: srv.URL + path}, srv.Client(), clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func newClock() *clock {
	c := &clock{}
	c.now.Store(time.Now())
	return c
}

// A token that is not an access token is refused before its key is looked
// up: it never makes the node fetch the issuer's key set.
func TestJWKS_ATokenOfAnotherTypeFetchesNoKeys(t *testing.T) {
	k, jwk := ecKey(t, "k1")
	srv := newJWKSServer(t, jwk)
	clk := newClock()
	r := newJWKSResolver(t, srv, "/jwks", clk)
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: k}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jwt.Signed(sig).Claims(validClaims(clk.Now())).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := r.Principal(context.Background(), tok); err == nil {
		t.Fatalf("accepted, principal %q", got)
	}
	if n := srv.hits.Load(); n != 0 {
		t.Errorf("JWKS fetched %d times for a token of another type, want 0", n)
	}
}

func TestJWKS_VerifiesAndCaches(t *testing.T) {
	k, jwk := ecKey(t, "k1")
	srv := newJWKSServer(t, jwk)
	clk := newClock()
	r := newJWKSResolver(t, srv, "/jwks", clk)
	tok := esToken(t, k, "k1", validClaims(clk.Now()))
	for i := 0; i < 3; i++ {
		if got, err := r.Principal(context.Background(), tok); err != nil || got != "did:dplaax:alice" {
			t.Fatalf("Principal = %q, %v", got, err)
		}
	}
	if srv.hits.Load() != 1 {
		t.Errorf("JWKS fetched %d times, want 1 (cached)", srv.hits.Load())
	}
	clk.Advance(jwksTTL + time.Second)
	if _, err := r.Principal(context.Background(), tok); err != nil {
		t.Fatal(err)
	}
	if srv.hits.Load() != 2 {
		t.Errorf("JWKS fetched %d times after TTL, want 2", srv.hits.Load())
	}
}

func TestJWKS_UnknownKidRefetchIsRateLimited(t *testing.T) {
	k1, jwk1 := ecKey(t, "k1")
	k2, jwk2 := ecKey(t, "k2")
	srv := newJWKSServer(t, jwk1)
	clk := newClock()
	r := newJWKSResolver(t, srv, "/jwks", clk)
	if _, err := r.Principal(context.Background(), esToken(t, k1, "k1", validClaims(clk.Now()))); err != nil {
		t.Fatal(err)
	}
	tok2 := esToken(t, k2, "k2", validClaims(clk.Now()))
	srv.keys.Store([]jose.JSONWebKey{jwk1, jwk2})

	// Within the minimum refetch interval an unknown kid does not trigger a fetch.
	if _, err := r.Principal(context.Background(), tok2); err == nil {
		t.Error("unknown kid accepted before the refetch interval elapsed")
	}
	if srv.hits.Load() != 1 {
		t.Errorf("hits = %d, want 1 (refetch rate-limited)", srv.hits.Load())
	}
	clk.Advance(jwksMinRefetch + time.Second)
	if _, err := r.Principal(context.Background(), tok2); err != nil {
		t.Errorf("rotated key not picked up after the refetch interval: %v", err)
	}
	if srv.hits.Load() != 2 {
		t.Errorf("hits = %d, want 2", srv.hits.Load())
	}
}

func TestJWKS_RejectsWrongKeyAndHMACConfusion(t *testing.T) {
	_, jwk := ecKey(t, "k1")
	other, _ := ecKey(t, "k1")
	srv := newJWKSServer(t, jwk)
	clk := newClock()
	r := newJWKSResolver(t, srv, "/jwks", clk)
	if _, err := r.Principal(context.Background(), esToken(t, other, "k1", validClaims(clk.Now()))); err == nil {
		t.Error("token signed by another key accepted")
	}
	if _, err := r.Principal(context.Background(), hsToken(t, testSecret, validClaims(clk.Now()))); err == nil {
		t.Error("HS256 token accepted by a JWKS resolver")
	}
}

func TestJWKS_FetchFailuresFailClosed(t *testing.T) {
	k, jwk := ecKey(t, "k1")
	srv := newJWKSServer(t, jwk)
	for _, path := range []string{"/redirect", "/huge", "/missing"} {
		clk := newClock()
		r := newJWKSResolver(t, srv, path, clk)
		if _, err := r.Principal(context.Background(), esToken(t, k, "k1", validClaims(clk.Now()))); err == nil {
			t.Errorf("%s: token accepted although the JWKS could not be fetched", path)
		}
	}
}

func TestNew_ErrorsDoNotQuoteTheSecret(t *testing.T) {
	secret := strings.Repeat("zq", 32)
	_, err := New(Config{Issuer: testIssuer, Audience: testAudience, Secret: secret, SecretEncoding: "hex"})
	if err == nil || strings.Contains(err.Error(), "zq") {
		t.Errorf("err = %v, want an error that does not quote the secret", err)
	}
}

func TestJWKS_CancelledCallerDoesNotPoisonCacheOrLimiter(t *testing.T) {
	k, jwk := ecKey(t, "k1")
	srv := newJWKSServer(t, jwk)
	clk := newClock()
	r := newJWKSResolver(t, srv, "/jwks", clk)
	tok := esToken(t, k, "k1", validClaims(clk.Now()))

	gate := make(chan struct{})
	srv.gate.Store(&gate)
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { _, err := r.Principal(ctx, tok); errc <- err }()
	for srv.hits.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-errc; err == nil {
		t.Fatal("cancelled caller got a principal")
	}
	close(gate)

	// The fetch ran on its own: a later caller is served without a second fetch
	// and is not held back by the refetch limiter.
	var err error
	for i := 0; i < 1000; i++ {
		if _, err = r.Principal(context.Background(), tok); err == nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if err != nil {
		t.Fatalf("later caller failed: %v", err)
	}
	if srv.hits.Load() != 1 {
		t.Errorf("hits = %d, want 1", srv.hits.Load())
	}
}

func TestJWKS_ConcurrentUnknownKidFetchesOnce(t *testing.T) {
	k, jwk := ecKey(t, "k1")
	srv := newJWKSServer(t, jwk)
	clk := newClock()
	r := newJWKSResolver(t, srv, "/jwks", clk)
	tok := esToken(t, k, "k1", validClaims(clk.Now()))
	gate := make(chan struct{})
	srv.gate.Store(&gate)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := r.Principal(context.Background(), tok); err != nil {
				t.Error(err)
			}
		}()
	}
	for srv.hits.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	close(gate)
	wg.Wait()
	if srv.hits.Load() != 1 {
		t.Errorf("hits = %d, want 1", srv.hits.Load())
	}
}

func TestJWKS_GraceKeepsKnownKidsWhileRefetchFails(t *testing.T) {
	k1, jwk1 := ecKey(t, "k1")
	k2, jwk2 := ecKey(t, "k2")
	srv := newJWKSServer(t, jwk1)
	clk := newClock()
	r := newJWKSResolver(t, srv, "/jwks", clk)
	ctx := context.Background()
	if _, err := r.Principal(ctx, esToken(t, k1, "k1", validClaims(clk.Now()))); err != nil {
		t.Fatal(err)
	}
	srv.fail.Store(true)
	clk.Advance(jwksTTL + time.Second)
	claims := validClaims(clk.Now())
	tok1, tok2 := esToken(t, k1, "k1", claims), esToken(t, k2, "k2", claims)

	// Expired set, refetch failing: a known kid still verifies; an unknown one
	// does not, and since the set could not be refetched it is unavailable, not
	// refused.
	if _, err := r.Principal(ctx, tok1); err != nil {
		t.Errorf("known kid refused during grace: %v", err)
	}
	if _, err := r.Principal(ctx, tok2); !wrapsUnavailable(err) {
		t.Errorf("unknown kid from a stale set: err = %v, want unavailable", err)
	}
	// The same holds while the refetch is rate-limited.
	if _, err := r.Principal(ctx, tok1); err != nil {
		t.Errorf("known kid refused while rate-limited: %v", err)
	}
	if _, err := r.Principal(ctx, tok2); !wrapsUnavailable(err) {
		t.Errorf("unknown kid from a stale set while rate-limited: err = %v, want unavailable", err)
	}
	// Past the grace bound nothing verifies, whether a refetch was tried or
	// rate-limited, and the key set is unavailable.
	clk.Advance(jwksGrace)
	claims = validClaims(clk.Now())
	for _, what := range []string{"refetch failing", "refetch rate-limited"} {
		if _, err := r.Principal(ctx, esToken(t, k1, "k1", claims)); !wrapsUnavailable(err) {
			t.Errorf("stale set beyond the grace period, %s: err = %v, want unavailable", what, err)
		}
		if srv.hits.Load() != 3 {
			t.Errorf("%s: hits = %d, want 3", what, srv.hits.Load())
		}
	}
	// Recovery: a successful fetch restores service.
	srv.fail.Store(false)
	srv.keys.Store([]jose.JSONWebKey{jwk1, jwk2})
	clk.Advance(jwksMinRefetch + time.Second)
	claims = validClaims(clk.Now())
	if _, err := r.Principal(ctx, esToken(t, k2, "k2", claims)); err != nil {
		t.Errorf("not recovered after the endpoint came back: %v", err)
	}
}

func TestHS256_NotBeforeWithinLeewayAndMultiAudience(t *testing.T) {
	now := time.Now()
	r := newHS(t, now)
	c := validClaims(now)
	c.NotBefore = jwt.NewNumericDate(now.Add(leeway / 2))
	c.Audience = jwt.Audience{"other", testAudience}
	if _, err := r.Principal(context.Background(), hsToken(t, testSecret, c)); err != nil {
		t.Errorf("nbf within leeway / multi-valued aud rejected: %v", err)
	}
	c.NotBefore = jwt.NewNumericDate(now.Add(2 * leeway))
	if _, err := r.Principal(context.Background(), hsToken(t, testSecret, c)); err == nil {
		t.Error("nbf beyond leeway accepted")
	}
}

func TestJWKS_SkipsKeysItCannotParse(t *testing.T) {
	k, jwk := ecKey(t, "k1")
	good, _ := json.Marshal(jwk)
	body := `{"keys":[{"kty":"OKP","crv":"X25519","kid":"x","x":"` + strings.Repeat("A", 43) + `"},` +
		`{"kty":"EC","crv":"secp256k1","kid":"y","x":"AA","y":"AA"},` + string(good) + `]}`
	srv := newJWKSServer(t, jwk)
	srv.raw.Store(&body)
	clk := newClock()
	r := newJWKSResolver(t, srv, "/jwks", clk)
	if _, err := r.Principal(context.Background(), esToken(t, k, "k1", validClaims(clk.Now()))); err != nil {
		t.Errorf("a set with unparsable members must still yield its good key: %v", err)
	}
}

func TestJWKS_SetWithoutKeysMemberIsAFailedFetch(t *testing.T) {
	for _, body := range []string{`{}`, `null`, `{"keys":null}`} {
		k, jwk := ecKey(t, "k1")
		srv := newJWKSServer(t, jwk)
		clk := newClock()
		r := newJWKSResolver(t, srv, "/jwks", clk)
		ctx := context.Background()
		if _, err := r.Principal(ctx, esToken(t, k, "k1", validClaims(clk.Now()))); err != nil {
			t.Fatal(err)
		}
		srv.raw.Store(&body)
		clk.Advance(jwksTTL + time.Second)
		tok := esToken(t, k, "k1", validClaims(clk.Now()))
		// The previous set is kept (grace applies), not replaced by an empty one.
		if _, err := r.Principal(ctx, tok); err != nil {
			t.Errorf("%s: previous set lost: %v", body, err)
		}
		if _, err := r.Principal(ctx, tok); err != nil {
			t.Errorf("%s: %v", body, err)
		}
		// Counted as an attempt: the second call did not refetch.
		if srv.hits.Load() != 2 {
			t.Errorf("%s: hits = %d, want 2 (failed attempt rate-limits the next)", body, srv.hits.Load())
		}
	}
}

// wrapsUnavailable reports whether err says the key set could not be had, rather
// than that the token was refused.
func wrapsUnavailable(err error) bool { return errors.Is(err, interceptors.ErrBackendUnavailable) }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// A fetch that yields no key set leaves the token unjudged, whatever the
// reason: the endpoint unreachable or past the fetch's own timeout, an answer
// with any status but 200, or a body that is not a key set. The error wraps
// interceptors.ErrBackendUnavailable, and the fetch's own timeout does not read
// as the caller's deadline.
func TestJWKS_AFetchThatYieldsNoKeySetIsUnavailable(t *testing.T) {
	type setup func(t *testing.T, srv *jwksServer, clk *clock) Resolver
	at := func(path string) setup {
		return func(t *testing.T, srv *jwksServer, clk *clock) Resolver { return newJWKSResolver(t, srv, path, clk) }
	}
	body := func(b string) setup {
		return func(t *testing.T, srv *jwksServer, clk *clock) Resolver {
			srv.raw.Store(&b)
			return newJWKSResolver(t, srv, "/jwks", clk)
		}
	}
	cases := map[string]setup{
		"a redirect":            at("/redirect"),
		"larger than the bound": at("/huge"),
		"not JSON":              body(`not json`),
		"no keys member":        body(`{}`),
		"keys not an array":     body(`{"keys":{}}`),
		"unreachable": func(t *testing.T, srv *jwksServer, clk *clock) Resolver {
			gone := httptest.NewTLSServer(http.NotFoundHandler())
			gone.Close()
			r, err := newResolver(Config{Issuer: testIssuer, Audience: testAudience, JWKSURL: gone.URL + "/jwks"}, srv.Client(), clk.Now)
			if err != nil {
				t.Fatal(err)
			}
			return r
		},
		"past the fetch's own timeout": func(t *testing.T, srv *jwksServer, clk *clock) Resolver {
			// What net/http reports when the fetch's deadline passes.
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return nil, context.DeadlineExceeded
			})}
			r, err := newResolver(Config{Issuer: testIssuer, Audience: testAudience, JWKSURL: srv.URL + "/jwks"}, client, clk.Now)
			if err != nil {
				t.Fatal(err)
			}
			return r
		},
	}
	for _, code := range []int{
		http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound,
		http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout,
	} {
		cases[fmt.Sprintf("status %d", code)] = func(t *testing.T, srv *jwksServer, clk *clock) Resolver {
			srv.status.Store(int32(code))
			return newJWKSResolver(t, srv, "/jwks", clk)
		}
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			k, jwk := ecKey(t, "k1")
			srv := newJWKSServer(t, jwk)
			clk := newClock()
			r := mk(t, srv, clk)
			tok := esToken(t, k, "k1", validClaims(clk.Now()))
			// The failed fetch, then the same while the next fetch is rate-limited.
			for _, what := range []string{"fetch failed", "refetch rate-limited"} {
				_, err := r.Principal(context.Background(), tok)
				if !wrapsUnavailable(err) {
					t.Errorf("%s: err = %v, want one wrapping ErrBackendUnavailable", what, err)
				}
				if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
					t.Errorf("%s: err = %v reads as the caller's context ending", what, err)
				}
			}
		})
	}
}

// A caller whose context ends while it waits for a fetch has not had its token
// judged: the error wraps interceptors.ErrBackendUnavailable and the context's
// error, so what the caller is told is that its own context ended. The fetch
// goes on for the others (TestJWKS_CancelledCallerDoesNotPoisonCacheOrLimiter).
func TestJWKS_CallerContextEndingWhileWaitingIsUnavailable(t *testing.T) {
	for name, c := range map[string]struct {
		ctx    func() (context.Context, context.CancelFunc)
		cancel bool // cancel once the fetch has reached the endpoint
		want   error
	}{
		"canceled": {func() (context.Context, context.CancelFunc) { return context.WithCancel(context.Background()) }, true, context.Canceled},
		"past its deadline": {func() (context.Context, context.CancelFunc) {
			return context.WithTimeout(context.Background(), 50*time.Millisecond)
		}, false, context.DeadlineExceeded},
	} {
		t.Run(name, func(t *testing.T) {
			k, jwk := ecKey(t, "k1")
			srv := newJWKSServer(t, jwk)
			gate := make(chan struct{})
			srv.gate.Store(&gate)
			defer close(gate)
			clk := newClock()
			r := newJWKSResolver(t, srv, "/jwks", clk)
			tok := esToken(t, k, "k1", validClaims(clk.Now()))
			ctx, cancel := c.ctx()
			defer cancel()
			errc := make(chan error, 1)
			go func() { _, err := r.Principal(ctx, tok); errc <- err }()
			if c.cancel {
				for srv.hits.Load() == 0 {
					time.Sleep(time.Millisecond)
				}
				cancel()
			}
			if err := <-errc; !wrapsUnavailable(err) || !errors.Is(err, c.want) {
				t.Errorf("err = %v, want one wrapping ErrBackendUnavailable and %v", err, c.want)
			}
		})
	}
}

// An unknown kid is a refusal of the token only when the latest fetch
// succeeded, so the set in hand is the issuer's current one. After a failed
// fetch it may name a key the node has not been able to see, so it is
// unavailable, also while the next fetch waits out jwksMinRefetch. A key id
// the set holds still verifies.
func TestJWKS_UnknownKidIsUnavailableOnlyAfterAFailedFetch(t *testing.T) {
	k1, jwk1 := ecKey(t, "k1")
	k2, _ := ecKey(t, "k2")
	srv := newJWKSServer(t, jwk1)
	clk := newClock()
	r := newJWKSResolver(t, srv, "/jwks", clk)
	ctx := context.Background()
	principal := func(k *ecdsa.PrivateKey, kid string) error {
		_, err := r.Principal(ctx, esToken(t, k, kid, validClaims(clk.Now())))
		return err
	}
	refused := func(step string, err error) {
		t.Helper()
		if err == nil || wrapsUnavailable(err) {
			t.Errorf("%s: err = %v, want a refusal of the token", step, err)
		}
	}
	isUnavailable := func(step string, err error) {
		t.Helper()
		if !wrapsUnavailable(err) {
			t.Errorf("%s: err = %v, want unavailable", step, err)
		}
	}
	hits := func(step string, want int32) {
		t.Helper()
		if got := srv.hits.Load(); got != want {
			t.Errorf("%s: hits = %d, want %d", step, got, want)
		}
	}

	if err := principal(k1, "k1"); err != nil {
		t.Fatal(err)
	}
	refused("unknown kid, rate-limited after a successful fetch", principal(k2, "k2"))
	hits("after a successful fetch", 1)

	clk.Advance(jwksMinRefetch + time.Second)
	srv.status.Store(http.StatusNotFound)
	isUnavailable("unknown kid, the fetch failed", principal(k2, "k2"))
	isUnavailable("unknown kid, rate-limited after a failed fetch", principal(k2, "k2"))
	if err := principal(k1, "k1"); err != nil {
		t.Errorf("known kid refused after a failed fetch: %v", err)
	}
	hits("after a failed fetch", 2)

	clk.Advance(jwksMinRefetch + time.Second)
	srv.status.Store(0)
	refused("unknown kid, the fetch succeeded", principal(k2, "k2"))
	refused("unknown kid, rate-limited after the fetch succeeded again", principal(k2, "k2"))
	hits("after the fetch succeeded again", 3)
}

// A fetch that succeeds replaces the set, also with one that holds no key the
// node can use: the issuer has withdrawn its keys, and no grace keeps the old
// ones. A token under a key id of the old set is then refused, not
// unavailable.
func TestJWKS_ASuccessfulFetchOfNoUsableKeyReplacesTheSet(t *testing.T) {
	for name, body := range map[string]string{
		"no keys":       `{"keys":[]}`,
		"no usable key": `{"keys":[{"kty":"EC","crv":"secp256k1","kid":"k1","x":"AA","y":"AA"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			k1, jwk1 := ecKey(t, "k1")
			srv := newJWKSServer(t, jwk1)
			clk := newClock()
			r := newJWKSResolver(t, srv, "/jwks", clk)
			ctx := context.Background()
			if _, err := r.Principal(ctx, esToken(t, k1, "k1", validClaims(clk.Now()))); err != nil {
				t.Fatal(err)
			}
			srv.raw.Store(&body)
			clk.Advance(jwksTTL + time.Second)
			for _, what := range []string{"the fetch", "rate-limited after it"} {
				_, err := r.Principal(ctx, esToken(t, k1, "k1", validClaims(clk.Now())))
				if err == nil || wrapsUnavailable(err) {
					t.Errorf("%s: err = %v, want a refusal of the token", what, err)
				}
			}
			if srv.hits.Load() != 2 {
				t.Errorf("hits = %d, want 2", srv.hits.Load())
			}
		})
	}
}

func TestLookup_Filters(t *testing.T) {
	k, pub := ecKey(t, "k1")
	other, otherPub := ecKey(t, "k2")
	_ = other
	priv := jose.JSONWebKey{Key: k, KeyID: "p", Algorithm: "ES256", Use: "sig"}
	hdr := func(kid, alg string) jose.Header { return jose.Header{KeyID: kid, Algorithm: alg} }
	with := func(f func(*jose.JSONWebKey)) jose.JSONWebKey { j := pub; f(&j); return j }

	cases := map[string]struct {
		keys []jose.JSONWebKey
		h    jose.Header
		ok   bool
	}{
		"match":                 {[]jose.JSONWebKey{pub}, hdr("k1", "ES256"), true},
		"alg mismatch":          {[]jose.JSONWebKey{pub}, hdr("k1", "ES384"), false},
		"use enc":               {[]jose.JSONWebKey{with(func(j *jose.JSONWebKey) { j.Use = "enc" })}, hdr("k1", "ES256"), false},
		"no use no alg":         {[]jose.JSONWebKey{with(func(j *jose.JSONWebKey) { j.Use = ""; j.Algorithm = "" })}, hdr("k1", "ES256"), true},
		"private key ignored":   {[]jose.JSONWebKey{priv}, hdr("p", "ES256"), false},
		"kid-less one key":      {[]jose.JSONWebKey{pub}, hdr("", "ES256"), true},
		"kid-less several keys": {[]jose.JSONWebKey{pub, otherPub}, hdr("", "ES256"), false},
		"unknown kid":           {[]jose.JSONWebKey{pub}, hdr("zz", "ES256"), false},
	}
	for name, c := range cases {
		if _, ok := lookup(&jose.JSONWebKeySet{Keys: c.keys}, c.h); ok != c.ok {
			t.Errorf("%s: ok = %v, want %v", name, ok, c.ok)
		}
	}
}
