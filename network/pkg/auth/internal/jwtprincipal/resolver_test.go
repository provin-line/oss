package jwtprincipal

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const (
	testIssuer   = "https://issuer.example"
	testAudience = "provin-network"
)

var testSecret = []byte("0123456789abcdef0123456789abcdef")

func hsToken(t *testing.T, secret []byte, claims jwt.Claims) string {
	t.Helper()
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: secret}, (&jose.SignerOptions{}).WithType("JWT"))
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
	hits atomic.Int32
	keys atomic.Value // []jose.JSONWebKey
}

func newJWKSServer(t *testing.T, keys ...jose.JSONWebKey) *jwksServer {
	t.Helper()
	s := &jwksServer{}
	s.keys.Store(keys)
	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		switch r.URL.Path {
		case "/jwks":
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
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: k}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid))
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
