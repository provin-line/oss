package auth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net"
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
	"github.com/o3co/protobuf.interceptors/endpoint"
	"github.com/provin-line/oss/network/pkg/auth"
)

func TestInterceptors_ReturnsChain(t *testing.T) {
	got := auth.Interceptors(endpoint.NewStaticEndpoint(nil))
	if len(got) != 2 {
		t.Fatalf("Interceptors returned %d, want 2 (policy-option then verification)", len(got))
	}
	// Concrete interceptor types are unexported, so order is not introspectable
	// here; it is verified behaviorally by the allow/deny end-to-end test in
	// enforcement_test.go (and the upstream VerificationInterceptor fails closed
	// with CodeInternal if PolicyOption did not run first).
}

func TestNewVerifier_O3coRequiresExplicitScheme(t *testing.T) {
	// NewO3coEndpoint silently prepends http:// when the scheme is omitted, so
	// our seam rejects a scheme-less URL (fail-closed — no accidental plaintext).
	for _, bad := range []string{
		"policy-verifier.internal:3001", // scheme-less
		"https://",                      // scheme set, hostless
		"https:///pv",                   // scheme set, empty host
	} {
		cfg := &auth.AuthConfig{Backend: auth.BackendO3co, PolicyVerifierURL: bad}
		if _, err := auth.NewVerifier(cfg); err == nil {
			t.Errorf("NewVerifier(o3co, %q): want error (fail-closed)", bad)
		}
	}
	cfg := &auth.AuthConfig{Backend: auth.BackendO3co, PolicyVerifierURL: "https://policy-verifier.internal:3001"}
	v, err := auth.NewVerifier(cfg)
	if err != nil {
		t.Fatalf("NewVerifier o3co happy path: %v", err)
	}
	if v == nil {
		t.Error("NewVerifier returned a nil verifier on the happy path")
	}
}

func TestNewVerifier_StaticDenyAllAndAllow(t *testing.T) {
	// Static backend is in-process authorization: it checks the bearer is
	// PRESENT (not that it is valid — that is why static is not authentication)
	// and matches (resource, action) against the allow-list. An empty allow-list
	// denies everything (safe default); a rule permits its (resource, action).
	ctx := interceptors.WithBearerToken(context.Background(), "present-but-unverified")

	denyAll, err := auth.NewVerifier(&auth.AuthConfig{Backend: auth.BackendStatic})
	if err != nil {
		t.Fatalf("NewVerifier static empty: %v", err)
	}
	if err := denyAll.Verify(ctx, "dids", "read"); err == nil {
		t.Error("empty static allow-list must deny even with a bearer present (got allow)")
	}

	allow := &auth.AuthConfig{Backend: auth.BackendStatic, Static: auth.StaticConfig{
		Allow: []auth.StaticAllowRule{{Resource: "dids", Action: "read"}},
	}}
	v, err := auth.NewVerifier(allow)
	if err != nil {
		t.Fatalf("NewVerifier static with rule: %v", err)
	}
	if err := v.Verify(ctx, "dids", "read"); err != nil {
		t.Errorf("allowed (dids, read) was denied: %v", err)
	}
	if err := v.Verify(ctx, "dids", "revoke"); err == nil {
		t.Error("un-allowed (dids, revoke) must be denied (got allow)")
	}
	// Bearer presence IS required (its value is never verified): no bearer -> deny.
	if err := v.Verify(context.Background(), "dids", "read"); err == nil {
		t.Error("static must deny when no bearer is present (presence check)")
	}
}

func TestNewVerifier_OPACedarRequireBaseURL(t *testing.T) {
	for name, cfg := range map[string]*auth.AuthConfig{
		"opa empty":   {Backend: auth.BackendOPA},
		"cedar empty": {Backend: auth.BackendCedar},
	} {
		if _, err := auth.NewVerifier(cfg); err == nil {
			t.Errorf("%s: want error (fail-closed on empty base-url)", name)
		}
	}
	opa := &auth.AuthConfig{Backend: auth.BackendOPA, OPA: auth.OPAConfig{BaseURL: "https://opa.internal:8181", PolicyPath: "provin/authz"}}
	if v, err := auth.NewVerifier(opa); err != nil || v == nil {
		t.Errorf("NewVerifier opa happy path: v=%v err=%v", v, err)
	}
	cedar := &auth.AuthConfig{Backend: auth.BackendCedar, Cedar: cedarCfg("https://cedar.internal:8180")}
	if v, err := auth.NewVerifier(cedar); err != nil || v == nil {
		t.Errorf("NewVerifier cedar happy path: v=%v err=%v", v, err)
	}
}

const testSecret = "0123456789abcdef0123456789abcdef"

func cedarCfg(baseURL string) auth.CedarConfig {
	return auth.CedarConfig{BaseURL: baseURL, JWT: auth.CedarJWTConfig{
		Issuer: "https://issuer.example", Audience: "provin-network", Secret: testSecret,
	}}
}

func TestNewVerifier_CedarRequiresJWTConfig(t *testing.T) {
	base := "https://cedar.internal:8180"
	with := func(f func(*auth.CedarJWTConfig)) *auth.AuthConfig {
		c := cedarCfg(base)
		f(&c.JWT)
		return &auth.AuthConfig{Backend: auth.BackendCedar, Cedar: c}
	}
	for name, cfg := range map[string]*auth.AuthConfig{
		"no issuer":   with(func(j *auth.CedarJWTConfig) { j.Issuer = "" }),
		"no audience": with(func(j *auth.CedarJWTConfig) { j.Audience = "" }),
		"no key":      with(func(j *auth.CedarJWTConfig) { j.Secret = "" }),
		"both keys":   with(func(j *auth.CedarJWTConfig) { j.JWKSURL = "https://issuer.example/jwks" }),
		"http jwks":   with(func(j *auth.CedarJWTConfig) { j.Secret = ""; j.JWKSURL = "http://issuer.example/jwks" }),
		"weak secret": with(func(j *auth.CedarJWTConfig) { j.Secret = "short" }),
	} {
		_, err := auth.NewVerifier(cfg)
		if err == nil {
			t.Errorf("%s: want error (fail-closed)", name)
			continue
		}
		if !strings.Contains(err.Error(), "provin.network.auth.cedar.jwt") {
			t.Errorf("%s: error %q does not name the config key", name, err)
		}
	}
}

func TestNewVerifier_CedarVerifiesBearerBeforeAskingAgent(t *testing.T) {
	var agentHits atomic.Int32
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agentHits.Add(1)
		var body struct{ Principal string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Principal != `User::"did:dplaax:alice"` {
			t.Errorf("agent asked about principal %q", body.Principal)
		}
		_, _ = w.Write([]byte(`{"decision":"Allow","diagnostics":{"reason":[],"errors":[]}}`))
	}))
	defer agent.Close()
	v, err := auth.NewVerifier(&auth.AuthConfig{Backend: auth.BackendCedar, Cedar: cedarCfg(agent.URL)})
	if err != nil {
		t.Fatal(err)
	}
	accessToken := (&jose.SignerOptions{}).WithType("at+jwt")
	claims := jwt.Claims{
		Issuer: "https://issuer.example", Audience: jwt.Audience{"provin-network"},
		Subject: "did:dplaax:alice", Expiry: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt: jwt.NewNumericDate(time.Now()),
	}
	sig, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte(testSecret)}, accessToken)
	good, _ := jwt.Signed(sig).Claims(claims).Serialize()

	if err := v.Verify(interceptors.WithBearerToken(context.Background(), good), "dids", "read"); err != nil {
		t.Fatalf("verified token denied: %v", err)
	}
	if agentHits.Load() != 1 {
		t.Fatalf("agent hits = %d, want 1", agentHits.Load())
	}
	// Same claims, signed with a different key: the signature cannot verify.
	otherSig, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte("ffffffffffffffffffffffffffffffff")}, accessToken)
	forged, _ := jwt.Signed(otherSig).Claims(claims).Serialize()
	if forged == good {
		t.Fatal("forged token equals the valid one")
	}
	err = v.Verify(interceptors.WithBearerToken(context.Background(), forged), "dids", "read")
	var unauth *interceptors.UnauthenticatedError
	if !errors.As(err, &unauth) {
		t.Errorf("forged token: err = %v, want UnauthenticatedError", err)
	}
	if agentHits.Load() != 1 {
		t.Errorf("agent was asked about an unverified token (hits = %d)", agentHits.Load())
	}
}

// cedarJWKSVerifier builds a cedar Verifier whose key set is at jwksURL, and
// counts the agent's requests.
func cedarJWKSVerifier(t *testing.T, jwksURL string) (auth.Verifier, *atomic.Int32) {
	t.Helper()
	agentHits := new(atomic.Int32)
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agentHits.Add(1)
		_, _ = w.Write([]byte(`{"decision":"Allow","diagnostics":{"reason":[],"errors":[]}}`))
	}))
	t.Cleanup(agent.Close)
	cfg := cedarCfg(agent.URL)
	cfg.JWT.Secret, cfg.JWT.JWKSURL = "", jwksURL
	v, err := auth.NewVerifier(&auth.AuthConfig{Backend: auth.BackendCedar, Cedar: cfg})
	if err != nil {
		t.Fatal(err)
	}
	return v, agentHits
}

// esAccessToken is an ES256 access token for the cedarCfg issuer and audience,
// under key id k1.
func esAccessToken(t *testing.T) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: k}, (&jose.SignerOptions{}).WithType("at+jwt").WithHeader("kid", "k1"))
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jwt.Signed(sig).Claims(jwt.Claims{
		Issuer: "https://issuer.example", Audience: jwt.Audience{"provin-network"},
		Subject: "did:dplaax:alice", Expiry: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt: jwt.NewNumericDate(time.Now()),
	}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// A cedar node that cannot fetch the issuer's key set has not judged the
// token: Verify reports the backend unavailable, not the caller
// unauthenticated, and the agent is not asked.
func TestNewVerifier_CedarKeySetItCannotFetchIsUnavailable(t *testing.T) {
	gone := httptest.NewTLSServer(http.NotFoundHandler())
	gone.Close()
	v, agentHits := cedarJWKSVerifier(t, gone.URL+"/jwks")
	err := v.Verify(interceptors.WithBearerToken(context.Background(), esAccessToken(t)), "dids", "read")
	var unauth *interceptors.UnauthenticatedError
	if !errors.Is(err, interceptors.ErrBackendUnavailable) || errors.As(err, &unauth) {
		t.Errorf("err = %v, want one wrapping ErrBackendUnavailable and no UnauthenticatedError", err)
	}
	if agentHits.Load() != 0 {
		t.Errorf("agent hits = %d, want 0", agentHits.Load())
	}
}

// A caller whose own context ends while the node waits for the issuer's key
// set is not refused as unauthenticated: the error carries the context's end,
// which the interceptors report as Canceled or DeadlineExceeded.
func TestNewVerifier_CedarCallerContextEndingWhileFetchingIsNotUnauthenticated(t *testing.T) {
	for name, c := range map[string]struct {
		ctx    func() (context.Context, context.CancelFunc)
		cancel bool // cancel once the fetch has connected
		want   error
	}{
		"canceled": {func() (context.Context, context.CancelFunc) { return context.WithCancel(context.Background()) }, true, context.Canceled},
		"past its deadline": {func() (context.Context, context.CancelFunc) {
			return context.WithTimeout(context.Background(), 100*time.Millisecond)
		}, false, context.DeadlineExceeded},
	} {
		t.Run(name, func(t *testing.T) {
			// A key set endpoint that accepts the connection and never answers.
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			accepted := make(chan struct{}, 1)
			var (
				mu    sync.Mutex
				conns []net.Conn
			)
			go func() {
				for {
					conn, err := ln.Accept()
					if err != nil {
						return
					}
					mu.Lock()
					conns = append(conns, conn)
					mu.Unlock()
					select {
					case accepted <- struct{}{}:
					default:
					}
				}
			}()
			t.Cleanup(func() {
				_ = ln.Close()
				mu.Lock()
				defer mu.Unlock()
				for _, conn := range conns {
					_ = conn.Close()
				}
			})
			v, agentHits := cedarJWKSVerifier(t, "https://"+ln.Addr().String()+"/jwks")
			tok := esAccessToken(t)
			ctx, cancel := c.ctx()
			defer cancel()
			errc := make(chan error, 1)
			go func() { errc <- v.Verify(interceptors.WithBearerToken(ctx, tok), "dids", "read") }()
			if c.cancel {
				<-accepted
				cancel()
			}
			err = <-errc
			var unauth *interceptors.UnauthenticatedError
			if errors.As(err, &unauth) || !errors.Is(err, interceptors.ErrBackendUnavailable) || !errors.Is(err, c.want) {
				t.Errorf("err = %v, want one wrapping ErrBackendUnavailable and %v, and no UnauthenticatedError", err, c.want)
			}
			if agentHits.Load() != 0 {
				t.Errorf("agent hits = %d, want 0", agentHits.Load())
			}
		})
	}
}

// A PDP answer in which one object names a key twice has no single reading:
// it is a malformed answer, neither an allow nor a deny, and not an outage.
func TestNewVerifier_RefusesAnAnswerThatRepeatsAKey(t *testing.T) {
	accessToken := (&jose.SignerOptions{}).WithType("at+jwt")
	sig, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte(testSecret)}, accessToken)
	good, _ := jwt.Signed(sig).Claims(jwt.Claims{
		Issuer: "https://issuer.example", Audience: jwt.Audience{"provin-network"},
		Subject: "did:dplaax:alice", Expiry: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt: jwt.NewNumericDate(time.Now()),
	}).Serialize()
	pdp := func(answer string) string {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(answer))
		}))
		t.Cleanup(srv.Close)
		return srv.URL
	}
	backends := map[string]struct {
		cfg      func(url string) *auth.AuthConfig
		allow    string // a whole allow
		repeated string // the same allow with one key named twice
	}{
		"o3co": {
			func(url string) *auth.AuthConfig {
				return &auth.AuthConfig{Backend: auth.BackendO3co, PolicyVerifierURL: url}
			},
			`{"resource":"dids","action":"read","decision":"allow","reason":{"groups":[]}}`,
			`{"resource":"dids","action":"read","decision":"allow","decision":"allow","reason":{"groups":[]}}`,
		},
		"opa": {
			func(url string) *auth.AuthConfig {
				return &auth.AuthConfig{Backend: auth.BackendOPA, OPA: auth.OPAConfig{BaseURL: url, PolicyPath: "provin/authz"}}
			},
			`{"result":true}`,
			`{"result":true,"result":true}`,
		},
		"cedar": {
			func(url string) *auth.AuthConfig {
				return &auth.AuthConfig{Backend: auth.BackendCedar, Cedar: cedarCfg(url)}
			},
			`{"decision":"Allow","diagnostics":{"reason":[],"errors":[]}}`,
			`{"decision":"Allow","decision":"Allow","diagnostics":{"reason":[],"errors":[]}}`,
		},
	}
	verify := func(name, answer string) error {
		v, err := auth.NewVerifier(backends[name].cfg(pdp(answer)))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return v.Verify(interceptors.WithBearerToken(context.Background(), good), "dids", "read")
	}
	for name, b := range backends {
		if err := verify(name, b.allow); err != nil {
			t.Fatalf("%s: the allow without a repeated key: %v", name, err)
		}
		err := verify(name, b.repeated)
		var (
			denied *interceptors.DeniedError
			unauth *interceptors.UnauthenticatedError
		)
		if err == nil || errors.As(err, &denied) || errors.As(err, &unauth) || errors.Is(err, interceptors.ErrBackendUnavailable) {
			t.Errorf("%s: err = %v, want a malformed answer (no allow, deny, refusal of the token or outage)", name, err)
		}
	}
}

func TestNewVerifier_PlainInternal(t *testing.T) {
	// A plaintext, non-loopback PDP URL needs an explicit plain-internal entry
	// (backend construction refuses it otherwise); an invalid entry fails
	// construction with the config key named.
	for name, cfg := range map[string]func(plain ...string) *auth.AuthConfig{
		"o3co": func(p ...string) *auth.AuthConfig {
			return &auth.AuthConfig{Backend: auth.BackendO3co, PolicyVerifierURL: "http://policy-verifier:3001", PlainInternal: p}
		},
		"opa": func(p ...string) *auth.AuthConfig {
			return &auth.AuthConfig{Backend: auth.BackendOPA, OPA: auth.OPAConfig{BaseURL: "http://policy-verifier:3001", PolicyPath: "p/a"}, PlainInternal: p}
		},
		"cedar": func(p ...string) *auth.AuthConfig {
			return &auth.AuthConfig{Backend: auth.BackendCedar, Cedar: cedarCfg("http://policy-verifier:3001"), PlainInternal: p}
		},
	} {
		_, err := auth.NewVerifier(cfg())
		if err == nil {
			t.Errorf("%s: plaintext to a non-loopback host without plain-internal must be refused", name)
		} else if !strings.Contains(err.Error(), "provin.network.auth.plain-internal") || strings.Contains(err.Error(), "AllowInsecure") {
			t.Errorf("%s: error %q must name provin.network.auth.plain-internal and not point at AllowInsecure", name, err)
		}
		if _, err := auth.NewVerifier(cfg("policy-verifier:3001")); err != nil {
			t.Errorf("%s: listed host:port refused: %v", name, err)
		}
		if _, err := auth.NewVerifier(cfg("other-host:3001")); err == nil {
			t.Errorf("%s: an entry for another host:port must not allow the URL", name)
		}
		_, err = auth.NewVerifier(cfg("policy-verifier"))
		if err == nil || !strings.Contains(err.Error(), "provin.network.auth.plain-internal") {
			t.Errorf("%s: invalid entry: err = %v, want one naming provin.network.auth.plain-internal", name, err)
		}
	}
}

func TestNewVerifier_UnknownBackendFailsClosed(t *testing.T) {
	if _, err := auth.NewVerifier(&auth.AuthConfig{Backend: "bogus"}); err == nil {
		t.Error("unknown backend must error (fail-closed — never silently pick one)")
	}
}

func TestNewVerifier_UnsetBackendDefaultsO3co(t *testing.T) {
	// A directly-constructed AuthConfig with an unset Backend must behave as the
	// field godoc promises — default to o3co — not be rejected as an unknown
	// backend. (The default lives in validate(), so it holds without going
	// through LoadAuthConfig.)
	cfg := &auth.AuthConfig{PolicyVerifierURL: "https://policy-verifier.internal:3001"}
	v, err := auth.NewVerifier(cfg)
	if err != nil {
		t.Fatalf("NewVerifier with unset backend: %v", err)
	}
	if v == nil {
		t.Error("NewVerifier returned nil verifier for the defaulted o3co backend")
	}
}
