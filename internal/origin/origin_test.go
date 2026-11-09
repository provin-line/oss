package origin_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/provin-line/oss/internal/origin"
)

func TestParse_ReadsAnOriginInItsOneSpelling(t *testing.T) {
	for in, want := range map[string]string{
		"https://Peer.Example":                 "https://peer.example",
		"HTTPS://peer.example:443":             "https://peer.example",
		"http://peer.example:80/":              "http://peer.example",
		"http://10.0.0.7:8080":                 "http://10.0.0.7:8080",
		"https://[2001:DB8::1]:8443":           "https://[2001:db8::1]:8443",
		"https://[2001:0db8:0:0:0:0:0:1]:8443": "https://[2001:db8::1]:8443",
		"https://peer.example:0443":            "https://peer.example",
		"http://peer.example:08080":            "http://peer.example:8080",
	} {
		if got, err := origin.Parse(in); err != nil || got != want {
			t.Errorf("Parse(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{
		"", "peer.example", "ftp://peer.example", "https://peer.example/path",
		"https://peer.example?q=1", "https://peer.example?", "https://peer.example#f",
		"https://user@peer.example", "https://", "mailto:x@peer.example",
		"https://peer.example#", "https://peer.example:65536", "https://peer.example:0",
		"https://peer.example:-1", "https://[fe80::1%25en0]",
		"https://İssuer.example", "https://%C4%B0ssuer.example",
	} {
		if got, err := origin.Parse(in); err == nil {
			t.Errorf("Parse(%q) = %q, want an error", in, got)
		}
	}
}

func TestOf_IsTheOriginOfAnEndpoint(t *testing.T) {
	for in, want := range map[string]string{
		"https://Peer.Example/dplaax.vc.v1.VCResolverService/": "https://peer.example",
		"https://peer.example:443/a?b=c":                       "https://peer.example",
		"http://10.0.0.7:8080/":                                "http://10.0.0.7:8080",
	} {
		if got, ok := origin.Of(in); !ok || got != want {
			t.Errorf("Of(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "peer.example/a", "ftp://peer.example", "https://user:pw@peer.example/", "mailto:x@y",
		"https://İssuer.example/", "https://%C4%B0ssuer.example/", "https://peer.example/#@evil.example"} {
		if got, ok := origin.Of(in); ok {
			t.Errorf("Of(%q) = %q, want none", in, got)
		}
	}
}

// A confined client follows no redirect, so a request that carries a
// credential is not sent on to another server.
func TestConfine_FollowsNoRedirect(t *testing.T) {
	var reached atomic.Bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Store(true) }))
	defer other.Close()
	named := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer named.Close()
	c := origin.Confine(named.Client())
	req, _ := http.NewRequest(http.MethodPost, named.URL, nil)
	req.Header.Set("Authorization", "Bearer t")
	resp, err := c.Do(req)
	if err == nil {
		resp.Body.Close()
		t.Error("a redirect was followed")
	}
	if reached.Load() {
		t.Error("the other server was reached")
	}
	if err == nil || !strings.Contains(err.Error(), other.Listener.Addr().String()) {
		t.Errorf("err = %v, want it to name the redirect's target", err)
	}
	if named.Client().CheckRedirect != nil {
		t.Error("Confine changed the client it was given")
	}
}

// In compares an endpoint's origin with listed origins in one spelling, also
// when a list was written by hand in another spelling; a listed value that is
// not an origin matches nothing.
func TestIn_ComparesInOneSpelling(t *testing.T) {
	listed := []string{"HTTPS://Peer.Example:443", "not an origin", "http://10.0.0.7:8080"}
	for endpoint, want := range map[string]bool{
		"https://peer.example/dplaax.vc.v1.VCResolverService/": true,
		"https://PEER.example:443/x":                           true,
		"http://10.0.0.7:8080/":                                true,
		"https://peer.example:8443/":                           false,
		"http://peer.example/":                                 false,
		"https://other.example/":                               false,
		"https://\u0130ssuer.example/":                         false,
	} {
		if got := origin.In(endpoint, listed); got != want {
			t.Errorf("In(%q) = %v, want %v", endpoint, got, want)
		}
	}
}
