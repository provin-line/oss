package core_test

import (
	"net/http"
	"testing"

	"github.com/provin-line/oss/network/pkg/core"
)

// HTTPClient must disable proxying: an SSRF guard pins the dialed target IP, but a
// proxy makes Go dial the proxy instead, so DialContext would validate the proxy,
// not the attacker-controlled target — silently bypassing the guarantee. The
// guarded client therefore sets Transport.Proxy = nil.
func TestURLGuard_HTTPClient_DisablesProxy(t *testing.T) {
	c := core.NewURLGuard().HTTPClient()
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport is %T, want *http.Transport", c.Transport)
	}
	if tr.Proxy != nil {
		t.Error("guarded HTTPClient must have Transport.Proxy == nil (proxy bypasses IP pinning)")
	}
}
