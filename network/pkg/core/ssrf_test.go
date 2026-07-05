package core_test

import (
	"context"
	"net/http"
	"net/netip"
	"net/url"
	"testing"

	"github.com/provin-line/oss/network/pkg/core"
)

// staticResolver returns fixed addrs (or an error) for any host — no real DNS.
func staticResolver(addrs []netip.Addr, err error) func(context.Context, string) ([]netip.Addr, error) {
	return func(context.Context, string) ([]netip.Addr, error) { return addrs, err }
}

func mustAddrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}

func TestCheckURL_BlocksByIPLiteral(t *testing.T) {
	g := core.NewURLGuard() // private blocked by default (D1)
	blocked := []string{
		"http://127.0.0.1/",                // loopback v4
		"http://[::1]/",                    // loopback v6
		"http://0.0.0.1/",                  // 0.0.0.0/8
		"http://169.254.169.254/",          // link-local / metadata
		"http://[fe80::1]/",                // link-local v6
		"http://10.0.0.5/",                 // private
		"http://192.168.1.1/",              // private
		"http://172.16.0.1/",               // private
		"http://100.100.100.200/",          // CGNAT (Alibaba metadata)
		"http://[fc00::1]/",                // ULA
		"http://[fec0::1]/",                // deprecated site-local
		"http://[::ffff:127.0.0.1]/",       // v4-mapped → Unmap → loopback
		"http://[::a9fe:a9fe]/",            // v4-compatible (::/96), NOT mapped
		"http://[64:ff9b::a9fe:a9fe]/",     // NAT64 → 169.254.169.254
		"http://[2002:a9fe:a9fe::]/",       // 6to4
		"http://192.0.2.1/",                // doc TEST-NET-1
		"http://198.18.0.1/",               // benchmarking
		"http://[2001:db8::1]/",            // doc v6
		"http://255.255.255.255/",          // broadcast (240/4)
		"http://224.0.0.1/",                // multicast
		"http://[::]/",                     // unspecified v6 (::/128)
		"http://[100:0:0:1::1]/",           // IANA dummy IPv6 prefix
		"http://[::ffff:169.254.169.254]/", // v4-mapped metadata → Unmap → blocked
	}
	for _, raw := range blocked {
		if err := g.CheckURL(context.Background(), raw); err == nil {
			t.Errorf("CheckURL(%q): want blocked, got nil", raw)
		}
	}
}

func TestCheckURL_BlocksZonedAddr(t *testing.T) {
	g := core.NewURLGuard()
	// Literal zone id.
	if err := g.CheckURL(context.Background(), "http://[fe80::1%25en0]/"); err == nil {
		t.Error("zoned IPv6 literal: want blocked")
	}
	// Resolver returning a zoned addr must also be rejected (same checkAddr path).
	zoned := netip.MustParseAddr("fe80::1").WithZone("en0")
	gz := core.NewURLGuard(core.WithResolver(staticResolver([]netip.Addr{zoned}, nil)))
	if err := gz.CheckURL(context.Background(), "http://host.example/"); err == nil {
		t.Error("resolver-returned zoned addr: want blocked")
	}
}

func TestCheckURL_LexicalNumericHostsRejected(t *testing.T) {
	// Resolver would (wrongly) say "public" — proves the lexical reject fires
	// BEFORE resolution, independent of resolver flavor.
	g := core.NewURLGuard(core.WithResolver(staticResolver(mustAddrs("8.8.8.8"), nil)))
	for _, raw := range []string{"http://2130706433/", "http://0177.0.0.1/", "http://1.1/"} {
		if err := g.CheckURL(context.Background(), raw); err == nil {
			t.Errorf("CheckURL(%q): want lexical reject of legacy numeric host", raw)
		}
	}
}

func TestCheckURL_SchemeAndUserinfoAndHost(t *testing.T) {
	g := core.NewURLGuard(core.WithResolver(staticResolver(mustAddrs("93.184.216.34"), nil)))
	bad := []string{
		"file:///etc/passwd",     // non-http scheme
		"gopher://x/",            // non-http scheme
		"http://user:pass@host/", // userinfo
		"http:///path",           // empty host
		"://nohost",              // unparseable-ish
	}
	for _, raw := range bad {
		if err := g.CheckURL(context.Background(), raw); err == nil {
			t.Errorf("CheckURL(%q): want blocked", raw)
		}
	}
}

func TestCheckURL_ResolverFailClosed(t *testing.T) {
	// Resolution error → block.
	gErr := core.NewURLGuard(core.WithResolver(staticResolver(nil, context.DeadlineExceeded)))
	if err := gErr.CheckURL(context.Background(), "http://host.example/"); err == nil {
		t.Error("resolution error: want blocked (fail-closed)")
	}
	// Zero results → block.
	gZero := core.NewURLGuard(core.WithResolver(staticResolver([]netip.Addr{}, nil)))
	if err := gZero.CheckURL(context.Background(), "http://host.example/"); err == nil {
		t.Error("zero resolved addrs: want blocked (fail-closed)")
	}
}

func TestCheckURL_MixedResolutionBlocksIfAnyBlocked(t *testing.T) {
	g := core.NewURLGuard(core.WithResolver(staticResolver(mustAddrs("93.184.216.34", "127.0.0.1"), nil)))
	if err := g.CheckURL(context.Background(), "http://host.example/"); err == nil {
		t.Error("one blocked addr among results: want blocked")
	}
}

func TestCheckURL_AllowsPublic(t *testing.T) {
	// Public IP literal.
	g := core.NewURLGuard()
	if err := g.CheckURL(context.Background(), "http://93.184.216.34/"); err != nil {
		t.Errorf("public IP literal: want allowed, got %v", err)
	}
	// Public via resolver.
	gr := core.NewURLGuard(core.WithResolver(staticResolver(mustAddrs("93.184.216.34", "2606:2800:220:1::1"), nil)))
	if err := gr.CheckURL(context.Background(), "https://example.com./"); err != nil { // trailing dot tolerated
		t.Errorf("public host via resolver (trailing dot): want allowed, got %v", err)
	}
	// v4-mapped PUBLIC literal is allowed (Unmap → public v4); the intentional
	// exception documented in checkAddr. Mapped private/local stays blocked
	// (covered in TestCheckURL_BlocksByIPLiteral).
	if err := g.CheckURL(context.Background(), "http://[::ffff:8.8.8.8]/"); err != nil {
		t.Errorf("v4-mapped public literal: want allowed, got %v", err)
	}
}

func TestCheckURL_AllowLoopbackOptIn(t *testing.T) {
	g := core.NewURLGuard(core.WithAllowLoopback(true))
	for _, raw := range []string{"http://127.0.0.1/", "http://[::1]/"} {
		if err := g.CheckURL(context.Background(), raw); err != nil {
			t.Errorf("WithAllowLoopback: %q should be allowed, got %v", raw, err)
		}
	}
	// Still blocks non-loopback local ranges.
	for _, raw := range []string{"http://169.254.169.254/", "http://10.0.0.1/"} {
		if err := g.CheckURL(context.Background(), raw); err == nil {
			t.Errorf("WithAllowLoopback must still block %q", raw)
		}
	}
}

func TestCheckRedirect(t *testing.T) {
	g := core.NewURLGuard()
	mk := func(raw string) *http.Request {
		u, _ := url.Parse(raw)
		return &http.Request{URL: u}
	}
	// Redirect into a blocked addr.
	if err := g.CheckRedirect(mk("http://169.254.169.254/"), nil); err == nil {
		t.Error("CheckRedirect into metadata: want blocked")
	}
	// Public redirect within the hop cap is fine.
	if err := g.CheckRedirect(mk("http://93.184.216.34/"), make([]*http.Request, 3)); err != nil {
		t.Errorf("CheckRedirect public within cap: want nil, got %v", err)
	}
	// 11th hop blocked even when target is public (10-hop cap preserved).
	if err := g.CheckRedirect(mk("http://93.184.216.34/"), make([]*http.Request, 10)); err == nil {
		t.Error("CheckRedirect 11th hop: want blocked (hop cap)")
	}
}

func TestCheckURL_AllowPrivateNetworksOptIn(t *testing.T) {
	ctx := context.Background()

	// Default: RFC 1918 stays blocked.
	g := core.NewURLGuard()
	if err := g.CheckURL(ctx, "http://172.20.0.2/"); err == nil {
		t.Error("default guard allowed a private address")
	}

	g = core.NewURLGuard(core.WithAllowPrivateNetworks(true))
	// The opt-in permits exactly the RFC 1918 IPv4 ranges — including their
	// v4-mapped IPv6 spellings, which Unmap() makes equivalent to the v4 form.
	for _, u := range []string{
		"http://10.1.2.3/",
		"http://172.20.0.2:8443/",
		"http://192.168.1.9/",
		"http://[::ffff:10.0.0.1]/",
	} {
		if err := g.CheckURL(ctx, u); err != nil {
			t.Errorf("CheckURL(%q) with private opt-in: %v", u, err)
		}
	}
	// The resolver path funnels through the same validator: a hostname whose A
	// record is private is allowed under the opt-in.
	gr := core.NewURLGuard(core.WithAllowPrivateNetworks(true),
		core.WithResolver(staticResolver(mustAddrs("172.20.0.2"), nil)))
	if err := gr.CheckURL(ctx, "http://peer.internal/"); err != nil {
		t.Errorf("CheckURL(resolved private) with opt-in: %v", err)
	}
	// Everything else stays blocked: link-local metadata, CGNAT, IPv6 ULA
	// (fd00:ec2::254 metadata lives there), and loopback (its own opt-in).
	for _, u := range []string{
		"http://169.254.169.254/",
		"http://100.100.100.200/",
		"http://[fc00::1]/",
		"http://[fd00:ec2::254]/",
		"http://127.0.0.1/",
	} {
		if err := g.CheckURL(ctx, u); err == nil {
			t.Errorf("CheckURL(%q) allowed despite private-networks opt-in", u)
		}
	}
}
