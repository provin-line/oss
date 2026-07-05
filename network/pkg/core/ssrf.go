// Package core is the network server foundation: SSRF-resistant outbound URL
// validation, secret URI resolution, and the typed/validated config tree built
// on hoconconfig. It is a library layer within network/ — it must not import
// gen/, pipeline/, cmd/, or service packages.
package core

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
)

// ErrURLBlocked is the sentinel for every SSRF rejection. Callers map it with
// errors.Is (e.g. to a Connect PermissionDenied/InvalidArgument).
var ErrURLBlocked = errors.New("core: outbound URL blocked")

// maxRedirects is Go's default redirect cap, re-imposed by CheckRedirect (a
// custom http.Client.CheckRedirect otherwise removes it).
const maxRedirects = 10

// blockedPrefixes is the authoritative deny list: all IANA special-purpose
// ranges plus deprecated local-use — everything that is not public global
// unicast ("public-internet-only", D1). Loopback (127/8, ::1) is handled by an
// early IsLoopback check in checkAddr (gated by the dev opt-in) and so is NOT
// listed here.
var blockedPrefixes = mustPrefixes(
	// IPv4
	"0.0.0.0/8",       // "this network" / unspecified block
	"10.0.0.0/8",      // private (RFC 1918)
	"100.64.0.0/10",   // CGNAT (Alibaba metadata 100.100.100.200)
	"169.254.0.0/16",  // link-local (incl. 169.254.169.254 metadata)
	"172.16.0.0/12",   // private
	"192.0.0.0/24",    // IETF protocol assignments
	"192.0.2.0/24",    // documentation TEST-NET-1
	"192.31.196.0/24", // AS112-v4
	"192.52.193.0/24", // AMT
	"192.88.99.0/24",  // deprecated 6to4 relay anycast
	"192.168.0.0/16",  // private
	"192.175.48.0/24", // direct delegation AS112
	"198.18.0.0/15",   // benchmarking
	"198.51.100.0/24", // documentation TEST-NET-2
	"203.0.113.0/24",  // documentation TEST-NET-3
	"224.0.0.0/4",     // multicast
	"240.0.0.0/4",     // reserved (incl. 255.255.255.255 broadcast)
	// IPv6
	"::/128",            // unspecified (explicit; also inside ::/96, kept so removing ::/96 can't silently unblock it)
	"::/96",             // deprecated IPv4-compatible (embeds v4; not Unmapped)
	"64:ff9b::/96",      // NAT64 well-known
	"64:ff9b:1::/48",    // NAT64 local-use
	"100::/64",          // discard-only
	"100:0:0:1::/64",    // IANA "dummy IPv6 prefix" (not globally reachable)
	"2001::/23",         // IETF protocol assignments (incl. Teredo 2001::/32)
	"2001:db8::/32",     // documentation
	"2002::/16",         // 6to4 (embeds v4)
	"2620:4f:8000::/48", // direct delegation AS112
	"3fff::/20",         // documentation
	"5f00::/16",         // SRv6
	"fc00::/7",          // unique-local (ULA; incl. fd00:ec2::254 metadata)
	"fe80::/10",         // link-local
	"fec0::/10",         // deprecated site-local
	"ff00::/8",          // multicast
)

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			panic("core: bad blocked prefix " + s + ": " + err.Error())
		}
		out[i] = p
	}
	return out
}

type resolveFunc func(ctx context.Context, host string) ([]netip.Addr, error)

// privatePrefixes are the RFC 1918 IPv4 ranges the WithAllowPrivateNetworks
// opt-in permits. Deliberately v4-only: IPv6 unique-local (fc00::/7) contains
// cloud metadata endpoints (fd00:ec2::254) and stays blocked; a v6-private
// deployment needs its own, narrower opt-in if one is ever justified.
var privatePrefixes = mustPrefixes(
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
)

// URLGuard validates outbound URLs against SSRF. Safe for concurrent use.
type URLGuard struct {
	allowLoopback bool
	allowPrivate  bool
	resolve       resolveFunc
}

// GuardOption configures a URLGuard.
type GuardOption func(*URLGuard)

// WithAllowLoopback permits loopback targets (127/8, ::1) — a local-dev opt-in
// ONLY. It relaxes nothing else: link-local, metadata, NAT64-to-metadata,
// unspecified, private, etc. stay blocked.
func WithAllowLoopback(allow bool) GuardOption {
	return func(g *URLGuard) { g.allowLoopback = allow }
}

// WithAllowPrivateNetworks permits RFC 1918 IPv4 private targets (10/8,
// 172.16/12, 192.168/16) — the opt-in for deployments whose peers live on a
// private network (LAN, VPC, container networks). It relaxes nothing else:
// loopback keeps its own opt-in, and link-local, CGNAT, IPv6 unique-local
// (which contains metadata endpoints), multicast, etc. stay blocked.
func WithAllowPrivateNetworks(allow bool) GuardOption {
	return func(g *URLGuard) { g.allowPrivate = allow }
}

// WithResolver injects the DNS resolver (test seam; default resolves via
// net.Resolver.LookupNetIP over "ip").
func WithResolver(resolve func(ctx context.Context, host string) ([]netip.Addr, error)) GuardOption {
	return func(g *URLGuard) { g.resolve = resolve }
}

// NewURLGuard builds a guard with the default deny policy.
func NewURLGuard(opts ...GuardOption) *URLGuard {
	g := &URLGuard{resolve: defaultResolve}
	for _, o := range opts {
		o(g)
	}
	return g
}

func defaultResolve(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// CheckURL returns nil iff raw is a well-formed http(s) URL whose host resolves
// only to non-blocked addresses. Every failure wraps ErrURLBlocked.
//
// CheckURL is a PREFLIGHT: it resolves and validates, but a later dial would
// re-resolve, so on its own it does not stop DNS rebinding. For an actual
// outbound request to a data-supplied endpoint, use HTTPClient (or DialContext),
// which pin the connection to the validated IP and close that gap.
func (g *URLGuard) CheckURL(ctx context.Context, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: parse: %v", ErrURLBlocked, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%w: scheme %q (only http/https)", ErrURLBlocked, u.Scheme)
	}
	if u.User != nil {
		return fmt.Errorf("%w: userinfo is not allowed", ErrURLBlocked)
	}
	host := strings.TrimSuffix(u.Hostname(), ".") // tolerate FQDN trailing dot
	if host == "" {
		return fmt.Errorf("%w: empty host", ErrURLBlocked)
	}

	// inet_aton legacy numeric forms (2130706433, 0177.0.0.1, 1.1) parse
	// differently across resolver flavors; reject lexically so the outcome is
	// deterministic. A genuine dotted IPv4 still parses below. (Hex forms like
	// 0x7f000001 are NOT [0-9.] so they skip this gate, but the
	// check-all-resolved-addrs posture blocks them: the resolver either decodes
	// them to a blocked addr or fails — both fail closed.)
	if isNumericHost(host) {
		if addr, perr := netip.ParseAddr(host); perr == nil {
			return g.checkAddr(addr)
		}
		return fmt.Errorf("%w: legacy numeric host %q", ErrURLBlocked, host)
	}

	if addr, perr := netip.ParseAddr(host); perr == nil {
		return g.checkAddr(addr)
	}

	addrs, err := g.resolve(ctx, host)
	if err != nil {
		return fmt.Errorf("%w: resolve %q: %v", ErrURLBlocked, host, err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("%w: %q resolved to no addresses", ErrURLBlocked, host)
	}
	for _, addr := range addrs {
		if err := g.checkAddr(addr); err != nil {
			return err
		}
	}
	return nil
}

// CheckRedirect plugs into http.Client.CheckRedirect: it guards every redirect
// hop AND re-imposes Go's default 10-hop cap (a custom CheckRedirect removes it).
func (g *URLGuard) CheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("%w: stopped after %d redirects", ErrURLBlocked, maxRedirects)
	}
	return g.CheckURL(req.Context(), req.URL.String())
}

// DialContext is a net.Dialer-shaped dial function that resolves the host ONCE,
// validates every resolved address, and connects only to a validated IP. Because
// the single resolution feeds both the check and the dial, a rebinding attacker
// cannot return a public address to validation and a blocked one to the dial —
// the gap CheckURL alone (a preflight) cannot close. The original Host is
// preserved for the request (TLS SNI / cert verification still use the URL host,
// since only the TCP target is pinned to the IP).
func (g *URLGuard) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("%w: dial address %q: %v", ErrURLBlocked, addr, err)
	}

	var validated []netip.Addr
	if ip, perr := netip.ParseAddr(host); perr == nil {
		if err := g.checkAddr(ip); err != nil {
			return nil, err
		}
		validated = append(validated, ip.Unmap())
	} else {
		if isNumericHost(host) {
			return nil, fmt.Errorf("%w: legacy numeric host %q", ErrURLBlocked, host)
		}
		addrs, rerr := g.resolve(ctx, host)
		if rerr != nil {
			return nil, fmt.Errorf("%w: resolve %q: %v", ErrURLBlocked, host, rerr)
		}
		if len(addrs) == 0 {
			return nil, fmt.Errorf("%w: %q resolved to no addresses", ErrURLBlocked, host)
		}
		for _, a := range addrs {
			if err := g.checkAddr(a); err != nil {
				return nil, err // one blocked addr blocks the host (matches CheckURL)
			}
			validated = append(validated, a.Unmap())
		}
	}

	// Dial only the validated IPs (pinned — no second resolution).
	var d net.Dialer
	var firstErr error
	for _, ip := range validated {
		conn, derr := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if derr == nil {
			return conn, nil
		}
		if firstErr == nil {
			firstErr = derr
		}
	}
	return nil, firstErr
}

// HTTPClient returns an *http.Client whose every connection is guarded: the dial
// is pinned to validated IPs (DialContext) and each redirect hop is re-checked
// (CheckRedirect). This is the safe way to fetch a data-supplied endpoint; it
// clones http.DefaultTransport so timeouts / TLS defaults are preserved.
//
// Proxying is disabled (Proxy = nil): the guard's guarantee is that the dialed
// target IP is validated and pinned, but an HTTP(S)_PROXY would make Go dial the
// proxy instead — DialContext would then validate the proxy address, not the
// attacker-controlled target host, silently bypassing the pin. A proxy is
// fundamentally incompatible with SSRF target-IP pinning, so a deployment needing
// a trusted egress proxy must use a separate, non-guarded path.
func (g *URLGuard) HTTPClient() *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.DialContext = g.DialContext
	t.Proxy = nil
	return &http.Client{
		Transport:     t,
		CheckRedirect: g.CheckRedirect,
	}
}

// checkAddr is the single validator for both IP-literal and resolved addresses.
func (g *URLGuard) checkAddr(addr netip.Addr) error {
	if !addr.IsValid() {
		return fmt.Errorf("%w: invalid address", ErrURLBlocked)
	}
	// Zoned addresses bypass netip.Prefix.Contains (it returns false for them),
	// so reject before any prefix test — fail-closed.
	if addr.Zone() != "" {
		return fmt.Errorf("%w: zoned address %q", ErrURLBlocked, addr)
	}
	// Unmap collapses an IPv4-mapped address (::ffff:v4) to its v4 form so it is
	// checked against the v4 prefixes. This is intentional: a mapped PRIVATE/LOCAL
	// v4 (::ffff:127.0.0.1, ::ffff:169.254.169.254) is still blocked, while a
	// mapped PUBLIC v4 (::ffff:8.8.8.8) is allowed as the public address it names.
	// We do not reject Is4In6 outright — resolvers legitimately return 4-in-6 for
	// public v4 hosts, and rejecting would false-block them.
	addr = addr.Unmap()
	if addr.IsLoopback() {
		if g.allowLoopback {
			return nil
		}
		return fmt.Errorf("%w: loopback %q", ErrURLBlocked, addr)
	}
	// The private allow runs BEFORE blockedPrefixes, so it must stay exactly
	// the RFC 1918 set: a future blocked prefix carved out INSIDE one of these
	// ranges would be silently overridden here — handle such a carve-out before
	// this allow, not by appending to blockedPrefixes.
	if g.allowPrivate {
		for _, p := range privatePrefixes {
			if p.Contains(addr) {
				return nil
			}
		}
	}
	for _, p := range blockedPrefixes {
		if p.Contains(addr) {
			return fmt.Errorf("%w: %q is in blocked range %s", ErrURLBlocked, addr, p)
		}
	}
	return nil
}

// isNumericHost reports whether h is composed only of digits and dots — the
// shape of inet_aton legacy IPv4 forms.
func isNumericHost(h string) bool {
	for _, r := range h {
		if (r < '0' || r > '9') && r != '.' {
			return false
		}
	}
	return h != ""
}
