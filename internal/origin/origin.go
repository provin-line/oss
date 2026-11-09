// Package origin reads and compares URL origins (RFC 6454) in one spelling:
// an http or https scheme and host in lower case (an IP address in its
// canonical form), the port as a decimal number from 1 to 65535 and only when
// it is not the scheme's default, and nothing else. Credentials are shown only to the
// origins an operator names, and this is how a named origin and an endpoint's
// origin are compared.
package origin

import (
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// Parse reads s as an origin an operator names, "scheme://host[:port]", and
// returns it in its one spelling. A path other than "/", a query, a
// fragment, user information, or a scheme other than http or https is an
// error.
func Parse(s string) (string, error) {
	u, err := url.Parse(s)
	if err != nil || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.ForceQuery || strings.Contains(s, "#") {
		return "", fmt.Errorf("%q is not an http(s) origin (scheme://host[:port])", s)
	}
	o, ok := of(u)
	if !ok {
		return "", fmt.Errorf("%q is not an http(s) origin (scheme://host[:port])", s)
	}
	return o, nil
}

// Of returns the origin of endpoint, an http or https URL, in its one
// spelling. An endpoint that is not one, or that carries user information,
// has none.
func Of(endpoint string) (string, bool) {
	u, err := url.Parse(endpoint)
	if err != nil || strings.Contains(endpoint, "#") {
		return "", false
	}
	return of(u)
}

// In reports whether endpoint's origin is one of origins. Each listed value
// is read as Parse reads it, so a value written in another spelling of an
// origin matches it, and a value that is not an origin matches nothing.
func In(endpoint string, origins []string) bool {
	o, ok := Of(endpoint)
	if !ok {
		return false
	}
	for _, listed := range origins {
		if p, err := Parse(listed); err == nil && p == o {
			return true
		}
	}
	return false
}

func of(u *url.URL) (string, bool) {
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" {
		return "", false
	}
	host := u.Hostname()
	for i := 0; i < len(host); i++ {
		// A host outside ASCII is dialed by its IDNA form, which lower-casing
		// does not give (U+0130 lowers to "i"): only ASCII hosts compare.
		if host[i] >= 0x80 {
			return "", false
		}
	}
	host = strings.ToLower(host)
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Zone() != "" {
			return "", false
		}
		host = addr.String()
	} else if strings.Contains(host, ":") {
		return "", false
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	port := 0
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return "", false
		}
		port = n
	}
	switch {
	case port == 0, scheme == "https" && port == 443, scheme == "http" && port == 80:
		return scheme + "://" + host, true
	default:
		return scheme + "://" + host + ":" + strconv.Itoa(port), true
	}
}

// Confine returns a copy of c that follows no redirect, for a request that
// carries a credential: the credential is shown to the origin the request was
// made to, and to no server that origin redirects to (net/http forwards an
// Authorization header to another port or a subdomain).
func Confine(c *http.Client) *http.Client {
	confined := *c
	confined.CheckRedirect = func(req *http.Request, _ []*http.Request) error {
		return fmt.Errorf("origin: a client that shows a credential follows no redirect (to %s)", req.URL.Redacted())
	}
	return &confined
}
