package core

import (
	"fmt"
	"net/url"
	"strings"
)

// NamedURL is one URL surface of a deployment, with the name an operator would
// recognize it by (a config key, or an advertised service-endpoint id).
type NamedURL struct {
	Name string
	URL  string
}

// RequireHTTPSEndpoints reports the URL surfaces that still say http:// while
// the node terminates TLS itself.
//
// It exists because a TLS listener does not rewrite what a node ADVERTISES. A
// node can serve a flawless HTTPS listener and still hand peers http:// in its
// DID service endpoints and its resolution overrides — every peer then fails to
// reach a node that looks perfectly healthy from the inside, which is the
// migration failure mode this returns as text an operator can act on.
//
// It is advisory by design, not fail-closed. An operator mid-migration may
// legitimately run a TLS listener while some peer still reaches an http://
// fronting proxy, and a node that refused to boot there would be a node that
// cannot be migrated incrementally. On a cleartext-acknowledged posture it says
// nothing: http:// is consistent there, and a warning that fires when nothing
// is wrong is a warning operators learn to ignore.
func RequireHTTPSEndpoints(tlsCfg TLSConfig, endpoints []NamedURL) []string {
	if !tlsCfg.ServesTLS() {
		return nil
	}
	var warnings []string
	for _, ep := range endpoints {
		if ep.URL == "" {
			continue
		}
		u, err := url.Parse(ep.URL)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: %q is not a parseable URL", ep.Name, ep.URL))
			continue
		}
		if strings.EqualFold(u.Scheme, "http") {
			warnings = append(warnings, fmt.Sprintf(
				"%s advertises %s over cleartext http while this node serves TLS — peers following it will not reach the TLS listener",
				ep.Name, ep.URL))
		}
	}
	return warnings
}
