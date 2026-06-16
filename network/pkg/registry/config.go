// Package registry is the registry-identity configuration layer: the
// did:dplaax {registry} segment this server is authoritative for, and the
// service endpoints embedded in every issued DID Document. It owns only the
// config contract (its reference.conf + a fail-closed loader); the values feed
// didregistry.New (registry id) and didregistry.WithServiceEndpoints.
package registry

import (
	_ "embed"
	"fmt"
	"net/url"
	"strings"

	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/hoconconfig"
)

//go:embed reference.conf
var referenceConf string

func init() {
	hoconconfig.RegisterPackageReference("network/registry", referenceConf)
}

const (
	keyID        = "provin.network.registry.id"
	keyEndpoints = "provin.network.registry.service-endpoints"
)

// RegistryConfig is the typed registry-identity config.
type RegistryConfig struct {
	// ID is the did:dplaax {registry} segment (e.g. "poc.dplaax.io").
	ID string
	// Endpoints are the service endpoints embedded in issued DID Documents, in
	// deterministic (sorted-by-id) order.
	Endpoints []did.ServiceEndpoint
}

// LoadRegistryConfig reads and validates the registry block. It fails closed:
// an empty/ill-formed registry id, or any malformed service endpoint, is a boot
// error — the values are copied verbatim into every issued DID Document, so a
// bad one would poison all issuance.
func LoadRegistryConfig(cfg *hoconconfig.Config) (*RegistryConfig, error) {
	id, err := cfg.String(keyID)
	if err != nil {
		return nil, fmt.Errorf("registry: config %s: %w", keyID, err)
	}
	if err := validateRegistryID(id); err != nil {
		return nil, fmt.Errorf("registry: config %s: %w", keyID, err)
	}
	eps, err := loadEndpoints(cfg)
	if err != nil {
		return nil, err
	}
	return &RegistryConfig{ID: id, Endpoints: eps}, nil
}

// loadEndpoints reads the id-keyed service-endpoints object. The map key is the
// endpoint id (so duplicates are impossible by construction); each entry must
// carry a non-empty type and an absolute http(s) URL.
func loadEndpoints(cfg *hoconconfig.Config) ([]did.ServiceEndpoint, error) {
	if !cfg.Has(keyEndpoints) {
		return nil, nil
	}
	ids, err := cfg.Keys(keyEndpoints)
	if err != nil {
		return nil, fmt.Errorf("registry: config %s: %w", keyEndpoints, err)
	}
	out := make([]did.ServiceEndpoint, 0, len(ids))
	for _, id := range ids {
		if err := validateEndpointID(id); err != nil {
			return nil, fmt.Errorf("registry: config %s: endpoint id %q: %w", keyEndpoints, id, err)
		}
		base := keyEndpoints + "." + id
		typ, err := cfg.String(base + ".type")
		if err != nil {
			return nil, fmt.Errorf("registry: endpoint %q: %s: %w", id, base+".type", err)
		}
		if strings.TrimSpace(typ) == "" {
			return nil, fmt.Errorf("registry: endpoint %q: type must not be empty", id)
		}
		rawURL, err := cfg.String(base + ".url")
		if err != nil {
			return nil, fmt.Errorf("registry: endpoint %q: %s: %w", id, base+".url", err)
		}
		if err := validateEndpointURL(rawURL); err != nil {
			return nil, fmt.Errorf("registry: endpoint %q: url: %w", id, err)
		}
		out = append(out, did.ServiceEndpoint{ID: id, Type: typ, ServiceEndpoint: rawURL})
	}
	return out, nil
}

// validateRegistryID requires a single, non-empty did:dplaax segment: no ":"
// (the DID delimiter), no path separators / whitespace / NUL, and not a
// traversal token. Dots are allowed (registries are dotted hostnames).
func validateRegistryID(id string) error {
	if id == "" {
		return fmt.Errorf("must not be empty")
	}
	if id == "." || id == ".." {
		return fmt.Errorf("must not be %q", id)
	}
	if strings.ContainsAny(id, ":/\\ \t\r\n\x00") {
		return fmt.Errorf("must be a single did:dplaax segment (no ':' , path separators, or whitespace): %q", id)
	}
	return nil
}

// validateEndpointID requires a non-empty fragment-safe id (it becomes the
// "#<id>" fragment): no "#", no ":" , no path separators or whitespace.
func validateEndpointID(id string) error {
	if id == "" {
		return fmt.Errorf("must not be empty")
	}
	if strings.ContainsAny(id, "#:/\\ \t\r\n\x00") {
		return fmt.Errorf("must be fragment-safe (no '#', ':', path separators, or whitespace)")
	}
	return nil
}

// validateEndpointURL requires an absolute http(s) URL with a host.
func validateEndpointURL(raw string) error {
	if raw == "" {
		return fmt.Errorf("must not be empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("not a valid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("must have an explicit http:// or https:// scheme (got %q)", raw)
	}
	if u.Host == "" {
		return fmt.Errorf("must have a host (got %q)", raw)
	}
	return nil
}
