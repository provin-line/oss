package auth

import (
	_ "embed"
	"fmt"

	"github.com/provin-line/oss/hoconconfig"
)

//go:embed reference.conf
var referenceConf string

func init() {
	hoconconfig.RegisterPackageReference("network/auth", referenceConf)
}

const keyPolicyVerifierURL = "provin.network.auth.policy-verifier-url"

// AuthConfig is the authorization layer's typed config.
type AuthConfig struct {
	// PolicyVerifierURL is the base URL of the auth.policy-verifier PDP.
	PolicyVerifierURL string
}

// LoadAuthConfig reads and validates the auth block from a loaded hocon config.
// It fails closed: an empty or scheme-less policy-verifier URL is a boot error,
// so the server cannot run authorization against an unset/ambiguous endpoint.
func LoadAuthConfig(cfg *hoconconfig.Config) (*AuthConfig, error) {
	rawURL, err := cfg.String(keyPolicyVerifierURL)
	if err != nil {
		return nil, fmt.Errorf("auth: config %s: %w", keyPolicyVerifierURL, err)
	}
	if err := validateVerifierURL(rawURL); err != nil {
		return nil, fmt.Errorf("auth: config %s: %w", keyPolicyVerifierURL, err)
	}
	return &AuthConfig{PolicyVerifierURL: rawURL}, nil
}
