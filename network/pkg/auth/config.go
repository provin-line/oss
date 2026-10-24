package auth

import (
	_ "embed"
	"fmt"
	"strings"

	"github.com/provin-line/oss/hoconconfig"
	"github.com/provin-line/oss/network/pkg/auth/internal/jwtprincipal"
)

//go:embed reference.conf
var referenceConf string

func init() {
	hoconconfig.RegisterPackageReference("network/auth", referenceConf)
}

const (
	keyBackend           = "provin.network.auth.backend"
	keyPolicyVerifierURL = "provin.network.auth.policy-verifier-url"
	keyOPABaseURL        = "provin.network.auth.opa.base-url"
	keyOPAPolicyPath     = "provin.network.auth.opa.policy-path"
	keyCedarBaseURL      = "provin.network.auth.cedar.base-url"
	keyPlainInternal     = "provin.network.auth.plain-internal"

	keyCedarJWTIssuer         = "provin.network.auth.cedar.jwt.issuer"
	keyCedarJWTAudience       = "provin.network.auth.cedar.jwt.audience"
	keyCedarJWTJWKSURL        = "provin.network.auth.cedar.jwt.jwks-url"
	keyCedarJWTSecret         = "provin.network.auth.cedar.jwt.secret"
	keyCedarJWTSecretEncoding = "provin.network.auth.cedar.jwt.secret-encoding"
	keyStaticAllow            = "provin.network.auth.static.allow"
)

// Backend selects where the authorization decision (PDP) is made. Every backend
// is fail-closed: the selected backend's required config must be set or the
// server does not boot. The values name the decision point, not its transport.
type Backend string

const (
	// BackendO3co calls an external o3co auth.policy-verifier over HTTP; it
	// verifies the caller's JWT and decides policy. The default when unset.
	BackendO3co Backend = "o3co"
	// BackendOPA calls an external Open Policy Agent REST endpoint.
	BackendOPA Backend = "opa"
	// BackendCedar calls an external Cedar-agent REST endpoint.
	BackendCedar Backend = "cedar"
	// BackendStatic decides in-process against a configured allow-list. It is
	// NOT authentication — the bearer token is only checked for presence, never
	// verified — so it suits a single-tenant or perimeter-authenticated
	// deployment, never one relying on the PDP to authenticate callers.
	BackendStatic Backend = "static"
)

// OPAConfig configures the opa backend (Open Policy Agent REST).
type OPAConfig struct {
	BaseURL    string
	PolicyPath string
}

// CedarConfig configures the cedar backend (Cedar-agent REST). A Cedar agent
// authenticates nothing, so the backend verifies the caller's bearer JWT itself
// (JWT) and asks the agent about the verified subject.
type CedarConfig struct {
	BaseURL string
	JWT     CedarJWTConfig
}

// CedarJWTConfig configures how the cedar backend verifies the bearer JWT.
// Issuer and Audience are required; exactly one of JWKSURL (https) and Secret
// (HS256, written in SecretEncoding: utf8, hex or base64; empty means utf8)
// supplies the key. The principal is the verified token's sub claim.
type CedarJWTConfig struct {
	Issuer         string
	Audience       string
	JWKSURL        string
	Secret         string
	SecretEncoding string
}

// StaticConfig configures the static backend's in-process allow-list. An empty
// Allow denies everything (the safe default).
type StaticConfig struct {
	Allow []StaticAllowRule
}

// StaticAllowRule is one allow-list entry: a request whose (resource, action)
// matches is permitted. Both fields support exact, "*", or "prefix/*" match.
type StaticAllowRule struct {
	Resource string
	Action   string
}

// AuthConfig is the authorization layer's typed config.
type AuthConfig struct {
	// Backend selects the PDP. Unset defaults to BackendO3co.
	Backend Backend
	// PolicyVerifierURL is the base URL of the auth.policy-verifier PDP
	// (backend = o3co).
	PolicyVerifierURL string
	// PlainInternal lists the "host:port" PDP endpoints that may be called over
	// plaintext http: only a listed endpoint that resolves to a private address
	// is reached. Empty (the default) permits plaintext to loopback only.
	PlainInternal []string
	// OPA, Cedar, and Static carry the params for their respective backends;
	// only the selected backend's block is consulted.
	OPA    OPAConfig
	Cedar  CedarConfig
	Static StaticConfig
}

// LoadAuthConfig reads and validates the auth block from a loaded hocon config.
// It reads every backend's block but validates only the selected backend's
// required config, failing closed: an unknown backend, or a missing/invalid
// required field for the selected backend, is a boot error. A static deployment
// needs no policy-verifier-url; an o3co/opa/cedar deployment needs a valid
// http(s):// endpoint.
func LoadAuthConfig(cfg *hoconconfig.Config) (*AuthConfig, error) {
	ac := &AuthConfig{}
	// Read tolerantly: an empty string under a dotted HOCON key does not
	// materialize (only the non-selected backends' unset defaults), so a missing
	// key means "". validate() supplies the fail-closed check for whichever
	// backend is actually selected.
	for key, dst := range map[string]*string{
		keyBackend:           (*string)(&ac.Backend),
		keyPolicyVerifierURL: &ac.PolicyVerifierURL,
		keyOPABaseURL:        &ac.OPA.BaseURL,
		keyOPAPolicyPath:     &ac.OPA.PolicyPath,
		keyCedarBaseURL:      &ac.Cedar.BaseURL,

		keyCedarJWTIssuer:         &ac.Cedar.JWT.Issuer,
		keyCedarJWTAudience:       &ac.Cedar.JWT.Audience,
		keyCedarJWTJWKSURL:        &ac.Cedar.JWT.JWKSURL,
		keyCedarJWTSecret:         &ac.Cedar.JWT.Secret,
		keyCedarJWTSecretEncoding: &ac.Cedar.JWT.SecretEncoding,
	} {
		v, err := optString(cfg, key)
		if err != nil {
			return nil, fmt.Errorf("auth: config %s: %w", key, err)
		}
		*dst = v
	}
	// Backend defaulting is centralized in validate() (the single source), so a
	// caller who constructs AuthConfig directly and calls NewVerifier gets the
	// same "" -> o3co default the field godoc promises.

	allow, err := cfg.StringList(keyStaticAllow)
	if err != nil {
		return nil, fmt.Errorf("auth: config %s: %w", keyStaticAllow, err)
	}
	for _, entry := range allow {
		rule, err := parseStaticAllow(entry)
		if err != nil {
			return nil, fmt.Errorf("auth: config %s: %w", keyStaticAllow, err)
		}
		ac.Static.Allow = append(ac.Static.Allow, rule)
	}

	plain, err := cfg.StringList(keyPlainInternal)
	if err != nil {
		return nil, fmt.Errorf("auth: config %s: %w", keyPlainInternal, err)
	}
	ac.PlainInternal = plain

	if err := ac.validate(); err != nil {
		return nil, fmt.Errorf("auth: config: %w", err)
	}
	return ac, nil
}

// optString returns the config value at key, or "" when the key is absent (an
// empty-string value under a dotted HOCON key does not materialize).
func optString(cfg *hoconconfig.Config, key string) (string, error) {
	if !cfg.Has(key) {
		return "", nil
	}
	return cfg.String(key)
}

// parseStaticAllow parses a "resource:action" allow entry. The ":" separator is
// unambiguous because dplaax resource and action tokens never contain a colon.
func parseStaticAllow(entry string) (StaticAllowRule, error) {
	resource, action, ok := strings.Cut(entry, ":")
	if !ok || resource == "" || action == "" {
		return StaticAllowRule{}, fmt.Errorf("static allow entry %q must be \"resource:action\"", entry)
	}
	return StaticAllowRule{Resource: resource, Action: action}, nil
}

// validate checks that the selected backend's required config is present and
// well-formed. Fail-closed: an unknown backend, or a missing/invalid required
// field, is an error. static needs nothing (an empty allow-list is deny-all).
// An empty Backend defaults to o3co here (the single source of that default, so
// it holds for both LoadAuthConfig and a directly-constructed AuthConfig).
func (cfg *AuthConfig) validate() error {
	if cfg.Backend == "" {
		cfg.Backend = BackendO3co
	}
	switch cfg.Backend {
	case BackendO3co:
		if err := validateVerifierURL(cfg.PolicyVerifierURL); err != nil {
			return fmt.Errorf("o3co policy-verifier-url: %w", err)
		}
	case BackendOPA:
		if err := validateVerifierURL(cfg.OPA.BaseURL); err != nil {
			return fmt.Errorf("opa base-url: %w", err)
		}
		if cfg.OPA.PolicyPath == "" {
			// Required by upstream NewOPAEndpoint; check it here so the boot
			// error carries config-key context instead of a bare upstream string.
			return fmt.Errorf("opa policy-path: must not be empty")
		}
	case BackendCedar:
		if err := validateVerifierURL(cfg.Cedar.BaseURL); err != nil {
			return fmt.Errorf("cedar base-url: %w", err)
		}
		if _, err := cfg.Cedar.JWT.resolver(); err != nil {
			return err
		}
	case BackendStatic:
		// no required field; an empty allow-list denies everything (safe).
	default:
		return fmt.Errorf("unknown backend %q (want o3co|opa|cedar|static)", cfg.Backend)
	}
	return nil
}

// resolver builds the principal resolver the cedar backend authenticates with.
// Its errors name the provin.network.auth.cedar.jwt keys.
func (c CedarJWTConfig) resolver() (jwtprincipal.Resolver, error) {
	r, err := jwtprincipal.New(jwtprincipal.Config{
		Issuer:         c.Issuer,
		Audience:       c.Audience,
		JWKSURL:        c.JWKSURL,
		Secret:         c.Secret,
		SecretEncoding: c.SecretEncoding,
	})
	if err != nil {
		return nil, fmt.Errorf("cedar jwt (provin.network.auth.cedar.jwt.*): %w", err)
	}
	return r, nil
}
