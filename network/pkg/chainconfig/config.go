// Package chainconfig is the chain transport configuration layer: it selects the
// pub-sub backend (nats in production, noop in debug builds) and carries the nats
// parameters (endpoint, account/trust-root seeds, resolver directory, node
// identity). It owns only the config contract (its reference.conf + a fail-closed
// loader); the values feed cmd/network's and cmd/pipeline's infra.Operator +
// subscriber wiring. The structural "noop only in a dev build" guarantee lives in the
// build-tagged operator seam, not here — this layer validates shape and reads
// seeds.
package chainconfig

import (
	_ "embed"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	jwt "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"github.com/provin-line/oss/did/dplaax"
	"github.com/provin-line/oss/hoconconfig"
)

//go:embed reference.conf
var referenceConf string

func init() {
	hoconconfig.RegisterPackageReference("network/chain", referenceConf)
}

// Transport values.
const (
	TransportNATS = "nats"
	TransportNoop = "noop"
)

const (
	keyTransport         = "provin.network.chain.transport"
	keyURL               = "provin.network.chain.nats.url"
	keyAccountSeedFile   = "provin.network.chain.nats.account-seed-file"
	keyTrustRootSeedFile = "provin.network.chain.nats.trust-root-seed-file"
	keyResolverDir       = "provin.network.chain.nats.resolver-dir"
	keyNodeDID           = "provin.network.chain.nats.node-did"
	keyResolverBaseURL   = "provin.network.chain.nats.resolver-base-url"
	keyConnectWait       = "provin.network.chain.nats.connect-wait"
	keyRegistryBaseURLs  = "provin.network.chain.nats.registry-base-urls"
	keySysUserJWTFile    = "provin.network.chain.nats.sys-user-jwt-file"
	keySysUserSeedFile   = "provin.network.chain.nats.sys-user-seed-file"
	keyAllowNoop         = "provin.network.chain.dev.allow-noop-transport"

	keyEmitHealthTTL                = "provin.network.chain.emit-health.ttl"
	keyEmitHealthAdvertiseNoReports = "provin.network.chain.emit-health.advertise-without-reports"
)

// Config is the typed chain transport config.
type Config struct {
	// Transport is the selected backend: TransportNATS or TransportNoop.
	Transport string
	// AllowNoopTransport is the dev gate for the noop transport. It only has
	// effect in a dev build; a production build excludes noop structurally.
	AllowNoopTransport bool
	// NATS is populated when Transport == TransportNATS.
	NATS NATSConfig
	// EmitHealth configures the ReportEmitHealth publisher-scoped by-reference
	// advertisement gate (Task 10 D4). Loaded unconditionally (it applies
	// regardless of Transport): cmd/network's emithealth.Store and
	// chainmanager.WithPublisherHealth read it.
	EmitHealth EmitHealthConfig
}

// EmitHealthConfig is the ReportEmitHealth TTL-store / advertisement-policy
// knobs (provin.network.chain.emit-health).
type EmitHealthConfig struct {
	// TTL is how long a ReportEmitHealth report stays fresh before
	// emithealth.Store.State reports it Expired — also the value echoed back
	// as ReportEmitHealthResponse.ttl, so a reporting publisher knows when to
	// re-report. Must be positive.
	TTL time.Duration
	// AdvertiseWithoutReports is whether by-reference is advertised for a
	// publisher this node has NEVER received a report for
	// (emithealth.NeverReported). false (default) is fail-degraded: a
	// report-mode node requires at least one healthy report before
	// advertising by-reference for that publisher.
	AdvertiseWithoutReports bool
}

// NATSConfig holds the nats decentralized-auth parameters.
type NATSConfig struct {
	// URL is the nats endpoint advertised to subscribers.
	URL string
	// AccountSeed / TrustRootSeed are the raw nkey seeds (read from their files,
	// trimmed). AccountSeed is this node's account; TrustRootSeed signs its
	// account JWT.
	AccountSeed   string
	TrustRootSeed string
	// ResolverDir is the directory account-claims JWTs are published to.
	ResolverDir string
	// NodeDID is the subscriber-side signing identity.
	NodeDID string
	// ResolverBaseURL optionally overrides registry -> base URL (empty = default
	// https://{registry}).
	ResolverBaseURL string
	// ConnectWait is the boot budget for the initial broker dial (transport
	// nats.Config.ConnectWait). Zero = strict fail-fast.
	ConnectWait time.Duration
	// RegistryBaseURLs maps a registry id to the base URL its DIDs resolve
	// against. Unmapped registries use the default (https://{registry}).
	// Mutually exclusive with ResolverBaseURL.
	RegistryBaseURLs map[string]string
	// SysUserJWT / SysUserSeed are the system-account user credentials for the
	// live claims push (read from their files, trimmed). Both set → grants
	// pushed to the running broker; both empty → live push disabled (claims
	// reach the broker via the resolver directory only). Setting exactly one
	// is a boot error.
	SysUserJWT  string
	SysUserSeed string
}

// LoadChainConfig reads and validates the chain block. It fails closed: an
// unknown transport, a missing nats parameter, an unreadable or wrong-type seed,
// or a malformed node DID is a boot error naming the key. It does NOT enforce the
// "noop needs a dev build" policy — that is the build-tagged operator seam's job.
func LoadChainConfig(cfg *hoconconfig.Config) (*Config, error) {
	transport, err := cfg.String(keyTransport)
	if err != nil {
		return nil, fmt.Errorf("chain: config %s: %w", keyTransport, err)
	}
	if transport != TransportNATS && transport != TransportNoop {
		return nil, fmt.Errorf("chain: config %s: unknown transport %q (want %q or %q)",
			keyTransport, transport, TransportNATS, TransportNoop)
	}
	allowNoop, err := cfg.Bool(keyAllowNoop)
	if err != nil {
		return nil, fmt.Errorf("chain: config %s: %w", keyAllowNoop, err)
	}
	out := &Config{Transport: transport, AllowNoopTransport: allowNoop}
	if transport == TransportNATS {
		if out.NATS, err = loadNATS(cfg); err != nil {
			return nil, err
		}
	}
	if out.EmitHealth, err = loadEmitHealth(cfg); err != nil {
		return nil, err
	}
	return out, nil
}

// loadEmitHealth reads the emit-health block — applicable regardless of
// Transport, so it is loaded unconditionally rather than nested under the
// nats-only branch above.
func loadEmitHealth(cfg *hoconconfig.Config) (EmitHealthConfig, error) {
	ttl, err := cfg.Duration(keyEmitHealthTTL)
	if err != nil {
		return EmitHealthConfig{}, fmt.Errorf("chain: config %s: %w", keyEmitHealthTTL, err)
	}
	if ttl <= 0 {
		return EmitHealthConfig{}, fmt.Errorf("chain: config %s: must be positive", keyEmitHealthTTL)
	}
	advertiseWithoutReports, err := cfg.Bool(keyEmitHealthAdvertiseNoReports)
	if err != nil {
		return EmitHealthConfig{}, fmt.Errorf("chain: config %s: %w", keyEmitHealthAdvertiseNoReports, err)
	}
	return EmitHealthConfig{TTL: ttl, AdvertiseWithoutReports: advertiseWithoutReports}, nil
}

func loadNATS(cfg *hoconconfig.Config) (NATSConfig, error) {
	var n NATSConfig
	var err error
	if n.URL, err = requireString(cfg, keyURL); err != nil {
		return n, err
	}
	if n.ResolverDir, err = requireString(cfg, keyResolverDir); err != nil {
		return n, err
	}
	if n.NodeDID, err = requireString(cfg, keyNodeDID); err != nil {
		return n, err
	}
	if _, err = dplaax.Parse(n.NodeDID); err != nil {
		return n, fmt.Errorf("chain: config %s: %w", keyNodeDID, err)
	}
	if n.AccountSeed, err = readSeed(cfg, keyAccountSeedFile, false); err != nil {
		return n, err
	}
	if n.TrustRootSeed, err = readSeed(cfg, keyTrustRootSeedFile, true); err != nil {
		return n, err
	}
	// resolver-base-url is optional in MEANING (empty -> didresolver default) but
	// reference.conf always defines the key, so a read error here is a type
	// mismatch (e.g. a number) — fail closed naming the key, not silently ignore it
	// (convergent review: Claude + Codex). NOTE: a non-empty value maps EVERY
	// registry to this one base URL (the override ignores the registry argument),
	// so it is a single-registry / dev-and-single-tenant seam, not a multi-registry
	// mapping; multi-registry deployments leave it empty (default https://{registry}).
	base, err := cfg.String(keyResolverBaseURL)
	if err != nil {
		return n, fmt.Errorf("chain: config %s: %w", keyResolverBaseURL, err)
	}
	n.ResolverBaseURL = base
	wait, err := cfg.Duration(keyConnectWait)
	if err != nil {
		return n, fmt.Errorf("chain: config %s: %w", keyConnectWait, err)
	}
	if wait < 0 {
		return n, fmt.Errorf("chain: config %s: must not be negative", keyConnectWait)
	}
	n.ConnectWait = wait
	urls, err := cfg.StringMap(keyRegistryBaseURLs)
	if err != nil {
		return n, fmt.Errorf("chain: config %s: %w", keyRegistryBaseURLs, err)
	}
	if len(urls) > 0 {
		if n.ResolverBaseURL != "" {
			return n, fmt.Errorf("chain: config %s and %s are mutually exclusive resolution models — set one", keyRegistryBaseURLs, keyResolverBaseURL)
		}
		for reg, raw := range urls {
			// A key that could never come out of dplaax.Parse would silently
			// miss at resolve time and fall back to external resolution — the
			// opposite of the operator's intent. Fail boot instead.
			if !dplaax.IsSafeSegment(reg) {
				return n, fmt.Errorf("chain: config %s: %q is not a valid registry segment", keyRegistryBaseURLs, reg)
			}
			u, err := url.Parse(raw)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				return n, fmt.Errorf("chain: config %s[%q]: %q is not an absolute http(s) URL", keyRegistryBaseURLs, reg, raw)
			}
			// A path prefix composes with the /did/... route; a query or
			// fragment would be glued mid-URL by the resolver and can only be
			// a mistake.
			if u.RawQuery != "" || u.Fragment != "" {
				return n, fmt.Errorf("chain: config %s[%q]: %q must not carry a query or fragment", keyRegistryBaseURLs, reg, raw)
			}
		}
		n.RegistryBaseURLs = urls
	}
	jwtPath, err := cfg.String(keySysUserJWTFile)
	if err != nil {
		return n, fmt.Errorf("chain: config %s: %w", keySysUserJWTFile, err)
	}
	seedPath, err := cfg.String(keySysUserSeedFile)
	if err != nil {
		return n, fmt.Errorf("chain: config %s: %w", keySysUserSeedFile, err)
	}
	switch {
	case jwtPath == "" && seedPath == "":
		// Live push disabled — the pre-slice behavior.
	case jwtPath == "" || seedPath == "":
		return n, fmt.Errorf("chain: config %s and %s must be set together (both for the live claims push, neither to disable it)", keySysUserJWTFile, keySysUserSeedFile)
	default:
		raw, err := os.ReadFile(jwtPath)
		if err != nil {
			return n, fmt.Errorf("chain: config %s: read sys-user JWT file: %w", keySysUserJWTFile, err)
		}
		n.SysUserJWT = strings.TrimSpace(string(raw))
		if n.SysUserJWT == "" {
			return n, fmt.Errorf("chain: config %s: sys-user JWT file is empty", keySysUserJWTFile)
		}
		if n.SysUserSeed, err = readUserSeed(seedPath); err != nil {
			return n, fmt.Errorf("chain: config %s: %w", keySysUserSeedFile, err)
		}
		// The JWT must belong to the seed: mispaired files (mixed provisioning
		// generations) would otherwise fail at the first push — an
		// authorization error 30s into a grant — instead of at boot with the
		// key named. A non-JWT file fails the same way.
		claims, err := jwt.DecodeUserClaims(n.SysUserJWT)
		if err != nil {
			return n, fmt.Errorf("chain: config %s: not a user JWT: %w", keySysUserJWTFile, err)
		}
		kp, _ := nkeys.FromSeed([]byte(n.SysUserSeed))
		pub, err := kp.PublicKey()
		if err != nil {
			return n, fmt.Errorf("chain: config %s: derive public key: %w", keySysUserSeedFile, err)
		}
		if claims.Subject != pub {
			return n, fmt.Errorf("chain: config %s and %s do not pair: JWT subject %q is not the seed's key (mixed provisioning generations?)", keySysUserJWTFile, keySysUserSeedFile, claims.Subject)
		}
	}
	return n, nil
}

// readUserSeed reads and trims a USER nkey seed — a swapped account/operator
// seed fails boot here rather than at the first push.
func readUserSeed(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read seed file: %w", err)
	}
	seed := strings.TrimSpace(string(raw))
	kp, err := nkeys.FromSeed([]byte(seed))
	if err != nil {
		return "", fmt.Errorf("invalid nkey seed: %w", err)
	}
	pub, err := kp.PublicKey()
	if err != nil {
		return "", fmt.Errorf("derive public key: %w", err)
	}
	if !nkeys.IsValidPublicUserKey(pub) {
		return "", errors.New("not a USER nkey seed")
	}
	return seed, nil
}

func requireString(cfg *hoconconfig.Config, key string) (string, error) {
	v, err := cfg.String(key)
	if err != nil {
		return "", fmt.Errorf("chain: config %s: %w", key, err)
	}
	if v == "" {
		return "", fmt.Errorf("chain: config %s: must not be empty", key)
	}
	return v, nil
}

// readSeed reads the seed file named by key, trims surrounding whitespace, and
// validates that the seed is of the expected type (operator vs account) so a
// swapped pair fails boot here rather than at nats.New.
func readSeed(cfg *hoconconfig.Config, key string, operator bool) (string, error) {
	path, err := requireString(cfg, key)
	if err != nil {
		return "", err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("chain: config %s: read seed file: %w", key, err)
	}
	seed := strings.TrimSpace(string(raw))
	kp, err := nkeys.FromSeed([]byte(seed))
	if err != nil {
		return "", fmt.Errorf("chain: config %s: invalid nkey seed: %w", key, err)
	}
	pub, err := kp.PublicKey()
	if err != nil {
		return "", fmt.Errorf("chain: config %s: derive public key: %w", key, err)
	}
	if operator && !nkeys.IsValidPublicOperatorKey(pub) {
		return "", fmt.Errorf("chain: config %s: not an operator seed", key)
	}
	if !operator && !nkeys.IsValidPublicAccountKey(pub) {
		return "", fmt.Errorf("chain: config %s: not an account seed", key)
	}
	return seed, nil
}
