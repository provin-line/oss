// Package chainconfig is the chain transport configuration layer: it selects the
// pub-sub backend (nats in production, noop in debug builds) and carries the nats
// parameters (endpoint, account/trust-root seeds, resolver directory, node
// identity). It owns only the config contract (its reference.conf + a fail-closed
// loader); the values feed the standalone mount's infra.Operator + subscriber
// wiring. The structural "noop only in a dev build" guarantee lives in the
// build-tagged operator seam, not here — this layer validates shape and reads
// seeds.
package chainconfig

import (
	_ "embed"
	"fmt"
	"os"
	"strings"
	"time"

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
	keyAllowNoop         = "provin.network.chain.dev.allow-noop-transport"
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
	return out, nil
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
	return n, nil
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
