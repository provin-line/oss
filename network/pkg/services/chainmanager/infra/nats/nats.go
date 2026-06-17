// Package nats is the production-shaped infra.Operator: a NATS decentralized-auth
// control-plane that maintains one local NATS account's exports/imports as a
// signed account-claims JWT, so the broker — independently of the peer-layer
// admission (slice-11/12) — enforces cross-account isolation.
//
// One Operator instance represents exactly ONE local account (infra.Operator's
// AddExport takes no account parameter): the publisher node's operator exports its
// output subject; the subscriber node's operator imports a remote subject naming
// the remote account by key. On each actual change the account claims are
// re-encoded under the injected trust-root key and handed to a JWTPublisher; the
// publisher delivers the JWT to where the broker's account resolver reads it.
//
// Key material (the account seed and the trust-root seed) is injected via Config
// and never generated or hardcoded here. This package imports only jwt + nkeys
// (claims + signing); the embedded nats-server and the nats.go client live in the
// isolation e2e (test-only), keeping the production transitive graph free of the
// broker server.
package nats

import (
	"fmt"
	"strings"
	"sync"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"github.com/provin-line/oss/network/pkg/services/chainmanager/infra"
)

// JWTPublisher delivers a signed account JWT to where the broker's account
// resolver reads it (keyed by the account public key). The in-memory
// (MemAccResolver) implementation is a test helper; the production push to a live
// account resolver lands with the prod nats wiring.
type JWTPublisher interface {
	Publish(accountPub, accountJWT string) error
}

// Config configures a nats Operator. Seeds are nkey seeds sourced from
// secrets/config; the code never generates them.
type Config struct {
	// AccountSeed is this local account's nkey seed (its identity; the account
	// JWT subject is its public key).
	AccountSeed string
	// TrustRootSeed is the nkey seed of the signing trust root (the NATS
	// "operator") that signs this account's JWT.
	TrustRootSeed string
	// URL is the nats endpoint advertised to subscribers in connection_info.
	URL string
	// Publisher delivers each re-encoded account JWT to the broker's resolver.
	Publisher JWTPublisher
}

// Operator is the nats account-claims infra.Operator (account-scoped).
type Operator struct {
	accountPub string
	trustRoot  nkeys.KeyPair
	url        string
	publisher  JWTPublisher

	mu     sync.Mutex
	claims *jwt.AccountClaims
}

var _ infra.Operator = (*Operator)(nil)

// New validates the config, derives this account's public key from its seed, and
// returns an Operator with an empty account-claims set. A malformed seed, an
// empty URL, or a nil Publisher is an error (fail-closed).
func New(cfg Config) (*Operator, error) {
	if cfg.Publisher == nil {
		return nil, fmt.Errorf("nats: Config.Publisher is required")
	}
	if cfg.URL == "" {
		return nil, fmt.Errorf("nats: Config.URL is required")
	}
	accKP, err := nkeys.FromSeed([]byte(cfg.AccountSeed))
	if err != nil {
		return nil, fmt.Errorf("nats: account seed: %w", err)
	}
	accPub, err := accKP.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("nats: account public key: %w", err)
	}
	trustRoot, err := nkeys.FromSeed([]byte(cfg.TrustRootSeed))
	if err != nil {
		return nil, fmt.Errorf("nats: trust-root seed: %w", err)
	}
	return &Operator{
		accountPub: accPub,
		trustRoot:  trustRoot,
		url:        cfg.URL,
		publisher:  cfg.Publisher,
		claims:     jwt.NewAccountClaims(accPub),
	}, nil
}

// PublishType names this operator's transport.
func (*Operator) PublishType() string { return "nats" }

// AddExport adds a Stream export for outputSubject (idempotent: a duplicate does
// not re-encode or re-publish) and returns the connection_info the subscriber
// needs to import + connect: subject, this account's public key, the nats URL,
// and publishType. The account key travels — over the wireauth-verified peer
// channel — into the subscriber's AddImport(remoteAccountKey=…).
func (o *Operator) AddExport(outputSubject string) (map[string]string, error) {
	if err := validateSubject(outputSubject); err != nil {
		return nil, err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.exportIndex(outputSubject) < 0 {
		o.claims.Exports = append(o.claims.Exports, &jwt.Export{
			Name:    outputSubject,
			Subject: jwt.Subject(outputSubject),
			Type:    jwt.Stream,
		})
		if err := o.publishLocked(); err != nil {
			return nil, err
		}
	}
	return map[string]string{
		"subject":     outputSubject,
		"account":     o.accountPub,
		"url":         o.url,
		"publishType": "nats",
	}, nil
}

// RemoveExport removes the Stream export for outputSubject. Absent → idempotent
// no-op (no re-publish).
func (o *Operator) RemoveExport(outputSubject string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	idx := o.exportIndex(outputSubject)
	if idx < 0 {
		return nil
	}
	o.claims.Exports = append(o.claims.Exports[:idx], o.claims.Exports[idx+1:]...)
	return o.publishLocked()
}

// AddImport adds a Stream import of remoteSubject from remoteAccountKey, mapped to
// localSubject (idempotent by (remoteSubject, remoteAccountKey) — the NATS import
// identity). A duplicate does not re-encode or re-publish.
func (o *Operator) AddImport(remoteSubject, remoteAccountKey, localSubject string) error {
	if err := validateSubject(remoteSubject); err != nil {
		return err
	}
	if !nkeys.IsValidPublicAccountKey(remoteAccountKey) {
		return fmt.Errorf("nats: invalid remote account key %q", remoteAccountKey)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.importIndex(remoteSubject, remoteAccountKey) < 0 {
		o.claims.Imports = append(o.claims.Imports, &jwt.Import{
			Name:         remoteSubject,
			Subject:      jwt.Subject(remoteSubject),
			Account:      remoteAccountKey,
			LocalSubject: jwt.RenamingSubject(localSubject),
			Type:         jwt.Stream,
		})
		return o.publishLocked()
	}
	return nil
}

// RemoveImport removes the import identified by (remoteSubject, remoteAccountKey).
// Absent → idempotent no-op.
func (o *Operator) RemoveImport(remoteSubject, remoteAccountKey string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	idx := o.importIndex(remoteSubject, remoteAccountKey)
	if idx < 0 {
		return nil
	}
	o.claims.Imports = append(o.claims.Imports[:idx], o.claims.Imports[idx+1:]...)
	return o.publishLocked()
}

// publishLocked re-encodes the current claims under the trust-root key and
// publishes them. Caller holds o.mu.
func (o *Operator) publishLocked() error {
	token, err := o.claims.Encode(o.trustRoot)
	if err != nil {
		return fmt.Errorf("nats: encode account JWT: %w", err)
	}
	if err := o.publisher.Publish(o.accountPub, token); err != nil {
		return fmt.Errorf("nats: publish account JWT: %w", err)
	}
	return nil
}

func (o *Operator) exportIndex(subject string) int {
	for i, e := range o.claims.Exports {
		if string(e.Subject) == subject {
			return i
		}
	}
	return -1
}

func (o *Operator) importIndex(subject, account string) int {
	for i, im := range o.claims.Imports {
		if string(im.Subject) == subject && im.Account == account {
			return i
		}
	}
	return -1
}

// validateSubject rejects an empty subject or one containing whitespace; NATS
// wildcards (* and >) are allowed.
func validateSubject(s string) error {
	if s == "" {
		return fmt.Errorf("nats: empty subject")
	}
	if strings.ContainsAny(s, " \t\r\n") {
		return fmt.Errorf("nats: subject %q contains whitespace", s)
	}
	return nil
}
