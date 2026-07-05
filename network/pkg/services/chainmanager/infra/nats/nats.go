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
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"github.com/provin-line/oss/network/pkg/services/chainmanager/infra"
)

// ErrNotPublished is returned by JWTPublisher.Load when no account JWT has been
// published yet for the account — the first-boot case, distinct from an I/O error.
var ErrNotPublished = errors.New("nats: account not yet published")

// JWTPublisher delivers a signed account JWT to where the broker's account
// resolver reads it (keyed by the account public key), and reads it back. The
// in-memory (MemAccResolver) implementation is a test helper; the production
// DirPublisher writes/reads the directory the resolver loads from.
//
// Load is the symmetric read of Publish — it lets the operator rehydrate its
// in-memory claims on restart so removals work and re-publishes do not drop prior
// grants. It returns ErrNotPublished when nothing has been published yet (first
// boot). NOTE (slice-16 D-x2): adding Load to this exported interface is
// source-breaking for any external implementer; all in-repo implementers are
// updated, and the package is pre-1.0.
type JWTPublisher interface {
	Publish(accountPub, accountJWT string) error
	Load(accountPub string) (accountJWT string, err error)
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
	if u, err := url.Parse(cfg.URL); err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("nats: Config.URL %q is not a valid URL (need scheme://host)", cfg.URL)
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
	o := &Operator{
		accountPub: accPub,
		trustRoot:  trustRoot,
		url:        cfg.URL,
		publisher:  cfg.Publisher,
		claims:     jwt.NewAccountClaims(accPub),
	}
	if err := o.hydrate(); err != nil {
		return nil, err
	}
	return o, nil
}

// hydrate rebuilds the in-memory claims from the previously published account JWT
// (slice-16 D-x1), so a restarted operator resumes with its full grant set —
// otherwise a Remove would no-op and the next Add would re-publish a JWT carrying
// only the new grant, dropping prior grants. ErrNotPublished is first boot (fresh
// claims).
//
// It fails closed on anything it would not itself have produced — dropping grants
// silently, or laundering an untrusted file into an authorized grant on the next
// re-sign, are both worse than refusing to start. DecodeAccountClaims verifies the
// token's own signature; we additionally require (a) the subject is this account
// and (b) the issuer is THIS trust root (security: a JWT signed by a different
// operator, or a stale/foreign resolver file, must not be absorbed and re-signed —
// Codex review). Standard claim validation (expiry / not-before / structure) must
// also pass. A deliberate trust-root rotation that leaves an old-issuer file is a
// one-time operator chore (clear or re-publish), correctly surfaced as a boot
// error rather than silently laundered.
func (o *Operator) hydrate() error {
	token, err := o.publisher.Load(o.accountPub)
	if errors.Is(err, ErrNotPublished) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("nats: load published claims for %s: %w", o.accountPub, err)
	}
	ac, err := jwt.DecodeAccountClaims(token)
	if err != nil {
		return fmt.Errorf("nats: decode published claims for %s: %w", o.accountPub, err)
	}
	if ac.Subject != o.accountPub {
		return fmt.Errorf("nats: published claims subject %q does not match account %q", ac.Subject, o.accountPub)
	}
	trustRootPub, err := o.trustRoot.PublicKey()
	if err != nil {
		return fmt.Errorf("nats: trust-root public key: %w", err)
	}
	if ac.Issuer != trustRootPub {
		return fmt.Errorf("nats: published claims issuer %q is not this trust root %q (untrusted/stale resolver file)", ac.Issuer, trustRootPub)
	}
	vr := jwt.CreateValidationResults()
	ac.Validate(vr)
	if vr.IsBlocking(true) {
		return fmt.Errorf("nats: published claims for %s failed validation: %v", o.accountPub, vr.Errors())
	}
	o.claims.Exports = ac.Exports
	o.claims.Imports = ac.Imports
	return nil
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
			// Roll back the uncommitted mutation: the resolver may not have the
			// JWT, so leaving the in-memory export would make a retry no-op
			// (idempotency skip) and never re-publish. Dropping it lets the retry
			// re-attempt and converge.
			o.claims.Exports = o.claims.Exports[:len(o.claims.Exports)-1]
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
	removed := o.claims.Exports[idx]
	o.claims.Exports = append(o.claims.Exports[:idx], o.claims.Exports[idx+1:]...)
	if err := o.publishLocked(); err != nil {
		// Roll back so a retry re-removes + re-publishes rather than no-op'ing on
		// an absent entry while the broker still holds the stale grant.
		o.claims.Exports = append(o.claims.Exports, removed)
		return err
	}
	return nil
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
		if err := o.publishLocked(); err != nil {
			o.claims.Imports = o.claims.Imports[:len(o.claims.Imports)-1] // roll back (see AddExport)
			return err
		}
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
	removed := o.claims.Imports[idx]
	o.claims.Imports = append(o.claims.Imports[:idx], o.claims.Imports[idx+1:]...)
	if err := o.publishLocked(); err != nil {
		o.claims.Imports = append(o.claims.Imports, removed) // roll back (see RemoveExport)
		return err
	}
	return nil
}

// publishLocked re-encodes the current claims under the trust-root key and
// publishes them. Caller holds o.mu.
// PublishClaims signs and publishes the account's CURRENT claims, mutation or
// not. Provisioning uses it to make a freshly-created account resolvable (and
// therefore connectable) before any grant exists — account JWTs are otherwise
// written only when a grant mutates the claims, leaving a bare account unable
// to connect.
func (o *Operator) PublishClaims() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.publishLocked()
}

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

// validateSubject rejects an empty subject, one containing whitespace, or one
// with an empty token (leading/trailing/doubled dot, e.g. ".a", "a.", "a..b") —
// all structurally invalid NATS subjects that jwt does not catch at encode time
// and that would surface only as silent non-delivery at the broker. NATS
// wildcards (* and >) are allowed.
func validateSubject(s string) error {
	if s == "" {
		return fmt.Errorf("nats: empty subject")
	}
	if strings.ContainsAny(s, " \t\r\n") {
		return fmt.Errorf("nats: subject %q contains whitespace", s)
	}
	for _, tok := range strings.Split(s, ".") {
		if tok == "" {
			return fmt.Errorf("nats: subject %q has an empty token", s)
		}
	}
	return nil
}
