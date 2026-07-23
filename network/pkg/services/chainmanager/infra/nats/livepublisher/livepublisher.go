// Package livepublisher pushes account claims to the RUNNING broker over the
// system-account API, so a grant issued to a live stack takes effect without
// a broker restart. It decorates an inner JWTPublisher (the durable store):
// durability first, then liveness — and on a failed push it compensates the
// durable store back to the previous JWT, keeping the file consistent with
// the operator's rolled-back in-memory claims.
//
// Wiring requirement (load-bearing): the inner durable store must be the
// broker's authoritative next-lookup source (the quickstart runs the broker's
// directory resolver over the same directory the DirPublisher writes).
// That is what makes a non-error response for an account nobody is currently
// connected under ("jwt update skipped" from a memory resolver) safe to
// accept: an unloaded account has no live clients to update, and its next
// first-lookup serves the durable JWT. If the broker's lookup source were a
// stale snapshot instead, accepting that response would silently re-open the
// no-flow gap this package exists to close.
//
// Concurrency contract: Publish's snapshot → write → push → compensate
// sequence is NOT internally synchronized; it is safe because the operator
// serializes every claims mutation and publish under its own mutex. A future
// caller invoking Publish concurrently for the SAME account could compensate
// with a stale snapshot — keep external serialization per account.
//
// This package deliberately lives OUTSIDE infra/nats: it needs the nats.go
// client, which infra/nats's production graph forbids (D-n7) — this is the
// one place cmd/network's production graph picks up that dependency
// (cmd/pipeline needs it independently, for its own data-plane transport).
// The nats-server stays out (see the deps guard).
package livepublisher

import (
	"errors"
	"fmt"
	"time"

	natsclient "github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	"github.com/provin-line/oss/canon"
	natsop "github.com/provin-line/oss/network/pkg/services/chainmanager/infra/nats"
)

// redialWait is the pause between dial attempts inside the deadline budget.
const redialWait = 250 * time.Millisecond

// failFastCap bounds each operation of a zero-timeout (fail-fast) push: one
// dial attempt and one request, each at most this long — mirroring the chain
// config's "connect-wait = 0s means strict fail-fast" semantic.
const failFastCap = 2 * time.Second

// retryBudget bounds the single post-failure retry that converges an
// applied-but-reply-lost update to a definitive outcome (CLAIMS.UPDATE is
// idempotent). The total worst case per publish is therefore
// timeout + retryBudget.
const retryBudget = 2 * time.Second

// Config configures a live claims publisher.
type Config struct {
	// URL is the broker endpoint (the same value the data plane dials).
	URL string
	// SysUserJWT / SysUserSeed are the system-account user credentials the
	// push authenticates with. Provisioning narrows this user to publishing
	// exactly this node's claims-update subject.
	SysUserJWT  string
	SysUserSeed string
	// Timeout is the TOTAL budget for one push: one absolute deadline spans
	// every dial attempt and the request. Zero is FAIL-FAST — one immediate
	// dial attempt and one request, mirroring the chain config's
	// connect-wait = 0s semantic (cmd/network's wiring, netcompose's
	// natsOperator, passes connect-wait through verbatim).
	Timeout time.Duration
}

// Publisher is a JWTPublisher decorator adding the live push. Construct with
// New.
type Publisher struct {
	inner   natsop.JWTPublisher
	url     string
	jwt     string
	seed    string
	timeout time.Duration
}

var _ natsop.JWTPublisher = (*Publisher)(nil)

// New validates cfg and returns a Publisher wrapping inner.
func New(inner natsop.JWTPublisher, cfg Config) (*Publisher, error) {
	if inner == nil {
		return nil, errors.New("livepublisher: nil inner publisher")
	}
	if cfg.URL == "" {
		return nil, errors.New("livepublisher: empty broker URL")
	}
	if cfg.SysUserJWT == "" || cfg.SysUserSeed == "" {
		return nil, errors.New("livepublisher: system-account user JWT and seed are both required")
	}
	kp, err := nkeys.FromSeed([]byte(cfg.SysUserSeed))
	if err != nil {
		return nil, fmt.Errorf("livepublisher: sys user seed: %w", err)
	}
	if pub, err := kp.PublicKey(); err != nil || !nkeys.IsValidPublicUserKey(pub) {
		return nil, errors.New("livepublisher: sys user seed is not a USER nkey seed")
	}
	if cfg.Timeout < 0 {
		return nil, errors.New("livepublisher: negative timeout")
	}
	return &Publisher{
		inner: inner, url: cfg.URL,
		jwt: cfg.SysUserJWT, seed: cfg.SysUserSeed,
		timeout: cfg.Timeout,
	}, nil
}

// Publish stores accountJWT durably via the inner publisher, then pushes it
// to the running broker ($SYS.REQ.ACCOUNT.<accountPub>.CLAIMS.UPDATE). The
// durable write comes first so a fresh account stays resolvable even when the
// broker never comes up (the boot path). If the push fails, the previous
// durable JWT is restored before the error returns — the caller (the
// operator) rolls back its in-memory claims on error, and the file must not
// stay ahead of them: a restart would otherwise hydrate a grant whose RPC
// reported failure. A grant is therefore not acknowledged until it is live
// (or the broker confirmed there is no one to update) — loud by design; the
// deployment runbook's manual push remains the fallback.
func (p *Publisher) Publish(accountPub, accountJWT string) error {
	prev, prevErr := p.inner.Load(accountPub)
	hasPrev := prevErr == nil
	if prevErr != nil && !errors.Is(prevErr, natsop.ErrNotPublished) {
		return fmt.Errorf("livepublisher: snapshot previous JWT: %w", prevErr)
	}
	if err := p.inner.Publish(accountPub, accountJWT); err != nil {
		return err
	}
	if err := p.push(accountPub, accountJWT, p.timeout); err != nil {
		// A TRANSPORT-class failure is ambiguous: the broker may have APPLIED
		// the update and only the reply was lost. Because CLAIMS.UPDATE is
		// idempotent, ONE retry within a small extra budget converges that
		// case to a definitive answer. A decoded rejection is never retried —
		// the broker answered, the outcome is unambiguous. (A lookup-based
		// reconcile would be a tautology in the recommended wiring: the
		// directory resolver's LOOKUP serves the very file the inner publisher
		// wrote before the push.) Fail-fast mode (zero timeout) skips the
		// retry: it trades this convergence for latency by contract.
		if !errors.Is(err, errRejected) && p.timeout > 0 {
			if retryErr := p.push(accountPub, accountJWT, retryBudget); retryErr == nil {
				return nil
			}
		}
		if hasPrev {
			if restoreErr := p.inner.Publish(accountPub, prev); restoreErr != nil {
				return fmt.Errorf("livepublisher: push failed (%w) AND restoring the previous durable JWT failed (%v) — durable state is ahead of the operator's claims until a retry succeeds", err, restoreErr)
			}
			return err
		}
		// No previous JWT to restore. cmd/network's wiring (netcompose's
		// natsOperator) publishes at boot before any grant exists, so the
		// expected first publish carries no grant delta to diverge over;
		// reaching this with a MUTATION means the durable JWT vanished mid-run
		// (an ops fault) — say exactly what state the failure leaves behind.
		return fmt.Errorf("livepublisher: push failed with no previous JWT to restore (%w) — the durable store now holds the unacknowledged claims; retry the operation, or remove %s.jwt and re-run boot publish to reset", err, accountPub)
	}
	return nil
}

// errRejected marks a push the broker DECODED AND ANSWERED negatively — an
// unambiguous outcome that must never be retried or reconciled away, as
// opposed to a transport-class failure where the reply may merely be lost.
var errRejected = errors.New("broker rejected the claims update")

// Load delegates to the inner (durable) publisher.
func (p *Publisher) Load(accountPub string) (string, error) {
	return p.inner.Load(accountPub)
}

// claimUpdateResponse mirrors the server's ServerAPIClaimUpdateResponse. The
// server field is carried but unused (ServerInfo metadata).
type claimUpdateResponse struct {
	Server any                `json:"server"`
	Data   *claimUpdateStatus `json:"data"`
	Error  *claimUpdateError  `json:"error"`
}

type claimUpdateStatus struct {
	Account string `json:"account"`
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type claimUpdateError struct {
	Account     string `json:"account"`
	Code        int    `json:"code"`
	Description string `json:"description"`
}

// acceptedMessages are the server outcomes that mean the durable JWT is (or
// will be at next lookup) what the broker serves. "jwt updated": a loaded
// account was updated live, or a directory resolver saved the JWT. "jwt
// update skipped": a memory resolver had no loaded account to update — safe
// exactly under the package-doc wiring requirement.
var acceptedMessages = map[string]bool{"jwt updated": true, "jwt update skipped": true}

// push dials the broker as the system user and requests the per-account
// claims update, all under one absolute deadline (or one fail-fast attempt
// when budget is zero). The per-account subject is used (not
// $SYS.REQ.CLAIMS.UPDATE) because every resolver type serves it; the global
// subject has no responder under a memory resolver.
//
// Error classification is load-bearing for the caller's retry decision:
// every failure AFTER a reply arrived wraps errRejected (the broker answered;
// the outcome is final), while dial/request failures do not (the reply may
// merely be lost).
func (p *Publisher) push(accountPub, accountJWT string, budget time.Duration) error {
	var nc *natsclient.Conn
	var err error
	requestBudget := failFastCap
	if budget == 0 {
		nc, err = p.dialOnce(failFastCap)
	} else {
		deadline := time.Now().Add(budget)
		nc, err = p.dial(deadline, budget)
		if err == nil {
			requestBudget = time.Until(deadline)
			if requestBudget <= 0 {
				nc.Close()
				return fmt.Errorf("livepublisher: push budget %s exhausted before the request", budget)
			}
		}
	}
	if err != nil {
		return err
	}
	defer nc.Close()

	msg, err := nc.Request("$SYS.REQ.ACCOUNT."+accountPub+".CLAIMS.UPDATE", []byte(accountJWT), requestBudget)
	if err != nil {
		return fmt.Errorf("livepublisher: claims-update request: %w", err)
	}

	var resp claimUpdateResponse
	if err := canon.NewStrictDecoder(msg.Data).Decode(&resp); err != nil {
		return fmt.Errorf("livepublisher: %w: undecodable response: %v", errRejected, err)
	}
	switch {
	case resp.Error != nil && resp.Data != nil:
		return fmt.Errorf("livepublisher: %w: response carries both data and error", errRejected)
	case resp.Error != nil:
		return fmt.Errorf("livepublisher: %w: %s (code %d)", errRejected, resp.Error.Description, resp.Error.Code)
	case resp.Data == nil:
		return fmt.Errorf("livepublisher: %w: response carries neither data nor error", errRejected)
	case resp.Data.Code != 200:
		return fmt.Errorf("livepublisher: %w: code %d (%s)", errRejected, resp.Data.Code, resp.Data.Message)
	case resp.Data.Account != accountPub:
		return fmt.Errorf("livepublisher: %w: acknowledged account %q, want %q", errRejected, resp.Data.Account, accountPub)
	case !acceptedMessages[resp.Data.Message]:
		return fmt.Errorf("livepublisher: %w: unexpected outcome %q", errRejected, resp.Data.Message)
	}
	return nil
}

// dial connects as the system user, retrying inside the absolute deadline
// (the broker may still be starting at node boot). Each attempt gets only the
// remaining budget; RetryOnFailedConnect is deliberately not used — it can
// hand back a RECONNECTING connection whose requests buffer past the budget.
// An authorization failure aborts immediately: retrying mispaired credentials
// can only burn the budget on the same answer.
func (p *Publisher) dial(deadline time.Time, budget time.Duration) (*natsclient.Conn, error) {
	var lastErr error
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, fmt.Errorf("livepublisher: broker unreachable within %s: %w", budget, lastErr)
		}
		nc, err := p.dialOnce(remaining)
		if err == nil {
			return nc, nil
		}
		if errors.Is(err, natsclient.ErrAuthorization) {
			return nil, fmt.Errorf("livepublisher: broker refused the system-user credentials: %w", err)
		}
		lastErr = err
		wait := redialWait
		if until := time.Until(deadline); until < wait {
			wait = until
		}
		if wait > 0 {
			time.Sleep(wait)
		}
	}
}

// dialOnce makes a single connection attempt bounded by budget.
func (p *Publisher) dialOnce(budget time.Duration) (*natsclient.Conn, error) {
	return natsclient.Connect(p.url,
		natsclient.UserJWTAndSeed(p.jwt, p.seed),
		natsclient.Timeout(budget),
		natsclient.RetryOnFailedConnect(false),
		natsclient.MaxReconnects(0),
	)
}
