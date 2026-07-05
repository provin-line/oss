// Package nats is the production NATS backend for the pipeline transport boundary:
// it implements transport.Publisher and transport.Subscriber over the nats.go client.
// It is the OSS-default messaging backend named by the transport package doc; a
// deployment swaps it for SQS/SNS etc. without touching pipeline process logic.
//
// A Conn owns one authenticated connection established as the node's NATS *account*:
// Connect mints an ephemeral user JWT signed by the account key and dials with it
// (the production form of the slice-16 capstone's natsClient helper). Publisher and
// Subscriber are per-subject views that share that one connection — a node runs many
// pipeline loops over one account connection, so connection teardown is owned by
// Conn.Close(), never by a per-subject Publisher.Close().
//
// This package imports the nats.go client in production (the intended introduction
// of nats.go into the production import graph). It must NOT import the embedded
// nats-server, which is a test-only harness (see deps_guard_test.go).
package nats

import (
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/nats-io/jwt/v2"
	natsclient "github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	"github.com/provin-line/oss/pipeline/transport"
)

const (
	// flushTimeout bounds the flush round-trip in Publish and Publisher.Close. It
	// caps how long a Publish blocks confirming broker receipt during an outage
	// before reporting the message undelivered.
	flushTimeout = 5 * time.Second
	// drainTimeout bounds Subscriber.Drain's wait for in-flight handlers to finish.
	drainTimeout = 30 * time.Second
)

// ErrAlreadySubscribed is returned by Subscriber.Subscribe when the subscriber
// already holds a subscription (one Subscriber = one subscription).
var ErrAlreadySubscribed = errors.New("nats: subscriber already has a subscription")

// Config configures a Conn. URL and AccountSeed are required and validated at
// Connect.
type Config struct {
	// URL is the nats:// server URL (scheme + host required).
	URL string
	// AccountSeed is the node's NATS account nkey seed. Ephemeral user JWTs are
	// minted from it; it is never persisted by this package. It must be an account
	// seed (not an operator or user seed).
	AccountSeed string
	// ConnectWait is the boot budget for the initial dial: Connect retries a
	// failed dial with backoff until it succeeds or the budget elapses, then
	// fails closed. Zero preserves the strict fail-fast contract (one attempt).
	// This covers orchestrated deployments where the broker and the node start
	// concurrently. LOCAL validation failures (malformed URL, non-account seed)
	// precede the budget and fail immediately; server-side rejections —
	// including authorization failures — ARE retried, because at boot they are
	// indistinguishable from a broker whose account resolver has not received
	// this account's JWT yet.
	ConnectWait time.Duration
}

// Conn owns one authenticated nats.go connection established as a NATS account.
// Construct with Connect. Conn.Close owns connection teardown.
type Conn struct {
	nc *natsclient.Conn
}

// Connect validates cfg, mints an ephemeral user JWT signed by the configured
// account, and dials the server as that account. Construction is fail-closed: an
// invalid URL or a seed that is not a valid account seed is an error, before any dial.
func Connect(cfg Config) (*Conn, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("nats: invalid URL %q: %w", cfg.URL, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("nats: URL %q must have scheme and host", cfg.URL)
	}

	accKP, err := nkeys.FromSeed([]byte(cfg.AccountSeed))
	if err != nil {
		return nil, fmt.Errorf("nats: invalid account seed: %w", err)
	}
	accPub, err := accKP.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("nats: account public key: %w", err)
	}
	if !nkeys.IsValidPublicAccountKey(accPub) {
		return nil, fmt.Errorf("nats: seed is not an account seed (public key %q)", accPub)
	}

	// Mint an ephemeral user identity under the account. The user nkey lives only
	// for this connection's lifetime; only the account seed is configured input.
	userKP, err := nkeys.CreateUser()
	if err != nil {
		return nil, fmt.Errorf("nats: create user key: %w", err)
	}
	userPub, err := userKP.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("nats: user public key: %w", err)
	}
	userSeed, err := userKP.Seed()
	if err != nil {
		return nil, fmt.Errorf("nats: user seed: %w", err)
	}
	ujwt, err := jwt.NewUserClaims(userPub).Encode(accKP)
	if err != nil {
		return nil, fmt.Errorf("nats: encode user JWT: %w", err)
	}

	// The budget clock starts before the FIRST attempt, and every attempt's
	// dial timeout is capped to the remaining budget, so ConnectWait is a hard
	// bound (modulo scheduler noise) rather than merely bounding when the last
	// attempt may start.
	deadline := time.Now().Add(cfg.ConnectWait)
	dial := func() (*natsclient.Conn, error) {
		opts := []natsclient.Option{
			natsclient.UserJWTAndSeed(ujwt, string(userSeed)),
			natsclient.Name("provin-pipeline"),
		}
		if cfg.ConnectWait > 0 {
			timeout := natsclient.DefaultTimeout
			if remaining := time.Until(deadline); remaining < timeout {
				timeout = remaining
			}
			if timeout <= 0 {
				timeout = time.Millisecond
			}
			opts = append(opts, natsclient.Timeout(timeout))
		}
		return natsclient.Connect(cfg.URL, opts...)
	}
	nc, err := dial()
	retried := false
	if err != nil && cfg.ConnectWait > 0 {
		// Boot-budget retry: back off 250ms → 2s until the budget elapses.
		// Every connect error is retried — at boot an authorization failure is
		// indistinguishable from an account JWT the resolver has not received
		// yet (see Config.ConnectWait).
		retried = true
		backoff := 250 * time.Millisecond
		for time.Now().Before(deadline) {
			sleep := backoff
			if remaining := time.Until(deadline); sleep > remaining {
				sleep = remaining
			}
			time.Sleep(sleep)
			if backoff < 2*time.Second {
				backoff *= 2
			}
			if nc, err = dial(); err == nil {
				break
			}
		}
	}
	if err != nil {
		if retried {
			return nil, fmt.Errorf("nats: connect (retried for %s): %w", cfg.ConnectWait, err)
		}
		return nil, fmt.Errorf("nats: connect: %w", err)
	}
	return &Conn{nc: nc}, nil
}

// Publisher returns a per-subject publisher over this connection.
func (c *Conn) Publisher(subject string) *Publisher {
	return &Publisher{nc: c.nc, subject: subject}
}

// Subscriber returns a per-subject subscriber over this connection.
func (c *Conn) Subscriber(subject string) *Subscriber {
	return &Subscriber{nc: c.nc, subject: subject}
}

// Close tears down the underlying connection. It owns connection lifecycle for all
// Publishers and Subscribers derived from this Conn.
func (c *Conn) Close() error {
	c.nc.Close()
	return nil
}

// Publisher publishes to one subject over a shared connection.
type Publisher struct {
	nc      *natsclient.Conn
	subject string
}

var _ transport.Publisher = (*Publisher)(nil)

// Publish sends data on the publisher's subject and flushes, returning only after
// the server has acknowledged receipt (the PONG to the post-publish PING implies the
// server processed and routed the PUB). nats.go Publish alone merely buffers the PUB
// and returns nil, so a message lost during an outage / failed reconnect would be
// reported as sent; the Loop then advances its sequence and records an emission for a
// message that never reached the broker. Flushing makes the delivery status honest
// (the data-plane audit thesis), at the cost of one round-trip per publish.
//
// Residual: core NATS is at-most-once — this confirms broker *receipt*, not durable
// storage or subscriber delivery. Exactly-once / durable delivery is JetStream, a
// follow-up.
func (p *Publisher) Publish(data []byte) error {
	if err := p.nc.Publish(p.subject, data); err != nil {
		return err
	}
	return p.nc.FlushTimeout(flushTimeout)
}

// Healthy reports whether the shared connection can serve traffic.
func (p *Publisher) Healthy() bool {
	return p.nc.IsConnected()
}

// Close flushes pending publishes so buffered messages reach the server, but does
// NOT close the shared connection — sibling Publishers/Subscribers on the same Conn
// keep using it. Connection teardown is Conn.Close's responsibility. Closing the
// connection here would tear down every sibling loop's transport (D-17a-3). If the
// connection is already closed (Conn.Close ran first) there is nothing to flush.
func (p *Publisher) Close() error {
	if p.nc.IsClosed() {
		return nil
	}
	return p.nc.FlushTimeout(flushTimeout)
}

// Subscriber consumes from one subject over a shared connection.
type Subscriber struct {
	nc      *natsclient.Conn
	subject string
	sub     *natsclient.Subscription
}

var _ transport.Subscriber = (*Subscriber)(nil)

// Subscribe registers an async handler for the subject and confirms the subscription
// with the server (Flush) before returning. A second call is an error: one
// Subscriber holds one subscription. The handler is invoked sequentially per
// subscription (nats.go runs one dispatcher goroutine per async subscription); this
// package adds no concurrency on the delivery path, preserving the ordering the
// transport.Loop sequence discipline relies on (D-17a-8).
func (s *Subscriber) Subscribe(handler func(data []byte)) error {
	if s.sub != nil {
		return ErrAlreadySubscribed
	}
	sub, err := s.nc.Subscribe(s.subject, func(m *natsclient.Msg) {
		handler(m.Data)
	})
	if err != nil {
		return fmt.Errorf("nats: subscribe %q: %w", s.subject, err)
	}
	// Round-trip to the server so the subscription is confirmed before returning.
	if err := s.nc.Flush(); err != nil {
		_ = sub.Unsubscribe()
		return fmt.Errorf("nats: confirm subscription %q: %w", s.subject, err)
	}
	s.sub = sub
	return nil
}

// Drain stops delivery after in-flight handlers complete. nats.go
// Subscription.Drain() only *initiates* drain (the wait runs on a background
// goroutine and the call returns before the in-flight handler finishes), so this
// blocks until the subscription reaches the Closed state — which nats.go transitions
// to only after pending messages, including the in-flight callback, have been
// processed (D-17a-5). A direct passthrough of Subscription.Drain() would let a
// caller tear down transport while a handler is still running.
func (s *Subscriber) Drain() error {
	if s.sub == nil {
		return nil
	}
	closed := s.sub.StatusChanged(natsclient.SubscriptionClosed)
	if err := s.sub.Drain(); err != nil {
		return fmt.Errorf("nats: drain %q: %w", s.subject, err)
	}
	select {
	case <-closed:
		return nil
	case <-time.After(drainTimeout):
		return fmt.Errorf("nats: drain %q timed out after %s", s.subject, drainTimeout)
	}
}
