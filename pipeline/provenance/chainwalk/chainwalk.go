// Package chainwalk implements provenance.ChainVerifier by walking a
// credential chain from its head: it resolves each previousCredential by
// content address, assembles the chain origin-first, and delegates the
// per-credential and chain-structure verification to an injected core
// (vc.Verifier.VerifyChain semantics).
//
// # Division of labour
//
// This package owns ASSEMBLY only — content-address resolution, cycle and
// depth guards, and ordering. It does NOT own verification semantics: the
// previousCredential linkage, the outputHash[n] == inputHash[n+1] data-flow
// invariant, ordering consistency, the origin-has-no-predecessor rule, and
// source-commitment consistency all live in the injected ChainCore. The real
// core is vc.Verifier, which additionally resolves issuer DIDs and verifies
// ed25519 proofs per credential (vc.Verifier.VerifyChain); 17e wires that real
// core in the standalone, with vcresolver/client as the network resolver. Unit
// tests still exercise assembly against a fake core. Splitting assembly from
// semantics keeps the chain-structure rules in their single source of truth
// (vc) rather than duplicated here.
//
// # Error discipline
//
// A chain that cannot be ASSEMBLED — an unresolvable predecessor (a hole), a
// cycle, or a chain longer than MaxDepth — is a Go error, never a verdict:
// chainwalk refuses to hand an incomplete or malformed chain to the core. The
// caller (a sink or chained runtime) maps these Go errors to
// ConfidenceIndeterminate exactly as it maps any verification transport error
// (the verdict could not be computed). Context cancellation propagates as the
// context error. A verdict is returned only when a complete chain reached the
// core; the core's verdict (verified / failed / indeterminate) passes through
// verbatim.
package chainwalk

import (
	"context"
	"errors"
	"fmt"

	"github.com/provin-line/oss/vc"
)

// DefaultMaxDepth bounds the number of credentials walked from the head
// (inclusive). It is a denial-of-service backstop: a malicious or corrupt
// chain must not drive unbounded resolution. 1024 is far above any realistic
// pipeline depth; deployments that legitimately exceed it raise it explicitly
// via WithMaxDepth.
const DefaultMaxDepth = 1024

// CredentialResolver fetches a pipeline credential by its content address
// ("sha256:<hex>"). It is the consumer-defined contract for the chain walk;
// the network VC resolver client satisfies it. Resolution failure (not found,
// transport error) is returned as an error — chainwalk turns it into a chain
// hole.
type CredentialResolver interface {
	ResolveCredential(ctx context.Context, contentAddress string) (*vc.PipelinePassCredential, error)
}

// ChainCore verifies an already-assembled chain (origin-first). *vc.Verifier
// satisfies it. chainwalk delegates all verification semantics here; it never
// re-implements the chain-structure rules.
type ChainCore interface {
	VerifyChain(ctx context.Context, chain []*vc.PipelinePassCredential) (*vc.VerifyResult, error)
}

// Typed construction errors.
var (
	// ErrMissingResolver is returned when New is given a nil resolver.
	ErrMissingResolver = errors.New("chainwalk: CredentialResolver is required")
	// ErrMissingCore is returned when New is given a nil core.
	ErrMissingCore = errors.New("chainwalk: ChainCore is required")
	// ErrNonPositiveMaxDepth is returned when WithMaxDepth is given a value < 1.
	ErrNonPositiveMaxDepth = errors.New("chainwalk: MaxDepth must be >= 1")
)

// UnresolvedPredecessorError reports a chain hole: a previousCredential that could not be
// resolved during assembly (not a context cancellation). The caller maps it to an
// indeterminate verdict; an async auditor reads Hash to check whether the hole is still
// being worked (e.g. queued in the unresolved pool) before finalizing that verdict.
type UnresolvedPredecessorError struct {
	Hash string
	Err  error
}

func (e *UnresolvedPredecessorError) Error() string {
	return fmt.Sprintf("chainwalk: resolve predecessor %s: %v", e.Hash, e.Err)
}

func (e *UnresolvedPredecessorError) Unwrap() error { return e.Err }

// UnresolvedHash returns the content address of the unresolved predecessor. It lets a
// consumer match this error through a capability interface (e.g. an async auditor's hole
// signal) without importing this package — keeping the layer dependency pointing inward.
func (e *UnresolvedPredecessorError) UnresolvedHash() string { return e.Hash }

// ChainVerifier implements provenance.ChainVerifier by resolver-walk. Construct
// with New.
type ChainVerifier struct {
	resolver CredentialResolver
	core     ChainCore
	maxDepth int
}

// Option configures a ChainVerifier.
type Option func(*ChainVerifier)

// WithMaxDepth overrides DefaultMaxDepth. The value must be >= 1.
func WithMaxDepth(n int) Option {
	return func(cv *ChainVerifier) { cv.maxDepth = n }
}

// New validates dependencies and returns a ready ChainVerifier.
func New(resolver CredentialResolver, core ChainCore, opts ...Option) (*ChainVerifier, error) {
	if resolver == nil {
		return nil, ErrMissingResolver
	}
	if core == nil {
		return nil, ErrMissingCore
	}
	cv := &ChainVerifier{resolver: resolver, core: core, maxDepth: DefaultMaxDepth}
	for _, opt := range opts {
		opt(cv)
	}
	if cv.maxDepth < 1 {
		return nil, ErrNonPositiveMaxDepth
	}
	return cv, nil
}

// VerifyChain assembles the chain from head by resolving each
// previousCredential, then delegates to the core. Implements
// provenance.ChainVerifier.
func (cv *ChainVerifier) VerifyChain(ctx context.Context, head *vc.PipelinePassCredential) (*vc.VerifyResult, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	if head == nil {
		return nil, errors.New("chainwalk: head credential is nil")
	}

	// Walk head → origin, collecting head-first. seen guards against cycles by
	// content address; the head's own address is seeded so a predecessor that
	// points back to it is caught.
	headAddr, err := head.Hash()
	if err != nil {
		return nil, fmt.Errorf("chainwalk: hash head: %w", err)
	}
	seen := map[string]bool{headAddr: true}

	headFirst := []*vc.PipelinePassCredential{head}
	cur := head
	for cur.PreviousCredential() != "" {
		if len(headFirst) >= cv.maxDepth {
			return nil, fmt.Errorf("chainwalk: chain exceeds MaxDepth %d at %s", cv.maxDepth, cur.PreviousCredential())
		}
		prevAddr := cur.PreviousCredential()
		if seen[prevAddr] {
			return nil, fmt.Errorf("chainwalk: cycle detected — previousCredential %s already visited", prevAddr)
		}
		seen[prevAddr] = true

		prev, err := cv.resolver.ResolveCredential(ctx, prevAddr)
		if err != nil {
			if isCtxErr(err) {
				return nil, err
			}
			// Unresolvable predecessor = a chain hole. Refuse to verify an
			// incomplete chain; the caller maps this to indeterminate. The hole's
			// content address is carried in a typed error so an async auditor can
			// check whether it is still being resolved before finalizing a verdict.
			return nil, &UnresolvedPredecessorError{Hash: prevAddr, Err: err}
		}
		if prev == nil {
			return nil, fmt.Errorf("chainwalk: resolver returned nil credential for %s", prevAddr)
		}
		headFirst = append(headFirst, prev)
		cur = prev
	}

	// Reverse to origin-first, the order the core's chain-structure checks
	// expect (chain[0] = origin/FirstDrop, chain[last] = head).
	originFirst := make([]*vc.PipelinePassCredential, len(headFirst))
	for i, c := range headFirst {
		originFirst[len(headFirst)-1-i] = c
	}

	return cv.core.VerifyChain(ctx, originFirst)
}

// isCtxErr reports whether err is a context cancellation or deadline — those
// propagate as the context error so callers drain on shutdown rather than
// treating it as a chain hole.
func isCtxErr(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
