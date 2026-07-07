package commands

import (
	"context"
	"fmt"
	"strings"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/bundle"
	"github.com/provin-line/oss/cmd/provin/internal/client"
	"github.com/provin-line/oss/did/dplaax"
	auditpb "github.com/provin-line/oss/gen/go/dplaax/audit/v1"
	"github.com/provin-line/oss/gen/go/dplaax/audit/v1/auditpbconnect"
	vcpb "github.com/provin-line/oss/gen/go/dplaax/vc/v1"
	"github.com/provin-line/oss/gen/go/dplaax/vc/v1/vcpbconnect"
	"github.com/provin-line/oss/network/pkg/core"
	"github.com/provin-line/oss/network/pkg/didresolver"
	"github.com/provin-line/oss/vc"
)

// BundleExportConfig carries `provin bundle export`'s inputs beyond the
// global environment.
type BundleExportConfig struct {
	// Head is the chain head content address — the value the relying party
	// holds from a sink record or an ingest 202 payload_hash.
	Head string
	// Out is the bundle directory to create; it must not exist.
	Out string
	// DIDBases maps a registry id to a base URL for DID-document fetches,
	// overriding the default https://{registry} derivation — the PoC seam
	// for registry ids that are not real DNS names. Unmapped registries fall
	// through to the default, so the two derivations cannot drift.
	DIDBases map[string]string
	// AllowLoopback / AllowPrivate relax the SSRF guard on DID-document
	// fetches for local development targets. Fail-closed by default.
	AllowLoopback bool
	AllowPrivate  bool
	// MaxDepth bounds the chain walk; 0 means bundle.DefaultMaxDepth.
	MaxDepth int
	// AggregateComplete widens the export through aggregate boundaries:
	// consumed sources (and their subchains) join the bundle so the
	// source-commitment axis re-verifies offline. "Complete" is with
	// respect to the SIGNED claimed source set — it cannot prove the
	// signer omitted nothing.
	AggregateComplete bool
	// VCResolverBases overrides the DID-advertised #vc-resolver endpoint
	// per registry id — the split-horizon seam: a document may advertise a
	// URL reachable only inside the emitting deployment's network (NAT,
	// ingress, container DNS), while the relying party reaches the same
	// service at a published address. Routing is operational, never part
	// of the frozen bundle convention; overridden endpoints still pass the
	// SSRF guard. Unmapped registries use the advertisement.
	VCResolverBases map[string]string
}

// BundleExport archives head's chain and authority documents into cfg.Out
// and prints the bundle digest — the out-of-band anchor to keep.
func BundleExport(ctx context.Context, env Env, cfg BundleExportConfig) error {
	vcc, err := client.VCResolver(env.httpClient(), env.Registry, env.Token)
	if err != nil {
		return err
	}
	guard := core.NewURLGuard(
		core.WithAllowLoopback(cfg.AllowLoopback),
		core.WithAllowPrivateNetworks(cfg.AllowPrivate),
	)
	docs := didresolver.New(guard, didresolver.WithRegistryBaseURL(func(registry string) (string, error) {
		if base, ok := cfg.DIDBases[registry]; ok {
			return base, nil
		}
		return didresolver.DefaultBaseURL(registry)
	}))

	exportOpts := bundle.ExportOptions{MaxDepth: cfg.MaxDepth, Source: env.Registry, AggregateComplete: cfg.AggregateComplete}
	if cfg.AggregateComplete {
		exportOpts.Consumed = &wireConsumedSource{
			token:      env.Token,
			guard:      guard,
			docs:       docs,
			didBases:   cfg.DIDBases,
			vcResolver: cfg.VCResolverBases,
			audit:      map[string]auditClient{},
			vcs:        map[string]vcpbconnect.VCResolverServiceClient{},
		}
	}
	res, err := bundle.Export(ctx, cfg.Out, cfg.Head,
		wireCredentialSource{c: vcc},
		wireDocumentSource{r: docs},
		exportOpts,
	)
	if err != nil {
		return err
	}
	out := env.out()
	fmt.Fprintf(out, "bundle written: %s\n", cfg.Out)
	fmt.Fprintf(out, "scope:          %s\n", res.Manifest.Scope)
	fmt.Fprintf(out, "head:           %s\n", res.Manifest.Head)
	fmt.Fprintf(out, "chain length:   %d\n", len(res.Manifest.Chain))
	fmt.Fprintf(out, "did documents:  %d\n", len(res.Manifest.DIDDocuments))
	if res.Manifest.V >= 2 {
		fmt.Fprintf(out, "receipts:       %d aggregate(s)\n", len(res.Manifest.Receipts))
	}
	fmt.Fprintf(out, "bundle digest: %s\n", res.Digest)
	fmt.Fprintln(out, "keep the digest out-of-band — it anchors the whole archive (proofs and documents included); verify with --digest, --head, or both")
	return nil
}

// BundleVerifyConfig carries `provin bundle verify`'s inputs. Head and
// Digest are the external anchors; at least one is required.
type BundleVerifyConfig struct {
	Dir    string
	Head   string
	Digest string
}

// BundleVerify re-verifies the bundle at cfg.Dir offline and prints the
// verdict. It returns an error — and the process exits non-zero — unless the
// chain verifies across all axes.
func BundleVerify(ctx context.Context, env Env, cfg BundleVerifyConfig) error {
	if cfg.Head == "" && cfg.Digest == "" {
		return fmt.Errorf("bundle verify: at least one external anchor is required (--head and/or --digest) — anchored only to its own manifest, a wholesale-rewritten bundle would still pass")
	}
	rep, err := bundle.Verify(ctx, cfg.Dir, bundle.VerifyOptions{
		ExpectedHead:   cfg.Head,
		ExpectedDigest: cfg.Digest,
	})
	if err != nil {
		return err
	}
	out := env.out()
	fmt.Fprintf(out, "head:                %s\n", rep.Head)
	fmt.Fprintf(out, "chain length:        %d\n", rep.ChainLength)
	fmt.Fprintf(out, "bundle digest:       %s\n", rep.Digest)
	fmt.Fprintf(out, "anchors checked:     head=%v digest=%v\n", rep.AnchoredHead, rep.AnchoredDigest)
	fmt.Fprintf(out, "scope:               %s\n", rep.Scope)
	if rep.Aggregates > 0 {
		fmt.Fprintf(out, "source commitments:  %d over %d bundled source(s) — complete w.r.t. the SIGNED claimed sets\n", rep.Aggregates, rep.Sources)
	}
	fmt.Fprintf(out, "data integrity:      %s\n", confidence(rep.Result.Axes.DataIntegrity))
	fmt.Fprintf(out, "signer authenticity: %s\n", confidence(rep.Result.Axes.SignerAuthenticity))
	fmt.Fprintf(out, "chain consistency:   %s\n", confidence(rep.Result.Axes.ChainConsistency))
	for _, n := range rep.Result.Notations {
		fmt.Fprintf(out, "notation:            %s\n", n)
	}
	if rep.Result.Overall != vc.ConfidenceVerified {
		fmt.Fprintf(out, "overall:             %s\n", confidence(rep.Result.Overall))
		return fmt.Errorf("bundle verify: chain is NOT verified (overall %s)", confidence(rep.Result.Overall))
	}
	fmt.Fprintln(out, "overall:             VERIFIED")
	return nil
}

func confidence(s vc.ConfidenceState) string {
	switch s {
	case vc.ConfidenceVerified:
		return "VERIFIED"
	case vc.ConfidenceIndeterminate:
		return "INDETERMINATE"
	default:
		return "FAILED"
	}
}

// wireConsumedSource is the CLI's bundle.ConsumedSetSource: receipt fetches
// route by the issuer's REGISTRY base (the --did-base map; unmapped falls
// through to https://{registry} — a #audit service advertisement is the
// recorded follow-up for a stable derivation), while source-credential
// fetches follow the repo's NORMATIVE pattern: the issuer DID document's
// single advertised #vc-resolver service endpoint (the batch resolver's
// derivation). Routing is operational, not part of the frozen convention.
// Every derived endpoint (issuer registry base, DID-advertised service) is
// UNTRUSTED input — a hostile credential naming did:dplaax:127.0.0.1:… or a
// DID document advertising a metadata URL must not turn the exporter into a
// bearer-carrying SSRF proxy — so every dial goes through the SAME URLGuard
// the DID-document fetches use (CheckURL preflight + guarded client;
// --allow-loopback/--allow-private apply uniformly). Only the caller's own
// --registry endpoint uses the environment client (explicit trust).
type wireConsumedSource struct {
	token      string
	guard      *core.URLGuard
	docs       *didresolver.Resolver
	didBases   map[string]string
	vcResolver map[string]string // registry -> #vc-resolver override (split-horizon)
	audit      map[string]auditClient
	vcs        map[string]vcpbconnect.VCResolverServiceClient
}

// auditClient aliases the generated client interface for the cache map.
type auditClient = auditpbconnect.AuditServiceClient

func (s *wireConsumedSource) registryBase(issuerDID string) (string, error) {
	d, err := dplaax.Parse(issuerDID)
	if err != nil {
		return "", fmt.Errorf("bundle export: issuer %q: %w", issuerDID, err)
	}
	if base, ok := s.didBases[d.Registry]; ok {
		return base, nil
	}
	return didresolver.DefaultBaseURL(d.Registry)
}

func (s *wireConsumedSource) FetchConsumed(ctx context.Context, issuerDID, headHash string) ([]string, error) {
	base, err := s.registryBase(issuerDID)
	if err != nil {
		return nil, err
	}
	c, ok := s.audit[base]
	if !ok {
		if err := s.guard.CheckURL(ctx, base); err != nil {
			return nil, fmt.Errorf("bundle export: audit endpoint for %s rejected: %w", issuerDID, err)
		}
		c, err = client.Audit(s.guard.HTTPClient(), base, s.token)
		if err != nil {
			return nil, err
		}
		s.audit[base] = c
	}
	var consumed []string
	pageToken := ""
	for {
		resp, err := c.GetConsumedSources(ctx, connect.NewRequest(&auditpb.GetConsumedSourcesRequest{
			HeadHash:  headHash,
			PageToken: pageToken,
		}))
		if err != nil {
			return nil, err
		}
		consumed = append(consumed, resp.Msg.GetConsumed()...)
		// The same walk-forever doctrine as the export walker: a hostile
		// emit-locus feeding endless pages must not hang the exporter or
		// grow the set without bound — every entry costs walker budget
		// anyway, so the walker's own cap is the honest ceiling.
		if len(consumed) > bundle.DefaultMaxDepth {
			return nil, fmt.Errorf("bundle export: receipt for %s exceeds %d entries — refusing an unbounded consumed set", headHash, bundle.DefaultMaxDepth)
		}
		pageToken = resp.Msg.GetNextPageToken()
		if pageToken == "" {
			return consumed, nil
		}
	}
}

func (s *wireConsumedSource) FetchSourceCredential(ctx context.Context, issuerDID, hash string) ([]byte, error) {
	c, ok := s.vcs[issuerDID]
	if !ok {
		endpoint, err := s.vcResolverEndpoint(ctx, issuerDID)
		if err != nil {
			return nil, err
		}
		if err := s.guard.CheckURL(ctx, endpoint); err != nil {
			return nil, fmt.Errorf("bundle export: #vc-resolver endpoint of %s rejected: %w", issuerDID, err)
		}
		c, err = client.VCResolver(s.guard.HTTPClient(), endpoint, s.token)
		if err != nil {
			return nil, err
		}
		// Cached per issuer (not per endpoint): two issuers sharing one
		// endpoint hold two clients — harmless.
		s.vcs[issuerDID] = c
	}
	res, err := c.ResolveVC(ctx, connect.NewRequest(&vcpb.ResolveVCRequest{Hash: hash}))
	if err != nil {
		return nil, err
	}
	return res.Msg.GetCredential(), nil
}

// vcResolverEndpoint resolves where an issuer's credentials can be fetched:
// the split-horizon override when the operator mapped the issuer's registry
// (--vc-resolver-base), otherwise the NORMATIVE derivation — the single
// #vc-resolver service the issuer's DID document advertises.
func (s *wireConsumedSource) vcResolverEndpoint(ctx context.Context, issuerDID string) (string, error) {
	d, err := dplaax.Parse(issuerDID)
	if err != nil {
		return "", fmt.Errorf("bundle export: issuer %q: %w", issuerDID, err)
	}
	if base, ok := s.vcResolver[d.Registry]; ok {
		return base, nil
	}
	doc, err := s.docs.Resolve(ctx, issuerDID)
	if err != nil {
		return "", fmt.Errorf("bundle export: resolve issuer %s for its #vc-resolver endpoint: %w", issuerDID, err)
	}
	var endpoint string
	var n int
	for _, svc := range doc.Service() {
		if svc.Type == "VCResolver" && strings.HasSuffix(svc.ID, "#vc-resolver") {
			endpoint = svc.ServiceEndpoint
			n++
		}
	}
	if n != 1 {
		return "", fmt.Errorf("bundle export: issuer %s advertises %d #vc-resolver VCResolver services, want exactly one", issuerDID, n)
	}
	return endpoint, nil
}

// wireCredentialSource adapts the VCResolverService client to the exporter's
// evidence seam.
type wireCredentialSource struct {
	c vcpbconnect.VCResolverServiceClient
}

func (s wireCredentialSource) FetchCredential(ctx context.Context, hash string) ([]byte, error) {
	res, err := s.c.ResolveVC(ctx, connect.NewRequest(&vcpb.ResolveVCRequest{Hash: hash}))
	if err != nil {
		return nil, err
	}
	return res.Msg.GetCredential(), nil
}

// wireDocumentSource adapts the production DID resolver's raw-bytes fetch to
// the exporter's document seam.
type wireDocumentSource struct {
	r *didresolver.Resolver
}

func (s wireDocumentSource) FetchDocument(ctx context.Context, didStr string) ([]byte, error) {
	_, raw, err := s.r.ResolveDocument(ctx, didStr)
	return raw, err
}
