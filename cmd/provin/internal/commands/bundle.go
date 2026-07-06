package commands

import (
	"context"
	"fmt"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/bundle"
	"github.com/provin-line/oss/cmd/provin/internal/client"
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

	res, err := bundle.Export(ctx, cfg.Out, cfg.Head,
		wireCredentialSource{c: vcc},
		wireDocumentSource{r: docs},
		bundle.ExportOptions{MaxDepth: cfg.MaxDepth, Source: env.Registry},
	)
	if err != nil {
		return err
	}
	out := env.out()
	fmt.Fprintf(out, "bundle written: %s\n", cfg.Out)
	fmt.Fprintf(out, "head:           %s\n", res.Manifest.Head)
	fmt.Fprintf(out, "chain length:   %d\n", len(res.Manifest.Chain))
	fmt.Fprintf(out, "did documents:  %d\n", len(res.Manifest.DIDDocuments))
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
