package commands

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/provin-line/oss/cmd/provin/internal/client"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/did/dplaax"
	"github.com/provin-line/oss/orgverify"
	"github.com/provin-line/oss/resolver"
)

// maxRegistryDocSize bounds the DID Document fetched by the org commands'
// resolver adapter — a registry response is attacker-influenceable input
// (whatever it chooses to serve at the resolved URL), so the body is read
// through an io.LimitReader and an over-cap response is an error rather than
// unbounded memory, mirroring network/pkg/didresolver's own cap.
const maxRegistryDocSize = 1 << 20 // 1 MiB

// OrgVerifyConfig carries `provin org verify`'s inputs beyond the global
// environment.
type OrgVerifyConfig struct {
	DID string
	// DNSResolver overrides the DNS TXT lookup mechanism; nil means the
	// system resolver (net.Resolver), matching orgverify.Options' own
	// default. Exported so tests can inject a fake DNS seam without ever
	// touching real DNS — main.go's flag parsing never sets it.
	DNSResolver orgverify.DNSResolver
}

// OrgVerify resolves cfg.DID's DNS-based organization endorsement and prints
// the verdict. A non-Verified verdict is reported via ExitStatus mapped from
// EndorsementLevel.ExitCode() (spec §7.2/§7.3) — org verify is the only org
// command whose exit code is verdict-driven; inspect/diagnose/generate-txt
// exit 0 on success regardless of the underlying state.
func OrgVerify(ctx context.Context, env Env, cfg OrgVerifyConfig) error {
	docResolver, err := newRegistryDocResolver(env)
	if err != nil {
		return err
	}
	res, err := orgverify.Verify(ctx, cfg.DID, orgverify.Options{
		DNSResolver: cfg.DNSResolver,
		DIDResolver: docResolver,
	})
	if err != nil {
		return fmt.Errorf("org verify: %w", err)
	}
	printVerdict(env.out(), res)
	if res.Level != orgverify.EndorsementVerified {
		return ExitStatus{Code: res.Level.ExitCode()}
	}
	return nil
}

func printVerdict(out io.Writer, res *orgverify.Result) {
	fmt.Fprintf(out, "endorsement: %s\n", res.Level)
	if res.Reason != "" && res.Reason != orgverify.ReasonOK {
		fmt.Fprintf(out, "reason:      %s\n", res.Reason)
	}
	if res.Detail != "" {
		fmt.Fprintf(out, "detail:      %s\n", res.Detail)
	}
}

// OrgInspectConfig carries `provin org inspect`'s inputs beyond the global
// environment.
type OrgInspectConfig struct {
	DID         string
	DNSResolver orgverify.DNSResolver // see OrgVerifyConfig.DNSResolver
}

// OrgInspect prints the raw DNS / DID Document observations for cfg.DID
// without computing a verdict. It exits 0 on any execution success — there
// is no verdict-driven exit code (spec §7.7).
func OrgInspect(ctx context.Context, env Env, cfg OrgInspectConfig) error {
	docResolver, err := newRegistryDocResolver(env)
	if err != nil {
		return err
	}
	res, err := orgverify.Inspect(ctx, cfg.DID, orgverify.Options{
		DNSResolver: cfg.DNSResolver,
		DIDResolver: docResolver,
	})
	if err != nil {
		return fmt.Errorf("org inspect: %w", err)
	}
	out := env.out()
	fmt.Fprintf(out, "did:         %s\n", res.DID)
	fmt.Fprintf(out, "owner did:   %s\n", res.OwnerDID)
	fmt.Fprintf(out, "org id:      %s (fqdn: %v)\n", res.OrgID, res.IsFQDN)
	switch {
	case res.DocumentError != "":
		fmt.Fprintf(out, "did document error: %s\n", res.DocumentError)
	case res.KeyFingerprint != "":
		fmt.Fprintf(out, "key fingerprint (from doc): %s\n", res.KeyFingerprint)
	}
	if res.DNSName != "" {
		fmt.Fprintf(out, "dns name:    %s\n", res.DNSName)
	}
	if res.DNSError != "" {
		fmt.Fprintf(out, "dns error:   %s\n", res.DNSError)
	}
	for i, rec := range res.DNSRecords {
		fmt.Fprintf(out, "dns record %d: %s\n", i+1, rec.Raw)
		if rec.Version == "" {
			fmt.Fprintf(out, "  parse: malformed\n")
			continue
		}
		fmt.Fprintf(out, "  parse: ok (did=%s)\n", rec.DID)
		if res.KeyFingerprint != "" && rec.DID == res.OwnerDID {
			match := "MISMATCH"
			if rec.KeyFingerprint == res.KeyFingerprint {
				match = "match"
			}
			fmt.Fprintf(out, "  fingerprint vs doc: %s\n", match)
		}
	}
	return nil
}

// OrgDiagnoseConfig carries `provin org diagnose`'s inputs beyond the global
// environment.
type OrgDiagnoseConfig struct {
	DID         string
	DNSResolver orgverify.DNSResolver // see OrgVerifyConfig.DNSResolver
}

// OrgDiagnose prints cfg.DID's verdict plus remediation steps. It exits 0
// even on a negative verdict (spec §7.7) — diagnose's product is remediation
// steps, not a pass/fail judgment; use `org verify` for the scriptable exit
// code.
func OrgDiagnose(ctx context.Context, env Env, cfg OrgDiagnoseConfig) error {
	docResolver, err := newRegistryDocResolver(env)
	if err != nil {
		return err
	}
	res, err := orgverify.Verify(ctx, cfg.DID, orgverify.Options{
		DNSResolver: cfg.DNSResolver,
		DIDResolver: docResolver,
	})
	if err != nil {
		return fmt.Errorf("org diagnose: %w", err)
	}
	out := env.out()
	printVerdict(out, res)
	steps := orgverify.Diagnose(res)
	if len(steps) == 0 {
		fmt.Fprintln(out, "\nno remediation needed.")
		return nil
	}
	fmt.Fprintln(out, "\nremediation steps:")
	for i, s := range steps {
		fmt.Fprintf(out, "\n%d. %s\n%s\n", i+1, s.Action, s.Detail)
	}
	return nil
}

// OrgGenerateTXTConfig carries `provin org generate-txt`'s inputs beyond the
// global environment.
type OrgGenerateTXTConfig struct {
	DID string
	// Fingerprint, when set (sha256:<64-lowercase-hex>), skips DID
	// resolution entirely — the offline mode spec §7.7 requires (no
	// --registry needed).
	Fingerprint string
}

// OrgGenerateTXT prints the DNS TXT record name and value that would endorse
// cfg.DID: two lines, the record name then the record value (spec §7.7).
// cfg.DID is normalized to its Owner DID first — the record name derives
// from the owner's orgId, and the record's did= value must equal what
// Verify() compares against (the owner DID), not whatever resource-level DID
// the operator happened to pass.
func OrgGenerateTXT(ctx context.Context, env Env, cfg OrgGenerateTXTConfig) error {
	owner, err := orgOwnerDID(cfg.DID)
	if err != nil {
		return fmt.Errorf("org generate-txt: %w", err)
	}
	ownerStr := owner.String()

	// FQDN gate first: a non-FQDN orgId can never carry a TXT record, so fail
	// before any network resolution.
	canon, ok, err := orgverify.NormalizeFQDN(owner.AccountID)
	if err != nil {
		return fmt.Errorf("org generate-txt: orgId is not a valid hostname: %w", err)
	}
	if !ok {
		return fmt.Errorf("org generate-txt: orgId %q is not an FQDN; a TXT record requires a real domain", owner.AccountID)
	}

	fingerprint := cfg.Fingerprint
	if fingerprint == "" {
		docResolver, err := newRegistryDocResolver(env)
		if err != nil {
			return err
		}
		doc, err := docResolver.Resolve(ctx, ownerStr)
		if err != nil {
			return fmt.Errorf("org generate-txt: resolve %s: %w", ownerStr, err)
		}
		fingerprint, err = orgverify.FingerprintFromDIDDocument(doc)
		if err != nil {
			return fmt.Errorf("org generate-txt: %w", err)
		}
	}

	val, err := orgverify.GenerateTXT(ownerStr, fingerprint)
	if err != nil {
		return fmt.Errorf("org generate-txt: %w", err)
	}

	out := env.out()
	fmt.Fprintln(out, orgverify.RecordName(canon))
	fmt.Fprintln(out, val)
	return nil
}

// orgOwnerDID parses and validates didStr (accepting owner/pipeline/process;
// rejecting unknown hierarchy patterns and non-"org" account types — the same
// gate orgverify.Verify applies) and returns its Owner-level DID.
func orgOwnerDID(didStr string) (*dplaax.DID, error) {
	parsed, err := dplaax.Parse(didStr)
	if err != nil {
		return nil, fmt.Errorf("parse %q: %w", didStr, err)
	}
	if err := dplaax.ValidateDID(parsed); err != nil {
		return nil, err
	}
	return parsed.OwnerDID(), nil
}

// newRegistryDocResolver builds a DID Document resolver over this registry's
// public route. It is named for that responsibility rather than for the org
// commands, which were merely its first caller: `owner init` settles an
// AlreadyExists registration through it too, because comparing a public key
// against a public document is not an authorized read.
//
// A small adapter over the registry's public W3C resolution route
// (GET <registry>/did/<accountType>/<accountId>[/<resourcePath>...]/did.json
// — see network/pkg/services/didregistry/handler.NewResolutionHandler, the
// route this mirrors), anchored at env.Registry (spec §7.4 — NOT derived
// from the target DID's own registry segment, unlike
// network/pkg/didresolver's cross-registry resolution used by bundle
// export). The route is unauthenticated (public DID resolution), so no
// bearer token is sent or required.
func newRegistryDocResolver(env Env) (resolver.Resolver, error) {
	if env.Registry == "" {
		return nil, fmt.Errorf("resolve: --registry is required (env PROVIN_REGISTRY) to resolve DID documents")
	}
	if err := client.ValidateBaseURL(env.Registry); err != nil {
		return nil, fmt.Errorf("resolve: registry URL: %w", err)
	}
	return &registryDocResolver{httpClient: env.httpClient(), registry: env.Registry}, nil
}

type registryDocResolver struct {
	httpClient httpDoer
	registry   string
}

// httpDoer is connect.HTTPClient's method shape (Do(*http.Request)
// (*http.Response, error)) — the org adapter is plain net/http, not
// ConnectRPC, so it names the shape locally rather than importing the
// connectrpc.com/connect package for a type alias.
type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Resolve fetches and parses the DID Document for didStr from the org
// adapter's registry base. It satisfies resolver.Resolver.
func (r *registryDocResolver) Resolve(ctx context.Context, didStr string) (*did.DIDDocument, error) {
	d, err := dplaax.Parse(didStr)
	if err != nil {
		return nil, fmt.Errorf("resolve: parse %q: %w", didStr, err)
	}
	segs := append([]string{d.AccountType, d.AccountID}, d.ResourcePath...)
	url := strings.TrimRight(r.registry, "/") + "/did/" + strings.Join(segs, "/") + "/did.json"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("resolve: build request for %s: %w", didStr, err)
	}
	req.Header.Set("Accept", "application/did+json")
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("resolve: fetch %s: %w", didStr, err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		// resolver.Resolver contract: authoritative absence wraps ErrNotFound
		// (consumers treat any other error as transient).
		return nil, fmt.Errorf("resolve: %s: not found at %s: %w", didStr, url, resolver.ErrNotFound)
	default:
		return nil, fmt.Errorf("resolve: %s: unexpected status %d from %s", didStr, resp.StatusCode, url)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRegistryDocSize+1))
	if err != nil {
		return nil, fmt.Errorf("resolve: read %s: %w", didStr, err)
	}
	if len(body) > maxRegistryDocSize {
		return nil, fmt.Errorf("resolve: %s: document exceeds %d bytes", didStr, maxRegistryDocSize)
	}
	var doc did.DIDDocument
	if err := doc.UnmarshalJSON(body); err != nil {
		return nil, fmt.Errorf("resolve: parse document for %s: %w", didStr, err)
	}
	// The resolver.Resolver contract requires the returned document's id to
	// equal the requested DID — without this, a registry answering with a
	// DIFFERENT identity's document would have its key fingerprinted, and a
	// matching TXT record would yield a false `verified`.
	if got := doc.ID(); got != didStr {
		return nil, fmt.Errorf("resolve: registry returned document for %q, requested %q", got, didStr)
	}
	return &doc, nil
}
