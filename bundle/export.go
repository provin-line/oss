package bundle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/did/dplaax"
	"github.com/provin-line/oss/vc"
)

// CredentialSource supplies one credential's raw wire bytes by content
// address — the export-side evidence seam (a VC-resolver wire client in
// production, a map in tests). It is an availability seam, not a trust
// anchor: Export recomputes every fetched credential's content address and
// rejects a mismatch.
type CredentialSource interface {
	FetchCredential(ctx context.Context, hash string) ([]byte, error)
}

// DocumentSource supplies one DID document's raw bytes — the export-side
// seam for the public resolution route. Errors pass through to confidence
// evaluation unwrapped, so a source that can distinguish definitive absence
// should wrap resolver.ErrNotFound.
type DocumentSource interface {
	FetchDocument(ctx context.Context, didStr string) ([]byte, error)
}

// ConsumedSetSource fetches aggregate evidence, keyed by the
// commitment-bearing credential's ISSUER — the emit-locus node records the
// receipt at emission and holds the verified consumed sources (and their
// batch-resolver-assembled subchains) in its own store. HOW an
// implementation resolves the issuer to endpoints is its concern; the seam
// only promises issuer-scoped evidence.
type ConsumedSetSource interface {
	FetchConsumed(ctx context.Context, issuerDID, headHash string) ([]string, error)
	FetchSourceCredential(ctx context.Context, issuerDID, hash string) ([]byte, error)
}

// ExportOptions tunes Export. The zero value is ready to use and produces
// the v1 linear bundle, byte-identical to the shipped behavior.
type ExportOptions struct {
	// MaxDepth bounds the TOTAL number of credentials fetched across every
	// spine; 0 means DefaultMaxDepth.
	MaxDepth int
	// Source is advisory provenance recorded in the manifest (typically the
	// node base URL the bundle was taken from). Never verified.
	Source string
	// AggregateComplete widens the walk through aggregate boundaries: every
	// commitment-bearing credential's consumed sources (and their whole
	// subchains, recursively) join the bundle, and export additionally
	// requires every source commitment to verify. Requires Consumed.
	AggregateComplete bool
	Consumed          ConsumedSetSource
}

// ExportResult is what Export hands back: the written manifest and the
// bundle digest — the manifest bytes' content address, covering every file
// in the bundle through Manifest.Files. The relying party keeps the digest
// out-of-band; it is the anchor that makes the archive tamper-evident.
type ExportResult struct {
	Manifest *Manifest
	Digest   string
}

// Export walks head's provenance over the sources and writes a complete,
// immutable bundle into dir (which must not yet exist).
//
// Export runs the real chain verification over the live sources and archives
// exactly the documents it resolves — the recording-resolver construction:
// the diddocs set cannot drift from what offline verification will need,
// because it IS what verification needed. A chain that does not verify
// (anything below ConfidenceVerified overall, on any spine or source
// commitment) aborts the export: writing an archive that could not
// re-verify offline would silently produce an incomplete bundle.
func Export(ctx context.Context, dir, head string, creds CredentialSource, docs DocumentSource, opts ExportOptions) (*ExportResult, error) {
	maxDepth := opts.MaxDepth
	if maxDepth <= 0 {
		maxDepth = DefaultMaxDepth
	}
	if !vc.IsContentAddress(head) {
		return nil, fmt.Errorf("bundle: head %q is not a content address", head)
	}
	if opts.AggregateComplete && opts.Consumed == nil {
		return nil, errors.New("bundle: AggregateComplete requires a ConsumedSetSource")
	}

	w := &walker{
		visited: map[string]*vc.PipelinePassCredential{},
		bytes:   map[string][]byte{},
		budget:  maxDepth,
		limit:   maxDepth,
	}
	mainSpine, err := w.spine(head, func(h string) ([]byte, error) { return creds.FetchCredential(ctx, h) })
	if err != nil {
		return nil, err
	}

	// Aggregate walk: classify every bundled credential by commitment shape
	// (receipts exist only where the runtime records them), fetching
	// consumed sources and their subchains; newly fetched credentials are
	// classified too (aggregates of aggregates).
	receipts := map[string][]string{}
	sourceSpines := map[string][]*vc.PipelinePassCredential{}
	commitSources := map[string][]*vc.PipelinePassCredential{}
	if opts.AggregateComplete {
		queue := make([]string, 0, len(mainSpine))
		for _, c := range mainSpine {
			h, err := c.Hash()
			if err != nil {
				return nil, fmt.Errorf("bundle: content address: %w", err)
			}
			queue = append(queue, h)
		}
		processed := map[string]bool{}
		for len(queue) > 0 {
			h := queue[0]
			queue = queue[1:]
			if processed[h] {
				continue
			}
			processed[h] = true
			c := w.visited[h]
			sc := c.SourceCommitment()
			if sc == nil {
				continue
			}
			switch {
			case len(sc.DerivedFrom) == 0:
				// A signed claim of zero conformant sources: no receipt
				// exists by design; verified over the empty set.
				commitSources[h] = nil
			case c.PreviousCredential() != "":
				// Chain-preserving commitment: all-consumed semantics
				// include the triggering predecessor, which the spine walk
				// already bundled. If the claimed issuer set is not fully
				// resolved by the predecessor alone, the verification gate
				// below fails closed with the commitment named.
				commitSources[h] = []*vc.PipelinePassCredential{w.visited[c.PreviousCredential()]}
			default:
				// Aggregate-shaped: the emit-locus receipt is required.
				issuer := c.Issuer()
				consumed, err := opts.Consumed.FetchConsumed(ctx, issuer, h)
				if err != nil {
					return nil, fmt.Errorf("bundle: aggregate-complete requires the emit-locus receipt for %s (issuer %s): %w", h, issuer, err)
				}
				consumed, err = normalizeConsumed(h, consumed)
				if err != nil {
					return nil, err
				}
				receipts[h] = consumed
				var srcs []*vc.PipelinePassCredential
				for _, sh := range consumed {
					sp, err := w.spine(sh, func(x string) ([]byte, error) {
						return opts.Consumed.FetchSourceCredential(ctx, issuer, x)
					})
					if err != nil {
						// Retry guidance ONLY for fetch failures: a cycle,
						// budget exhaustion, or lying source will not heal
						// by waiting.
						if errors.Is(err, errFetchUnavailable) {
							return nil, fmt.Errorf("bundle: source subchain of %s (consumed by %s): %w — the emit-locus batch resolver may not have assembled it yet; check GetAuditStatus and retry", sh, h, err)
						}
						return nil, fmt.Errorf("bundle: source subchain of %s (consumed by %s): %w", sh, h, err)
					}
					sourceSpines[sh] = sp
					srcs = append(srcs, w.visited[sh])
					for _, spc := range sp {
						sph, err := spc.Hash()
						if err != nil {
							return nil, fmt.Errorf("bundle: content address: %w", err)
						}
						queue = append(queue, sph)
					}
				}
				commitSources[h] = srcs
			}
		}
	}

	// Run the real verifier through a recording resolver: whatever document
	// set verification resolves — issuers plus their full controller chains
	// to the terminal owners, across EVERY spine — is exactly what gets
	// archived.
	rec := newRecordingResolver(docs)
	verifier := vc.NewVerifier(rec, ed25519.Verifier{})
	res, err := verifier.VerifyChain(ctx, mainSpine)
	if err != nil {
		return nil, fmt.Errorf("bundle: verify chain before export: %w", err)
	}
	if res.Overall != vc.ConfidenceVerified {
		return nil, fmt.Errorf("bundle: chain does not verify (overall %v, axes %+v) — refusing to write an archive that could not re-verify offline", res.Overall, res.Axes)
	}
	for sh, sp := range sourceSpines {
		sres, err := verifier.VerifyChain(ctx, sp)
		if err != nil {
			return nil, fmt.Errorf("bundle: verify source subchain %s: %w", sh, err)
		}
		if sres.Overall != vc.ConfidenceVerified {
			return nil, fmt.Errorf("bundle: source subchain %s does not verify (overall %v) — refusing to write an archive that could not re-verify offline", sh, sres.Overall)
		}
	}
	for h, srcs := range commitSources {
		state, err := verifier.VerifySourceCommitment(ctx, w.visited[h], srcs)
		if err != nil {
			return nil, fmt.Errorf("bundle: verify source commitment of %s: %w", h, err)
		}
		if state != vc.ConfidenceVerified {
			return nil, fmt.Errorf("bundle: source commitment of %s = %v with the gathered sources — refusing to write an archive that could not re-verify offline (a chain-preserving commitment claiming issuers beyond its predecessor is not exportable today)", h, state)
		}
	}

	// Compose the file set (slash-separated rel path -> bytes) over EVERY
	// bundled credential plus everything verification resolved.
	files := make(map[string][]byte, len(w.bytes)+len(rec.raw))
	for h, raw := range w.bytes {
		rel, err := credentialPath(h)
		if err != nil {
			return nil, err
		}
		files[rel] = raw
	}
	chainAddrs := make([]string, len(mainSpine))
	for i, cred := range mainSpine {
		h, err := cred.Hash()
		if err != nil {
			return nil, fmt.Errorf("bundle: content address: %w", err)
		}
		chainAddrs[i] = h
	}
	dids := make([]string, 0, len(rec.raw))
	for didStr, raw := range rec.raw {
		rel, err := documentPath(didStr)
		if err != nil {
			return nil, err
		}
		files[rel] = raw
		dids = append(dids, didStr)
	}
	sort.Strings(dids)
	rels := make([]string, 0, len(files))
	for rel := range files {
		rels = append(rels, rel)
	}
	if err := checkCaseFoldCollisions(rels); err != nil {
		return nil, err
	}

	// Write the evidence first, the manifest last: a manifest's presence
	// marks a complete bundle.
	if _, err := os.Stat(dir); err == nil {
		return nil, fmt.Errorf("bundle: %s already exists — a bundle is immutable, export into a fresh path", dir)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("bundle: stat %s: %w", dir, err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("bundle: create %s: %w", dir, err)
	}
	// A failed export must not strand a manifest-less partial directory:
	// "the directory exists" must keep implying "the bundle is complete".
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(dir)
		}
	}()
	fileDigests := make(map[string]string, len(files))
	for rel, raw := range files {
		abs := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			return nil, fmt.Errorf("bundle: create %s: %w", filepath.Dir(abs), err)
		}
		if err := os.WriteFile(abs, raw, 0o644); err != nil {
			return nil, fmt.Errorf("bundle: write %s: %w", rel, err)
		}
		fileDigests[rel] = digest(raw)
	}

	m := &Manifest{
		V:            manifestVersion,
		Scope:        ScopeLinear,
		Head:         head,
		Chain:        chainAddrs,
		DIDDocuments: dids,
		Files:        fileDigests,
		CreatedAt:    time.Now().UTC().Format(time.RFC3339),
		Source:       opts.Source,
	}
	if opts.AggregateComplete {
		m.V = 2
		m.Scope = ScopeAggregateComplete
		m.Receipts = receipts
	}
	raw, err := encodeManifest(m)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, manifestFile), raw, 0o644); err != nil {
		return nil, fmt.Errorf("bundle: write manifest: %w", err)
	}
	complete = true
	return &ExportResult{Manifest: m, Digest: digest(raw)}, nil
}

// encodeManifest serializes through the PER-VERSION exact wire struct, so a
// v1 manifest can never grow a v2-only member (and stays byte-identical to
// the shipped format).
func encodeManifest(m *Manifest) ([]byte, error) {
	var wire any
	switch m.V {
	case 1:
		wire = &manifestWireV1{
			V: m.V, Scope: m.Scope, Head: m.Head, Chain: m.Chain,
			DIDDocuments: m.DIDDocuments, Files: m.Files,
			CreatedAt: m.CreatedAt, Source: m.Source,
		}
	case 2:
		wire = &manifestWireV2{
			V: m.V, Scope: m.Scope, Head: m.Head, Chain: m.Chain,
			DIDDocuments: m.DIDDocuments, Files: m.Files,
			CreatedAt: m.CreatedAt, Source: m.Source, Receipts: m.Receipts,
		}
	default:
		return nil, fmt.Errorf("bundle: unsupported manifest version %d", m.V)
	}
	raw, err := json.MarshalIndent(wire, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("bundle: marshal manifest: %w", err)
	}
	return append(raw, '\n'), nil
}

// normalizeConsumed validates and canonicalizes one receipt: every entry a
// content address, sorted lexicographically, no duplicates.
func normalizeConsumed(headHash string, consumed []string) ([]string, error) {
	out := append([]string(nil), consumed...)
	sort.Strings(out)
	for i, h := range out {
		if !vc.IsContentAddress(h) {
			return nil, fmt.Errorf("bundle: receipt for %s: entry %q is not a content address", headHash, h)
		}
		if i > 0 && out[i-1] == h {
			return nil, fmt.Errorf("bundle: receipt for %s: duplicate consumed hash %s", headHash, h)
		}
	}
	return out, nil
}

// walker accumulates every fetched credential across all spines under one
// shared budget (the MaxDepth DoS backstop applies to the TOTAL, not per
// spine).
type walker struct {
	visited map[string]*vc.PipelinePassCredential
	bytes   map[string][]byte
	budget  int
	limit   int // the configured cap, for error messages
}

// errFetchUnavailable marks a spine failure caused by the underlying fetch
// (as opposed to a cycle, budget exhaustion, or a lying source) — the one
// class where "retry later" is honest advice.
var errFetchUnavailable = errors.New("bundle: credential fetch failed")

// spine walks previousCredential links from `from` to the origin, fetching
// (with the lying-source content-address defense) anything not already
// held, and returns the origin-first spine. Shared credentials across
// spines are fetched once.
func (w *walker) spine(from string, fetch func(hash string) ([]byte, error)) ([]*vc.PipelinePassCredential, error) {
	if !vc.IsContentAddress(from) {
		return nil, fmt.Errorf("bundle: %q is not a content address", from)
	}
	var spine []*vc.PipelinePassCredential
	seen := map[string]bool{}
	for cur := from; cur != ""; {
		if seen[cur] {
			return nil, fmt.Errorf("bundle: chain link cycle at %s", cur)
		}
		seen[cur] = true
		c, ok := w.visited[cur]
		if !ok {
			if w.budget == 0 {
				return nil, fmt.Errorf("bundle: walk exceeds max depth %d at %s", w.limit, cur)
			}
			w.budget--
			raw, err := fetch(cur)
			if err != nil {
				return nil, fmt.Errorf("%w: %s: %v", errFetchUnavailable, cur, err)
			}
			c = new(vc.PipelinePassCredential)
			if err := c.UnmarshalJSON(raw); err != nil {
				return nil, fmt.Errorf("bundle: parse credential %s: %w", cur, err)
			}
			got, err := c.Hash()
			if err != nil {
				return nil, fmt.Errorf("bundle: content address of fetched %s: %w", cur, err)
			}
			if got != cur {
				return nil, fmt.Errorf("bundle: fetched credential for %s has content address %s — refusing a lying source", cur, got)
			}
			w.visited[cur] = c
			w.bytes[cur] = raw
		}
		spine = append(spine, c)
		cur = c.PreviousCredential()
	}
	for i, j := 0, len(spine)-1; i < j; i, j = i+1, j-1 {
		spine[i], spine[j] = spine[j], spine[i]
	}
	return spine, nil
}

// recordingResolver satisfies the verifier's resolver contract over a
// DocumentSource, keeping the raw bytes of every document it successfully
// resolved. Source errors pass through unwrapped so the resolver error
// taxonomy (resolver.ErrNotFound = definitive) survives into confidence
// evaluation; a document whose id differs from the requested DID is an
// error, never honoured (the same registry-substitution defense as the
// production resolver).
type recordingResolver struct {
	docs   DocumentSource
	raw    map[string][]byte
	parsed map[string]*did.DIDDocument
}

func newRecordingResolver(docs DocumentSource) *recordingResolver {
	return &recordingResolver{
		docs:   docs,
		raw:    map[string][]byte{},
		parsed: map[string]*did.DIDDocument{},
	}
}

func (r *recordingResolver) Resolve(ctx context.Context, didStr string) (*did.DIDDocument, error) {
	d, err := dplaax.Parse(didStr)
	if err != nil {
		return nil, fmt.Errorf("bundle: resolve %q: %w", didStr, err)
	}
	key := d.String()
	if doc, ok := r.parsed[key]; ok {
		return doc, nil
	}
	raw, err := r.docs.FetchDocument(ctx, key)
	if err != nil {
		return nil, err
	}
	doc := new(did.DIDDocument)
	if err := doc.UnmarshalJSON(raw); err != nil {
		return nil, fmt.Errorf("bundle: parse document for %s: %w", key, err)
	}
	if doc.ID() != key {
		return nil, fmt.Errorf("bundle: document id %q does not match requested %q — never honoured", doc.ID(), key)
	}
	r.raw[key] = raw
	r.parsed[key] = doc
	return doc, nil
}
