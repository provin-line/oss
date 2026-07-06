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

// ExportOptions tunes Export. The zero value is ready to use.
type ExportOptions struct {
	// MaxDepth bounds the chain walk; 0 means DefaultMaxDepth.
	MaxDepth int
	// Source is advisory provenance recorded in the manifest (typically the
	// node base URL the bundle was taken from). Never verified.
	Source string
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
// (anything below ConfidenceVerified overall) aborts the export: writing an
// archive that could not re-verify offline would silently produce an
// incomplete bundle.
func Export(ctx context.Context, dir, head string, creds CredentialSource, docs DocumentSource, opts ExportOptions) (*ExportResult, error) {
	maxDepth := opts.MaxDepth
	if maxDepth <= 0 {
		maxDepth = DefaultMaxDepth
	}
	if !vc.IsContentAddress(head) {
		return nil, fmt.Errorf("bundle: head %q is not a content address", head)
	}

	// Walk the chain head-first, archiving raw bytes; recompute each content
	// address so a lying source cannot poison the archive.
	credBytes := make(map[string][]byte)
	var chain []*vc.PipelinePassCredential // built head-first, reversed below
	for cur := head; cur != ""; {
		if _, dup := credBytes[cur]; dup {
			return nil, fmt.Errorf("bundle: chain link cycle at %s", cur)
		}
		if len(chain) == maxDepth {
			return nil, fmt.Errorf("bundle: chain exceeds max depth %d at %s", maxDepth, cur)
		}
		raw, err := creds.FetchCredential(ctx, cur)
		if err != nil {
			return nil, fmt.Errorf("bundle: fetch credential %s: %w", cur, err)
		}
		cred := new(vc.PipelinePassCredential)
		if err := cred.UnmarshalJSON(raw); err != nil {
			return nil, fmt.Errorf("bundle: parse credential %s: %w", cur, err)
		}
		got, err := cred.Hash()
		if err != nil {
			return nil, fmt.Errorf("bundle: content address of fetched %s: %w", cur, err)
		}
		if got != cur {
			return nil, fmt.Errorf("bundle: fetched credential for %s has content address %s — refusing a lying source", cur, got)
		}
		credBytes[cur] = raw
		chain = append(chain, cred)
		cur = cred.PreviousCredential()
	}
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}

	// Run the real verifier through a recording resolver: whatever document
	// set verification resolves — issuers plus their full controller chains
	// to the terminal owners — is exactly what gets archived.
	rec := newRecordingResolver(docs)
	res, err := vc.NewVerifier(rec, ed25519.Verifier{}).VerifyChain(ctx, chain)
	if err != nil {
		return nil, fmt.Errorf("bundle: verify chain before export: %w", err)
	}
	if res.Overall != vc.ConfidenceVerified {
		return nil, fmt.Errorf("bundle: chain does not verify (overall %v, axes %+v) — refusing to write an archive that could not re-verify offline", res.Overall, res.Axes)
	}

	// Compose the file set (slash-separated rel path -> bytes).
	files := make(map[string][]byte, len(credBytes)+len(rec.raw))
	chainAddrs := make([]string, len(chain))
	for i, cred := range chain {
		h, err := cred.Hash()
		if err != nil {
			return nil, fmt.Errorf("bundle: content address: %w", err)
		}
		chainAddrs[i] = h
		rel, err := credentialPath(h)
		if err != nil {
			return nil, err
		}
		files[rel] = credBytes[h]
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
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("bundle: marshal manifest: %w", err)
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(filepath.Join(dir, manifestFile), raw, 0o644); err != nil {
		return nil, fmt.Errorf("bundle: write manifest: %w", err)
	}
	complete = true
	return &ExportResult{Manifest: m, Digest: digest(raw)}, nil
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
