package bundle

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/provin-line/oss/canon"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/resolver"
	"github.com/provin-line/oss/vc"
)

// VerifyOptions carries the caller's external anchors. Both are optional at
// this layer (the CLI enforces at least one): an unanchored Verify still
// checks internal integrity end to end, but its verdict is only as
// trustworthy as the bundle's own manifest.
type VerifyOptions struct {
	// ExpectedHead anchors what data flowed: it must equal the manifest head
	// (which every credential body is then verified against).
	ExpectedHead string
	// ExpectedDigest anchors who signed it: the bundle digest kept from
	// export must equal the manifest bytes' content address, which through
	// Manifest.Files covers every archived byte including proofs and DID
	// documents.
	ExpectedDigest string
}

// Report is the offline verdict and what it was computed over.
type Report struct {
	Head        string
	Digest      string // the bundle digest computed from the manifest bytes
	ChainLength int
	// AnchoredHead / AnchoredDigest record which external anchors were
	// supplied and checked — a consumer of the report must know whether the
	// verdict is externally anchored or bundle-self-referential.
	AnchoredHead   bool
	AnchoredDigest bool
	// Scope is the manifest's verified coverage claim (ScopeLinear or
	// ScopeAggregateComplete).
	Scope string
	// Aggregates / Sources count the commitment-bearing credentials whose
	// source commitments were recomputed offline, and the total source
	// credentials fed to those recomputations. Zero on linear bundles.
	Aggregates int
	Sources    int
	// Result is the verdict across the three confidence axes; on an
	// aggregate-complete bundle its Overall additionally folds in every
	// source subchain's verdict and every source-commitment recomputation
	// (weakest link — anything below Verified means the evidence, though
	// structurally intact, does not verify).
	Result *vc.VerifyResult
}

// Verify loads the bundle at dir and re-verifies the entire chain offline:
// anchors, per-file digests, content addresses, chain structure, proofs,
// and authority chains. It never dials — its resolver is backed exclusively
// by the bundle's diddocs tree, and within that closed world absence is
// definitive (a missing document fails the axis that needed it, it does not
// leave it indeterminate).
//
// Structural damage — a listed file missing or altered, an unlisted file,
// a chain hole, a manifest index diverging from the evidence — is an error
// wrapping ErrBundleIntegrity: an archive is evidence, damage is never
// treated as a lesser verdict. A structurally intact bundle whose chain
// does not verify returns a Report with the failing axes and no error.
func Verify(ctx context.Context, dir string, opts VerifyOptions) (*Report, error) {
	manifestRaw, err := readBundleFile(dir, manifestFile)
	if err != nil {
		return nil, fmt.Errorf("bundle: read manifest: %w", err)
	}
	dig := digest(manifestRaw)
	if opts.ExpectedDigest != "" && dig != opts.ExpectedDigest {
		return nil, fmt.Errorf("%w: bundle digest is %s, expected %s", ErrAnchorMismatch, dig, opts.ExpectedDigest)
	}

	m, err := decodeManifest(manifestRaw)
	if err != nil {
		return nil, err
	}
	if !vc.IsContentAddress(m.Head) {
		return nil, fmt.Errorf("%w: manifest head %q is not a content address", ErrBundleIntegrity, m.Head)
	}
	if opts.ExpectedHead != "" && m.Head != opts.ExpectedHead {
		return nil, fmt.Errorf("%w: manifest head is %s, expected %s", ErrAnchorMismatch, m.Head, opts.ExpectedHead)
	}

	// Per-file integrity: every listed path structurally valid, no
	// case-fold collisions, every listed file present with matching digest,
	// no unlisted file present. Structure and collisions are checked BEFORE
	// any file is opened: a hostile manifest must not drive a single read.
	rels := make([]string, 0, len(m.Files))
	for rel := range m.Files {
		if err := checkListedPath(rel); err != nil {
			return nil, err
		}
		rels = append(rels, rel)
	}
	if err := checkCaseFoldCollisions(rels); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBundleIntegrity, err)
	}
	fileBytes := make(map[string][]byte, len(m.Files))
	for rel, want := range m.Files {
		b, err := readBundleFile(dir, rel)
		if err != nil {
			return nil, fmt.Errorf("%w: listed file %s: %v", ErrBundleIntegrity, rel, err)
		}
		if digest(b) != want {
			return nil, fmt.Errorf("%w: %s does not match its manifest digest", ErrBundleIntegrity, rel)
		}
		fileBytes[rel] = b
	}
	for _, sub := range []string{credentialsDir, didDocsDir} {
		if err := checkNoUnlistedFiles(dir, sub, m.Files); err != nil {
			return nil, err
		}
	}

	// Load credentials, holding each file to its own name: the filename IS
	// the claimed content address, and the bytes must hash to it.
	creds := make(map[string]*vc.PipelinePassCredential)
	for rel, raw := range fileBytes {
		if !strings.HasPrefix(rel, credentialsDir+"/") {
			continue
		}
		addr := "sha256:" + strings.TrimSuffix(path.Base(rel), ".json")
		if !strings.HasSuffix(rel, ".json") || !vc.IsContentAddress(addr) {
			return nil, fmt.Errorf("%w: %s is not a credential entry (want %s/<hex>.json)", ErrBundleIntegrity, rel, credentialsDir)
		}
		cred := new(vc.PipelinePassCredential)
		if err := cred.UnmarshalJSON(raw); err != nil {
			return nil, fmt.Errorf("%w: parse credential %s: %v", ErrBundleIntegrity, rel, err)
		}
		got, err := cred.Hash()
		if err != nil {
			return nil, fmt.Errorf("%w: content address of %s: %v", ErrBundleIntegrity, rel, err)
		}
		if got != addr {
			return nil, fmt.Errorf("%w: %s is misfiled — its bytes hash to %s", ErrBundleIntegrity, rel, got)
		}
		creds[addr] = cred
	}

	// Rebuild the chain origin-first from the signed links, then hold the
	// manifest's convenience index to it.
	var chain []*vc.PipelinePassCredential
	var chainAddrs []string
	visited := make(map[string]bool)
	for cur := m.Head; cur != ""; {
		if visited[cur] {
			return nil, fmt.Errorf("%w: chain link cycle at %s", ErrBundleIntegrity, cur)
		}
		visited[cur] = true
		cred, ok := creds[cur]
		if !ok {
			return nil, fmt.Errorf("%w: chain hole — credential %s is linked but not in the bundle", ErrBundleIntegrity, cur)
		}
		chain = append(chain, cred)
		chainAddrs = append(chainAddrs, cur)
		cur = cred.PreviousCredential()
	}
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
		chainAddrs[i], chainAddrs[j] = chainAddrs[j], chainAddrs[i]
	}
	if len(chainAddrs) != len(m.Chain) {
		return nil, fmt.Errorf("%w: manifest chain lists %d credentials, the evidence links %d", ErrBundleIntegrity, len(m.Chain), len(chainAddrs))
	}
	for i, addr := range chainAddrs {
		if m.Chain[i] != addr {
			return nil, fmt.Errorf("%w: manifest chain[%d] is %s, the evidence links %s", ErrBundleIntegrity, i, m.Chain[i], addr)
		}
	}
	// Exactly-its-evidence: v1 compares against the single spine; v2 uses
	// SET semantics against the union of every spine (below), because a
	// consumed source may legitimately be shared (diamond) yet stored once.
	if m.V == 1 && len(creds) != len(chain) {
		return nil, fmt.Errorf("%w: %d credential files but the chain links %d — a bundle carries exactly its evidence", ErrBundleIntegrity, len(creds), len(chain))
	}

	// v2: receipts sanity, commitment coverage, source spines, union rule.
	var sourceSpines map[string][]*vc.PipelinePassCredential
	var commitJobs map[string][]*vc.PipelinePassCredential
	if m.V == 2 {
		sourceSpines = map[string][]*vc.PipelinePassCredential{}
		commitJobs = map[string][]*vc.PipelinePassCredential{}
		union := make(map[string]bool, len(creds))
		for _, addr := range chainAddrs {
			union[addr] = true
		}
		for k, entry := range m.Receipts {
			c, ok := creds[k]
			if !ok {
				return nil, fmt.Errorf("%w: receipts key %s is not a bundled credential", ErrBundleIntegrity, k)
			}
			sc := c.SourceCommitment()
			if sc == nil || len(sc.DerivedFrom) == 0 || c.PreviousCredential() != "" {
				return nil, fmt.Errorf("%w: receipts entry for %s, which is not an aggregate-shaped commitment-bearing credential", ErrBundleIntegrity, k)
			}
			if len(entry) == 0 {
				return nil, fmt.Errorf("%w: receipt for %s is empty — all-consumed receipts are never empty", ErrBundleIntegrity, k)
			}
			for i, sh := range entry {
				if !vc.IsContentAddress(sh) {
					return nil, fmt.Errorf("%w: receipt for %s: entry %q is not a content address", ErrBundleIntegrity, k, sh)
				}
				if sh == k {
					// A self-referential receipt would put k on its own
					// "source spine" and launder a spineless credential past
					// the union rule (verdict-safe — a credential cannot
					// commit to its own hash — but spineless extras are an
					// INTEGRITY error, not a verdict downgrade).
					return nil, fmt.Errorf("%w: receipt for %s lists the credential itself as a source", ErrBundleIntegrity, k)
				}
				if i > 0 && entry[i-1] >= sh {
					return nil, fmt.Errorf("%w: receipt for %s is not strictly ascending at %s (duplicates and unsorted receipts are malformed evidence)", ErrBundleIntegrity, k, sh)
				}
				if _, ok := creds[sh]; !ok {
					return nil, fmt.Errorf("%w: consumed source %s (receipt of %s) is not bundled", ErrBundleIntegrity, sh, k)
				}
				if _, done := sourceSpines[sh]; done {
					continue
				}
				sp, err := rebuildSpine(creds, sh)
				if err != nil {
					return nil, err
				}
				sourceSpines[sh] = sp
				for _, spc := range sp {
					h, err := spc.Hash()
					if err != nil {
						return nil, fmt.Errorf("%w: content address: %v", ErrBundleIntegrity, err)
					}
					union[h] = true
				}
			}
		}
		// Commitment coverage over EVERY bundled credential, by shape: no
		// silent linear-only downgrade offline (the AuditScope doctrine).
		for h, c := range creds {
			sc := c.SourceCommitment()
			if sc == nil {
				continue
			}
			_, hasReceipt := m.Receipts[h]
			switch {
			case len(sc.DerivedFrom) == 0:
				if hasReceipt {
					return nil, fmt.Errorf("%w: receipts entry for %s, whose commitment claims zero sources", ErrBundleIntegrity, h)
				}
				commitJobs[h] = nil
			case c.PreviousCredential() != "":
				if hasReceipt {
					return nil, fmt.Errorf("%w: receipts entry for chain-preserving credential %s (its source is its bundled predecessor)", ErrBundleIntegrity, h)
				}
				prev, ok := creds[c.PreviousCredential()]
				if !ok {
					return nil, fmt.Errorf("%w: chain hole — credential %s is linked but not in the bundle", ErrBundleIntegrity, c.PreviousCredential())
				}
				commitJobs[h] = []*vc.PipelinePassCredential{prev}
			default:
				if !hasReceipt {
					return nil, fmt.Errorf("%w: commitment-bearing credential %s has no receipts entry — an aggregate-complete bundle must not silently downgrade to linear-only coverage", ErrBundleIntegrity, h)
				}
				var srcs []*vc.PipelinePassCredential
				for _, sh := range m.Receipts[h] {
					srcs = append(srcs, creds[sh])
				}
				commitJobs[h] = srcs
			}
		}
		for h := range creds {
			if !union[h] {
				return nil, fmt.Errorf("%w: credential %s lies on no spine — a bundle carries exactly its evidence", ErrBundleIntegrity, h)
			}
		}
	}

	// Index the archived documents, holding each to its own location, and
	// the manifest's document index to the evidence.
	index := make(map[string]*did.DIDDocument)
	var docDIDs []string
	for rel, raw := range fileBytes {
		if !strings.HasPrefix(rel, didDocsDir+"/") {
			continue
		}
		didStr, err := didFromDocumentPath(rel)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrBundleIntegrity, err)
		}
		doc := new(did.DIDDocument)
		if err := doc.UnmarshalJSON(raw); err != nil {
			return nil, fmt.Errorf("%w: parse document %s: %v", ErrBundleIntegrity, rel, err)
		}
		if doc.ID() != didStr {
			return nil, fmt.Errorf("%w: %s holds a document for %q, not its own location's DID %q", ErrBundleIntegrity, rel, doc.ID(), didStr)
		}
		index[didStr] = doc
		docDIDs = append(docDIDs, didStr)
	}
	sort.Strings(docDIDs)
	manifestDIDs := append([]string(nil), m.DIDDocuments...)
	sort.Strings(manifestDIDs)
	if len(docDIDs) != len(manifestDIDs) {
		return nil, fmt.Errorf("%w: manifest lists %d documents, the bundle holds %d", ErrBundleIntegrity, len(manifestDIDs), len(docDIDs))
	}
	for i := range docDIDs {
		if docDIDs[i] != manifestDIDs[i] {
			return nil, fmt.Errorf("%w: manifest document index diverges from the evidence at %q", ErrBundleIntegrity, docDIDs[i])
		}
	}

	verifier := vc.NewVerifier(&archiveResolver{docs: index}, ed25519.Verifier{})
	res, err := verifier.VerifyChain(ctx, chain)
	if err != nil {
		return nil, fmt.Errorf("bundle: verify chain: %w", err)
	}
	aggregates, sources := 0, 0
	if m.V == 2 {
		// Weakest-link composition: every source subchain and every source
		// commitment folds into the overall verdict, annotated so a reader
		// can see which sub-verdict dragged it down.
		spineHeads := make([]string, 0, len(sourceSpines))
		for sh := range sourceSpines {
			spineHeads = append(spineHeads, sh)
		}
		sort.Strings(spineHeads)
		for _, sh := range spineHeads {
			sp := sourceSpines[sh]
			sres, err := verifier.VerifyChain(ctx, sp)
			if err != nil {
				return nil, fmt.Errorf("bundle: verify source subchain %s: %w", sh, err)
			}
			if sres.Overall < res.Overall {
				res.Overall = sres.Overall
			}
			if sres.Overall != vc.ConfidenceVerified {
				res.Notations = append(res.Notations, fmt.Sprintf("source subchain %s: %v", sh, sres.Overall))
			}
		}
		commitHeads := make([]string, 0, len(commitJobs))
		for h := range commitJobs {
			commitHeads = append(commitHeads, h)
		}
		sort.Strings(commitHeads)
		for _, h := range commitHeads {
			srcs := commitJobs[h]
			state, err := verifier.VerifySourceCommitment(ctx, creds[h], srcs)
			if err != nil {
				return nil, fmt.Errorf("bundle: verify source commitment of %s: %w", h, err)
			}
			aggregates++
			sources += len(srcs)
			if state < res.Overall {
				res.Overall = state
			}
			if state != vc.ConfidenceVerified {
				res.Notations = append(res.Notations, fmt.Sprintf("source commitment %s: %v (recomputed from the bundled sources)", h, state))
			}
		}
	}
	return &Report{
		Head:           m.Head,
		Digest:         dig,
		ChainLength:    len(chain),
		AnchoredHead:   opts.ExpectedHead != "",
		AnchoredDigest: opts.ExpectedDigest != "",
		Scope:          m.Scope,
		Aggregates:     aggregates,
		Sources:        sources,
		Result:         res,
	}, nil
}

// decodeManifest probes {v} strictly, then decodes through the PER-VERSION
// exact wire struct: unknown members (including a v2-only member on a v1
// manifest) are rejected by construction.
func decodeManifest(raw []byte) (*Manifest, error) {
	var probe struct {
		V int `json:"v"`
	}
	if err := canon.NewStrictDecoder(raw).Decode(&probe); err != nil {
		return nil, fmt.Errorf("bundle: parse manifest: %w", err)
	}
	v := probe.V
	strictInto := func(dst any) error {
		// decoder-hygiene-exempt: unknown-field rejection layered over the canon strict probe above.
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		return dec.Decode(dst)
	}
	switch v {
	case 1:
		var w manifestWireV1
		if err := strictInto(&w); err != nil {
			return nil, fmt.Errorf("bundle: parse v1 manifest: %w", err)
		}
		if w.Scope != ScopeLinear {
			return nil, fmt.Errorf("bundle: unsupported scope %q for manifest v1", w.Scope)
		}
		return &Manifest{V: w.V, Scope: w.Scope, Head: w.Head, Chain: w.Chain,
			DIDDocuments: w.DIDDocuments, Files: w.Files, CreatedAt: w.CreatedAt, Source: w.Source}, nil
	case 2:
		var w manifestWireV2
		if err := strictInto(&w); err != nil {
			return nil, fmt.Errorf("bundle: parse v2 manifest: %w", err)
		}
		if w.Scope != ScopeAggregateComplete {
			return nil, fmt.Errorf("bundle: unsupported scope %q for manifest v2", w.Scope)
		}
		return &Manifest{V: w.V, Scope: w.Scope, Head: w.Head, Chain: w.Chain,
			DIDDocuments: w.DIDDocuments, Files: w.Files, CreatedAt: w.CreatedAt, Source: w.Source,
			Receipts: w.Receipts}, nil
	default:
		return nil, fmt.Errorf("bundle: unsupported manifest version %d", v)
	}
}

// rebuildSpine walks previousCredential links from `from` over the bundled
// credentials, origin-first; a hole is a named integrity error.
func rebuildSpine(creds map[string]*vc.PipelinePassCredential, from string) ([]*vc.PipelinePassCredential, error) {
	var spine []*vc.PipelinePassCredential
	seen := map[string]bool{}
	for cur := from; cur != ""; {
		if seen[cur] {
			return nil, fmt.Errorf("%w: chain link cycle at %s", ErrBundleIntegrity, cur)
		}
		seen[cur] = true
		c, ok := creds[cur]
		if !ok {
			return nil, fmt.Errorf("%w: chain hole — credential %s is linked but not in the bundle", ErrBundleIntegrity, cur)
		}
		spine = append(spine, c)
		cur = c.PreviousCredential()
	}
	for i, j := 0, len(spine)-1; i < j; i, j = i+1, j-1 {
		spine[i], spine[j] = spine[j], spine[i]
	}
	return spine, nil
}

// checkListedPath fail-closes a manifest that tries to drive reads outside
// the bundle. The check is STRUCTURAL, not lexical: a listed path must be
// byte-identical to what the exporter's own path constructors produce — a
// credential entry directly under credentials/ named by a content address,
// or a document entry that round-trips through didFromDocumentPath. That
// whitelists the charset (no separators, no backslashes — path.Clean treats
// `\` as an ordinary byte, so a lexical check would pass `credentials/..\..`
// and Windows path cleaning would then walk it out of the bundle) and
// forbids subdirectory credential entries, which would let two files carry
// the same content address with different proof bytes and make the verdict
// depend on map order.
func checkListedPath(rel string) error {
	switch {
	case strings.HasPrefix(rel, credentialsDir+"/"):
		base, ok := strings.CutSuffix(path.Base(rel), ".json")
		if !ok || !vc.IsContentAddress("sha256:"+base) {
			return fmt.Errorf("%w: manifest lists %q, not a credential entry (want %s/<hex>.json)", ErrBundleIntegrity, rel, credentialsDir)
		}
		if want, err := credentialPath("sha256:" + base); err != nil || rel != want {
			return fmt.Errorf("%w: manifest lists %q, want %s/<hex>.json directly under %s/", ErrBundleIntegrity, rel, credentialsDir, credentialsDir)
		}
	case strings.HasPrefix(rel, didDocsDir+"/"):
		didStr, err := didFromDocumentPath(rel)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrBundleIntegrity, err)
		}
		want, err := documentPath(didStr)
		if err != nil || rel != want {
			return fmt.Errorf("%w: manifest lists %q, which does not round-trip its DID's document path", ErrBundleIntegrity, rel)
		}
	default:
		return fmt.Errorf("%w: manifest lists %q outside %s/ and %s/", ErrBundleIntegrity, rel, credentialsDir, didDocsDir)
	}
	return nil
}

// maxBundleFileSize bounds a single bundle-file read. Bundle contents are
// hostile input to Verify; a regular-file check stops devices and FIFOs, and
// this cap stops a grown regular file from exhausting memory. Generous
// against real evidence: the node's own credential and document caps are
// 1 MiB each.
const maxBundleFileSize = 16 << 20

// readBundleFile reads one bundle-relative file with the hostile-input
// defenses Verify requires: the entry must be a REGULAR file (a symlink
// would make an offline verification depend on bytes outside the archive —
// or worse, act as an out-of-bundle read oracle; a FIFO would block it) and
// within the size cap.
func readBundleFile(dir, rel string) ([]byte, error) {
	abs := filepath.Join(dir, filepath.FromSlash(rel))
	fi, err := os.Lstat(abs)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file (mode %s) — an archive holds bytes, not links or devices", fi.Mode())
	}
	if fi.Size() > maxBundleFileSize {
		return nil, fmt.Errorf("%d bytes exceeds the %d-byte bundle file cap", fi.Size(), maxBundleFileSize)
	}
	return os.ReadFile(abs)
}

// checkNoUnlistedFiles walks one evidence subtree and rejects any regular
// file the manifest does not list — an unlisted file in an archive is a
// tamper signal, not a passenger.
func checkNoUnlistedFiles(dir, sub string, listed map[string]string) error {
	root := filepath.Join(dir, sub)
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		if _, ok := listed[filepath.ToSlash(rel)]; !ok {
			return fmt.Errorf("%w: %s is not listed in the manifest", ErrBundleIntegrity, filepath.ToSlash(rel))
		}
		return nil
	})
	switch {
	case err == nil, errors.Is(err, fs.ErrNotExist):
		// An absent subtree is governed by the listed-files check, not here.
		return nil
	case errors.Is(err, ErrBundleIntegrity):
		return err
	default:
		return fmt.Errorf("bundle: walk %s: %w", sub, err)
	}
}

// archiveResolver resolves DIDs over the bundle's archived documents only —
// the offline verifier's closed world. Absence from an archive is
// definitive (resolver.ErrNotFound), never transient: there is no "later"
// in which a dead registry starts answering.
type archiveResolver struct {
	docs map[string]*did.DIDDocument
}

func (a *archiveResolver) Resolve(_ context.Context, didStr string) (*did.DIDDocument, error) {
	doc, ok := a.docs[didStr]
	if !ok {
		return nil, fmt.Errorf("bundle: no document archived for %s: %w", didStr, resolver.ErrNotFound)
	}
	return doc, nil
}
