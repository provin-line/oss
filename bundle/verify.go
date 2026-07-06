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
	// Result is the chain verdict across the three confidence axes. Overall
	// below ConfidenceVerified means the evidence, though structurally
	// intact, does not verify.
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

	var m Manifest
	if err := canon.NewStrictDecoder(manifestRaw).Decode(&m); err != nil {
		return nil, fmt.Errorf("bundle: parse manifest: %w", err)
	}
	// Second pass for what the canonical-form decoder does not reject:
	// unknown members. The manifest is a strict envelope — an unrecognized
	// field is a version mismatch or tampering, not a passenger.
	// decoder-hygiene-exempt: supplementary unknown-field rejection layered over the canon strict decode above.
	strict := json.NewDecoder(bytes.NewReader(manifestRaw))
	strict.DisallowUnknownFields()
	if err := strict.Decode(new(Manifest)); err != nil {
		return nil, fmt.Errorf("bundle: parse manifest: %w", err)
	}
	if m.V != manifestVersion {
		return nil, fmt.Errorf("bundle: unsupported manifest version %d", m.V)
	}
	if m.Scope != ScopeLinear {
		return nil, fmt.Errorf("bundle: unsupported scope %q", m.Scope)
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
	if len(creds) != len(chain) {
		return nil, fmt.Errorf("%w: %d credential files but the chain links %d — a bundle carries exactly its evidence", ErrBundleIntegrity, len(creds), len(chain))
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

	res, err := vc.NewVerifier(&archiveResolver{docs: index}, ed25519.Verifier{}).VerifyChain(ctx, chain)
	if err != nil {
		return nil, fmt.Errorf("bundle: verify chain: %w", err)
	}
	return &Report{
		Head:           m.Head,
		Digest:         dig,
		ChainLength:    len(chain),
		AnchoredHead:   opts.ExpectedHead != "",
		AnchoredDigest: opts.ExpectedDigest != "",
		Result:         res,
	}, nil
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
