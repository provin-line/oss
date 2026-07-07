// Package bundle defines the portable audit-evidence bundle: the on-disk
// convention a relying party archives during live operation so that a
// provenance chain re-verifies offline — years later, with every piece of
// the emitting infrastructure gone — plus the assembly (Export) and the
// offline verification (Verify) that operate it.
//
// A bundle is a directory:
//
//	<dir>/
//	  manifest.json                      versioned index (Manifest)
//	  credentials/<hex>.json             raw credential wire bytes, filename =
//	                                     content-address hex (the same naming
//	                                     as the node's evidence CAS)
//	  diddocs/<registry>/did/<seg>/…/did.json
//	                                     raw DID documents from the public
//	                                     resolution route; each
//	                                     diddocs/<registry>/ subtree mirrors
//	                                     that registry's route layout, so
//	                                     serving it at the registry's base URL
//	                                     is a conforming resolution endpoint
//
// # Two-tier external anchoring
//
// A credential's content address covers its BODY only — the proof is
// excluded from the hash. The chain head therefore transitively anchors
// every body (chain links live inside the signed bodies) but NOT the proof
// bytes or the archived DID documents: an attacker who can rewrite the whole
// bundle can re-sign the unchanged bodies under his own keys and swap the
// archived documents to present those keys under the original DIDs, and the
// same head still verifies. The manifest closes this: Files maps every
// bundle file to its sha256, and the BUNDLE DIGEST — the content address of
// the manifest bytes themselves, printed by Export — covers everything.
// Keep the bundle digest out-of-band to anchor *who signed*; the head alone
// (a sink record, an ingest 202 payload_hash) anchors *what data flowed*.
// Verify checks whichever anchors the caller supplies and reports which
// were checked.
//
// # Scope
//
// ScopeLinear covers a previousCredential walk from the head to a FirstDrop
// origin, verified across all three confidence axes including the full
// authority chain (process → pipeline → owner documents — signing keys
// alone are NOT a sufficient archive). A chain through an aggregate bundles
// fine (the aggregate FirstDrop is the origin), but the sources the
// aggregate consumed do not travel: the source commitment stays unevaluated,
// exactly like a linear-only AuditRecord. An aggregate-complete scope is a
// future manifest value, blocked on consumed-set exposure.
//
// Offline verification runs the provin profile's cryptosuite (ed25519 /
// EdDSA-JCS-2022) with no cryptosuite-lifecycle policy, matching the PoC
// node runtime.
package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/provin-line/oss/did/dplaax"
	"github.com/provin-line/oss/vc"
)

// ScopeLinear is the v1 manifest scope: the bundle claims a linear
// previousCredential chain and nothing beyond it.
const ScopeLinear = "linear"

// ScopeAggregateComplete is the v2 manifest scope: the bundle additionally
// carries, for every commitment-bearing credential, the consumed source
// credentials (and their whole linear subchains), so the source-commitment
// axis re-verifies offline. "Complete" means complete WITH RESPECT TO THE
// SIGNED CLAIMED SOURCE SET — it does not (and cryptographically cannot)
// prove the signer omitted nothing from the actual world.
const ScopeAggregateComplete = "aggregate-complete"

// DefaultMaxDepth bounds the export chain walk when ExportOptions.MaxDepth
// is unset — the same DoS backstop rationale as the batch resolver's
// max-depth: a hostile chain must not make the exporter walk forever.
const DefaultMaxDepth = 1024

const (
	manifestVersion = 1
	manifestFile    = "manifest.json"
	credentialsDir  = "credentials"
	didDocsDir      = "diddocs"
)

var (
	// ErrAnchorMismatch reports that a caller-supplied external anchor
	// (expected head or expected bundle digest) does not match the bundle.
	ErrAnchorMismatch = errors.New("bundle: anchor mismatch")
	// ErrBundleIntegrity reports structural damage or tampering: a listed
	// file missing or altered, an unlisted file present, a misfiled or
	// content-address-violating credential, a chain hole, or a manifest
	// index diverging from the evidence. A bundle is evidence — damage is
	// never treated as absence.
	ErrBundleIntegrity = errors.New("bundle: integrity violation")
)

// Manifest is the versioned bundle index. It is a convenience index over the
// evidence, never an authority: Verify recomputes everything it states and
// fails on divergence. CreatedAt and Source are advisory provenance only.
type Manifest struct {
	V            int               `json:"v"`
	Scope        string            `json:"scope"`
	Head         string            `json:"head"`
	Chain        []string          `json:"chain"` // origin-first content addresses of the MAIN spine
	DIDDocuments []string          `json:"didDocuments"`
	Files        map[string]string `json:"files"` // slash-separated rel path -> sha256 of the file bytes
	CreatedAt    string            `json:"createdAt"`
	Source       string            `json:"source,omitempty"`
	// Receipts (v2 / ScopeAggregateComplete only) maps every
	// aggregate-shaped commitment-bearing credential to its recorded
	// consumed set (lexicographic). Receipts are UNTRUSTED discovery hints,
	// never authority: verification recomputes the SIGNED Merkle root from
	// the bundled source credentials — a lying receipt cannot produce a
	// false Verified, it can only fail. nil on v1 manifests.
	Receipts map[string][]string `json:"receipts,omitempty"`
}

// The wire shapes are PER-VERSION EXACT structs: a v1 manifest carrying any
// v2-only member (receipts, even null) is rejected by the strict decoder by
// construction, so "v1 means exactly the shipped semantics" cannot erode.
type manifestWireV1 struct {
	V            int               `json:"v"`
	Scope        string            `json:"scope"`
	Head         string            `json:"head"`
	Chain        []string          `json:"chain"`
	DIDDocuments []string          `json:"didDocuments"`
	Files        map[string]string `json:"files"`
	CreatedAt    string            `json:"createdAt"`
	Source       string            `json:"source,omitempty"`
}

type manifestWireV2 struct {
	V            int                 `json:"v"`
	Scope        string              `json:"scope"`
	Head         string              `json:"head"`
	Chain        []string            `json:"chain"`
	DIDDocuments []string            `json:"didDocuments"`
	Files        map[string]string   `json:"files"`
	CreatedAt    string              `json:"createdAt"`
	Source       string              `json:"source,omitempty"`
	Receipts     map[string][]string `json:"receipts"`
}

// digest returns the content address of b — the same "sha256:<hex>" grammar
// as credential content addresses, here over literal file bytes.
func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// credentialPath returns the bundle-relative (slash-separated) path a
// credential with the given content address is stored at.
func credentialPath(hash string) (string, error) {
	if !vc.IsContentAddress(hash) {
		return "", fmt.Errorf("bundle: %q is not a content address", hash)
	}
	return credentialsDir + "/" + strings.TrimPrefix(hash, "sha256:") + ".json", nil
}

// documentPath returns the bundle-relative (slash-separated) path a DID's
// document is stored at: diddocs/<registry>/did/<segments…>/did.json — the
// registry's own resolution-route layout under a per-registry root. Parse
// validates every segment against the safe-segment rule, so the segments
// can participate in filesystem paths without traversal risk.
func documentPath(didStr string) (string, error) {
	d, err := dplaax.Parse(didStr)
	if err != nil {
		return "", fmt.Errorf("bundle: document path for %q: %w", didStr, err)
	}
	segs := append([]string{didDocsDir, d.Registry, "did", d.AccountType, d.AccountID}, d.ResourcePath...)
	return path.Join(append(segs, "did.json")...), nil
}

// didFromDocumentPath is the inverse of documentPath: it reconstructs the
// DID a diddocs entry claims to be for, so Verify can hold each archived
// document to its own location.
func didFromDocumentPath(rel string) (string, error) {
	parts := strings.Split(rel, "/")
	if len(parts) < 6 || parts[0] != didDocsDir || parts[2] != "did" || parts[len(parts)-1] != "did.json" {
		return "", fmt.Errorf("bundle: %q is not a document path (want %s/<registry>/did/<segments…>/did.json)", rel, didDocsDir)
	}
	didStr := "did:dplaax:" + parts[1] + ":" + strings.Join(parts[3:len(parts)-1], ":")
	if _, err := dplaax.Parse(didStr); err != nil {
		return "", fmt.Errorf("bundle: document path %q reconstructs an invalid DID: %w", rel, err)
	}
	return didStr, nil
}

// checkCaseFoldCollisions rejects a path set in which two distinct entries
// differ only by case: the safe-segment rule admits uppercase, and a
// case-insensitive filesystem (the macOS default) would silently merge such
// entries — an archive must not depend on the filesystem it happens to be
// unpacked on.
func checkCaseFoldCollisions(paths []string) error {
	seen := make(map[string]string, len(paths))
	for _, p := range paths {
		folded := strings.ToLower(p)
		if other, ok := seen[folded]; ok && other != p {
			return fmt.Errorf("bundle: case-fold path collision between %q and %q — case-insensitive filesystems would merge them", other, p)
		}
		seen[folded] = p
	}
	return nil
}
