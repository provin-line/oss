// Package numberinventory scans persisted JSON artifacts for numbers that the
// RFC 8785 canonicalization switch would re-serialize, so the switch can be
// gated on evidence rather than on an assumption (ForkW-1 §2.2b-1).
//
// Why it exists: content addresses are recomputed on read
// (vcresolver/filestore verifies a credential hashes to its own filename), so
// changing the canonicalizer changes the address of any artifact whose bytes
// change — and only integers outside ±(2^53-1) change. An artifact carrying one
// becomes unreadable at its stored address, breaking chains and source
// commitments even though its proof is still cryptographically valid. This
// package finds those artifacts first.
//
// It is internal on purpose: it is migration scaffolding, not a protocol
// surface, and it is expected to be deleted once the switch is behind us.
package numberinventory

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/provin-line/oss/canon"
)

// Finding is one artifact that blocks the switch.
type Finding struct {
	// File is the artifact's path.
	File string
	// Path locates the number inside the artifact ("credentialSubject.n").
	Path string
	// Literal is the raw token as stored.
	Literal string
	// Reason is why it blocks: an unsafe number, or an artifact that could not
	// be inspected at all.
	Reason string
}

// Report is the evidence a switch decision is recorded against.
type Report struct {
	// Roots are the directories scanned, as given.
	Roots []string
	// Scanned counts JSON artifacts successfully inspected.
	Scanned int
	// Unsafe counts artifacts carrying a number outside the safe range.
	Unsafe int
	// Undecodable counts artifacts the strict decoder rejected — these were
	// NOT inspected, so they are not evidence of safety.
	Undecodable int
	// Findings lists every blocker, unsafe and undecodable alike.
	Findings []Finding
}

// Safe reports whether the scan clears the switch: every artifact was
// inspected, and none carries an unsafe number. An uninspected artifact is not
// a pass — coverage that silently drops to zero is the failure mode this gate
// exists to prevent.
func (r *Report) Safe() bool { return r.Unsafe == 0 && r.Undecodable == 0 }

// Scan walks roots and inspects every .json artifact under them. A root that
// does not exist contributes nothing and is not an error: a store that was
// never created holds no artifacts, which is a real result.
//
// Payload blobs are out of scope by construction — only .json files are read,
// and payload bytes are outside every signature scope (a credential carries
// their string hash, never their numbers).
func Scan(roots ...string) (*Report, error) {
	rep := &Report{Roots: roots}
	for _, root := range roots {
		if err := scanRoot(root, rep); err != nil {
			return nil, err
		}
	}
	return rep, nil
}

func scanRoot(root string, rep *Report) error {
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".json") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("numberinventory: read %s: %w", path, err)
		}
		inspect(path, raw, rep)
		return nil
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// inspect decodes through the strict decoder — the raw-token stage, where
// integers survive as exact literals — and gates the result. Decoding with a
// lossy parser first would round the very values being looked for
// (canon.number.raw-token-guard).
func inspect(path string, raw []byte, rep *Report) {
	var v any
	if err := canon.NewStrictDecoder(raw).Decode(&v); err != nil {
		rep.Undecodable++
		rep.Findings = append(rep.Findings, Finding{
			File:   path,
			Reason: fmt.Sprintf("not inspectable (strict decode failed: %v)", err),
		})
		return
	}
	rep.Scanned++
	if err := canon.AdmitSafeNumbers(v); err != nil {
		var unsafeErr *canon.UnsafeNumberError
		f := Finding{File: path, Reason: err.Error()}
		if errors.As(err, &unsafeErr) {
			f.Path = unsafeErr.Path
			f.Literal = unsafeErr.Literal
			f.Reason = unsafeErr.Reason
		}
		rep.Unsafe++
		rep.Findings = append(rep.Findings, f)
	}
}
