package mirrorstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/provin-line/oss/canon"
	"github.com/provin-line/oss/tlog"
)

// checkpointFile holds the REMOTE loop-signed checkpoint, persisted
// verbatim: the registry has no loop key and never synthesizes or
// re-signs a checkpoint (D-T4), so every field the wire carries —
// including Signature and SignedBy — round-trips through this file.
const checkpointFile = "checkpoint.json"

// checkpointEnvelope is the on-disk shape. All six tlog.Checkpoint fields
// are carried; Signature round-trips through encoding/json's []byte<->
// base64 encoding exactly (JSON base64 is lossless), so "verbatim" holds
// through the file.
type checkpointEnvelope struct {
	V         int       `json:"v"`
	Origin    string    `json:"origin"`
	Size      uint64    `json:"size"`
	Head      string    `json:"head"`
	Timestamp time.Time `json:"timestamp"`
	SignedBy  string    `json:"signedBy"`
	Signature []byte    `json:"signature"`
}

func toEnvelope(cp *tlog.Checkpoint) checkpointEnvelope {
	return checkpointEnvelope{
		V: 1, Origin: cp.Origin, Size: cp.Size, Head: cp.Head,
		Timestamp: cp.Timestamp, SignedBy: cp.SignedBy, Signature: cp.Signature,
	}
}

func (e checkpointEnvelope) checkpoint() *tlog.Checkpoint {
	return &tlog.Checkpoint{
		Origin: e.Origin, Size: e.Size, Head: e.Head,
		Timestamp: e.Timestamp, SignedBy: e.SignedBy, Signature: e.Signature,
	}
}

// readCheckpointFile returns the persisted checkpoint for dir, or (nil,
// nil) if none has ever been written for this log.
func readCheckpointFile(dir string) (*tlog.Checkpoint, error) {
	raw, err := os.ReadFile(filepath.Join(dir, checkpointFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("mirrorstore: read checkpoint %s: %w", dir, err)
	}
	var env checkpointEnvelope
	if err := canon.NewStrictDecoder(raw).Decode(&env); err != nil {
		return nil, fmt.Errorf("mirrorstore: damaged checkpoint file %s: %w", dir, err)
	}
	if env.V != 1 {
		return nil, fmt.Errorf("mirrorstore: checkpoint %s: unsupported version %d", dir, env.V)
	}
	return env.checkpoint(), nil
}

// writeCheckpointFile atomically replaces the persisted checkpoint (tmp +
// fsync + rename + dir-fsync — writeAtomic). It is the LAST step of an
// AppendVerified call so a crash between the records fsync and this
// replace leaves the checkpoint at its PRIOR value and the excess records
// get truncated on the next Open (D-T4 crash ordering).
func writeCheckpointFile(dir string, cp *tlog.Checkpoint) error {
	// A local storage envelope, never hashed or signed over — the
	// checkpoint's OWN signature already covers Size/Head/Origin/SignedBy/
	// Timestamp (see tlog/checkpoint.go's SignedView); this envelope is just
	// how those already-signed bytes sit on disk
	// (canonicalizer-hygiene-exempt).
	raw, err := json.Marshal(toEnvelope(cp))
	if err != nil {
		return fmt.Errorf("mirrorstore: marshal checkpoint: %w", err)
	}
	if err := writeAtomic(filepath.Join(dir, checkpointFile), raw); err != nil {
		return fmt.Errorf("mirrorstore: write checkpoint %s: %w", dir, err)
	}
	return nil
}
