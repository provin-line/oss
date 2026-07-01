package aggregate

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
)

// ManifestFold is the reference Fold: it emits a deterministic JSON manifest of
// the consumed sources' content addresses (sorted, with the count) via the
// stdlib encoder — byte-stable for an equal input set, which is what the audit
// value needs (it is not JCS-canonicalized; the strict gate only rejects
// malformed/trailing/duplicate-key output). Recording which
// inputs were consumed lives in the OUTPUT payload — the integrity-protected
// place for it (outputHash + the issuer's signature bind it), never a credential
// field (Paper 01 §4.8). A real deployment supplies its own Fold over the input
// payloads; this default makes the consumed set auditable from the output alone.
type ManifestFold struct{}

// Fold returns {"sources":[<sorted content addresses>],"count":N} as canonical
// JSON. The sort keeps the output byte-deterministic for an equal input set.
func (ManifestFold) Fold(_ context.Context, inputs []PooledInput) ([]byte, error) {
	hashes := make([]string, 0, len(inputs))
	for _, in := range inputs {
		h, err := in.Credential.Hash()
		if err != nil {
			return nil, fmt.Errorf("aggregate: hash source credential for manifest: %w", err)
		}
		hashes = append(hashes, h)
	}
	sort.Strings(hashes)
	return json.Marshal(struct {
		Sources []string `json:"sources"`
		Count   int      `json:"count"`
	}{Sources: hashes, Count: len(hashes)})
}
