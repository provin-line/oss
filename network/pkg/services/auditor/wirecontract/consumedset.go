package wirecontract

import (
	"errors"
	"fmt"
	"sort"

	"github.com/provin-line/oss/vc"
)

// CanonicalizeConsumedSet sorts and deduplicates a receipt's consumed source content addresses
// into the canonical form auditor.ReceiptStore.Put persists and compares against. It rejects a
// set that is empty after dedup and, per member, enforces the FULL content-address grammar
// (vc.IsContentAddress: "sha256:<64 lowercase hex>") — not merely a non-empty-string check. Both
// auditor.ReceiptStore implementations (auditor.MemReceiptStore and filestore.ReceiptStore) call
// this (via the auditor package's back-compat alias — PR3b Task 2 moved the definition into this
// leaf package) so canonicalization cannot drift between them, and auditor.EvidenceService.Register
// calls it too, so an authorized RegisterEvidence caller cannot pin an irreversible first-write-wins
// receipt with a malformed member — every reader downstream (GetConsumedSources, the
// source-commitment auditor) would otherwise treat it as damage. The grammar's fixed length and
// hex-only alphabet are also what make the wireauth handler's deterministic "\n" join over this
// canonical set (see RegisterEvidenceFields) collision-free: a member that could itself contain
// "\n" (or vary in length) would let two DIFFERENT consumed sets join to the SAME signed bytes —
// enforcing the grammar here is what rules that out, not an assumption at the join site.
//
// Moved out of the auditor service root into this leaf package (PR3b Task 2) so a client-only
// consumer of the wire contract need not import the service root; the auditor package keeps a
// var alias (see auditor/receipt.go) so existing call sites are unchanged.
func CanonicalizeConsumedSet(hashes []string) ([]string, error) {
	cp := make([]string, len(hashes))
	copy(cp, hashes)
	sort.Strings(cp)
	out := make([]string, 0, len(cp))
	for i, addr := range cp {
		if !vc.IsContentAddress(addr) {
			return nil, fmt.Errorf("auditor: consumed set member %q is not a sha256:<hex> content address", addr)
		}
		if i == 0 || addr != cp[i-1] {
			out = append(out, addr)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("auditor: consumed set is empty")
	}
	return out, nil
}
