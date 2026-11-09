package auditor

import (
	"github.com/provin-line/oss/internal/excerpt"
	"github.com/provin-line/oss/internal/netexcerpt"
)

// boundNotations is notes with each within netexcerpt.TextLimit bytes of
// UTF-8. It returns notes itself when every one fits, and otherwise a new
// slice, so a record a store holds is never changed.
func boundNotations(notes []string) []string {
	for i, n := range notes {
		if v, _ := excerpt.Of(n, netexcerpt.TextLimit); v != n {
			out := make([]string, len(notes))
			copy(out, notes[:i])
			for j := i; j < len(notes); j++ {
				out[j], _ = excerpt.Of(notes[j], netexcerpt.TextLimit)
			}
			return out
		}
	}
	return notes
}

// boundRecord is rec with its notations bounded (boundNotations). The runner
// records it, and the status service serves it whatever the store holds: a
// store holds no validation of its own.
func boundRecord(rec AuditRecord) AuditRecord {
	rec.Notations = boundNotations(rec.Notations)
	rec.SourceCommitmentNotations = boundNotations(rec.SourceCommitmentNotations)
	return rec
}
