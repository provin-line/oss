package decisionrecord

// KeptDecisionIDs is how many decision ids f keeps in its summary window.
func KeptDecisionIDs(f *Filter) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, w := range f.windows {
		n += len(w.accepted)
	}
	return n
}
