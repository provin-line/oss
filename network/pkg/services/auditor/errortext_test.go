package auditor

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/provin-line/oss/internal/netexcerpt"
	"github.com/provin-line/oss/vc"
)

// longText is far longer than any text the auditor writes, with line breaks
// and bytes that are not UTF-8.
var longText = strings.Repeat("ab\n\xff", 64<<10)

func requireNotationsBounded(t *testing.T, what string, notes []string) {
	t.Helper()
	if len(notes) == 0 {
		t.Fatalf("%s: no notation", what)
	}
	for _, n := range notes {
		if len(n) > netexcerpt.TextLimit || !utf8.ValidString(n) {
			t.Errorf("%s: notation of %d bytes (UTF-8: %v): %.80q", what, len(n), utf8.ValidString(n), n)
		}
	}
}

type errReceipts struct{ err error }

func (r errReceipts) Get(string) ([]string, error) { return nil, r.err }

// Each notation the runner records is within netexcerpt.TextLimit bytes of
// UTF-8, however long the text it takes from an error or a receipt: a verify
// error, an unreadable receipt, a corrupt receipt entry, a verifier's error.
func TestRunner_RecordsNotationsWithinTheLimit(t *testing.T) {
	ctx := context.Background()

	cv := fakeCV{fn: func() (*vc.VerifyResult, error) { return nil, errors.New(longText) }}
	r, _, status := newRunner(t, cv, headStore(), fakePool{}, okCfg())
	r.logger = log.New(io.Discard, "", 0)
	_ = r.drainOnce(ctx)
	rec, err := status.Get(headH)
	if err != nil {
		t.Fatal(err)
	}
	requireNotationsBounded(t, "verify error", rec.Notations)

	verified := fakeCV{fn: func() (*vc.VerifyResult, error) { return verifiedResult(), nil }}
	sources := map[string]*vc.PipelinePassCredential{scSrc1: {}, scSrc2: {}}
	for _, c := range []struct {
		name     string
		receipts ReceiptReader
		scv      *fakeSCV
	}{
		{"unreadable receipt", errReceipts{errors.New(longText)}, &fakeSCV{state: vc.ConfidenceVerified}},
		{"corrupt receipt entry", fakeReceipts{m: map[string][]string{headH: {longText}}}, &fakeSCV{state: vc.ConfidenceVerified}},
		{"verifier error", fakeReceipts{m: map[string][]string{headH: {scSrc1, scSrc2}}}, &fakeSCV{state: vc.ConfidenceFailed, err: errors.New(longText)}},
	} {
		r, _, status := newRunnerSC(t, verified, c.receipts, c.scv, sources)
		r.logger = log.New(io.Discard, "", 0)
		_ = r.drainOnce(ctx)
		rec, err := status.Get(headH)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		requireNotationsBounded(t, c.name, rec.SourceCommitmentNotations)
		if c.name == "corrupt receipt entry" {
			if max := 96 + netexcerpt.ValueLimit; len(rec.SourceCommitmentNotations[0]) > max {
				t.Errorf("%s: notation of %d bytes names the entry past netexcerpt.ValueLimit", c.name, len(rec.SourceCommitmentNotations[0]))
			}
		}
	}
}

// A consumed hash that is not a content address is refused with the hash
// named within netexcerpt.ValueLimit bytes, however long.
func TestConsumeVerify_NamesAMalformedHashWithinTheLimit(t *testing.T) {
	_, err := newConsumeVerifier(t, &fakeSCV{}, &fakeSourceResolver{}).Verify(context.Background(), &vc.PipelinePassCredential{}, []string{longText})
	if !errors.Is(err, ErrInvalidConsumedHash) {
		t.Fatalf("Verify: %v, want ErrInvalidConsumedHash", err)
	}
	if max := 64 + netexcerpt.ValueLimit; len(err.Error()) > max {
		t.Errorf("error of %d bytes, want at most %d", len(err.Error()), max)
	}
}

// A record served by GetStatus and ListStatuses has each notation within
// netexcerpt.TextLimit bytes, whatever the store holds; the notations that
// fit, before and after a long one, are served as they are, and the stored
// record is left as it is.
func TestStatusService_ServesNotationsWithinTheLimit(t *testing.T) {
	ctx := context.Background()
	h := "sha256:" + strings.Repeat("a", 64)
	store := NewMemStatusStore()
	if err := store.Put(h, AuditRecord{
		Notations:                 []string{"first", longText, "last"},
		SourceCommitmentNotations: []string{longText},
		Scope:                     AuditScope{LinearChain: true, SourceCommitmentEvaluated: true},
		AuditedAt:                 time.Unix(1, 0),
	}); err != nil {
		t.Fatal(err)
	}
	svc := NewStatusService(store, NewMemReceiptStore())

	rec, err := svc.GetStatus(ctx, h)
	if err != nil {
		t.Fatal(err)
	}
	requireNotationsBounded(t, "GetStatus", rec.Notations)
	requireNotationsBounded(t, "GetStatus", rec.SourceCommitmentNotations)
	if rec.Notations[0] != "first" || rec.Notations[2] != "last" {
		t.Errorf("notations that fit became %q and %q", rec.Notations[0], rec.Notations[2])
	}

	entries, _, _, err := svc.ListStatuses(ctx, "", 10, time.Time{}, time.Time{})
	if err != nil || len(entries) != 1 {
		t.Fatalf("ListStatuses: %v, %d entries", err, len(entries))
	}
	requireNotationsBounded(t, "ListStatuses", entries[0].Record.Notations)
	requireNotationsBounded(t, "ListStatuses", entries[0].Record.SourceCommitmentNotations)

	stored, err := store.Get(h)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Notations[1] != longText || stored.SourceCommitmentNotations[0] != longText {
		t.Error("serving a record changed the stored one")
	}
}

// A consume-locus verdict's notation is within netexcerpt.TextLimit bytes,
// however long the resolver's or the verifier's error.
func TestConsumeVerify_NotationWithinTheLimit(t *testing.T) {
	ctx := context.Background()
	cA, hA := srcCred(t, "did:example:a")

	unavailable := &fakeSourceResolver{errs: map[string]error{hA: errors.New(longText)}}
	got, err := newConsumeVerifier(t, &fakeSCV{}, unavailable).Verify(ctx, &vc.PipelinePassCredential{}, []string{hA})
	if err != nil {
		t.Fatal(err)
	}
	requireNotationsBounded(t, "unavailable source", []string{got.Notation})

	scv := &fakeSCV{state: vc.ConfidenceFailed, err: errors.New(longText)}
	resolved := &fakeSourceResolver{byHash: map[string]*vc.PipelinePassCredential{hA: cA}}
	got, err = newConsumeVerifier(t, scv, resolved).Verify(ctx, &vc.PipelinePassCredential{}, []string{hA})
	if err != nil {
		t.Fatal(err)
	}
	requireNotationsBounded(t, "verifier error", []string{got.Notation})
}

// failingHeads fails every resolution with err.
type failingHeads struct{ err error }

func (f failingHeads) ResolveVC(context.Context, string) (*vc.PipelinePassCredential, error) {
	return nil, f.err
}

// A log line of the runner names an error quoted within netexcerpt.TextLimit
// bytes, on one line, however long or many-lined the error.
func TestRunner_LogsAnErrorWithinTheLimit(t *testing.T) {
	var buf bytes.Buffer
	cv := fakeCV{fn: func() (*vc.VerifyResult, error) { return verifiedResult(), nil }}
	r, _, _ := newRunner(t, cv, failingHeads{errors.New(longText)}, fakePool{}, okCfg())
	r.logger = log.New(&buf, "", 0)
	_ = r.drainOnce(context.Background())
	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("logged %d lines, want 1: %.200q", len(lines), buf.String())
	}
	if max := 128 + len(headH) + netexcerpt.TextLimit; len(lines[0]) > max {
		t.Errorf("log line of %d bytes, want at most %d", len(lines[0]), max)
	}
}

// An unresolved predecessor, which the chain verifier names, is named in the
// notation and in the log line of an abandoned head within
// netexcerpt.ValueLimit bytes, on one line.
func TestRunner_NamesAnUnresolvedPredecessorWithinTheLimit(t *testing.T) {
	var buf bytes.Buffer
	cv := fakeCV{fn: func() (*vc.VerifyResult, error) { return nil, holeErr{hash: longText} }}
	r, _, status := newRunner(t, cv, headStore(), fakePool{}, Config{Interval: time.Second, BatchSize: 16, MaxAttempts: 1})
	r.logger = log.New(&buf, "", 0)
	_ = r.drainOnce(context.Background())
	rec, err := status.Get(headH)
	if err != nil {
		t.Fatal(err)
	}
	requireNotationsBounded(t, "unresolved predecessor", rec.Notations)
	for _, n := range rec.Notations {
		if max := 96 + netexcerpt.ValueLimit; len(n) > max {
			t.Errorf("notation of %d bytes names the predecessor past netexcerpt.ValueLimit: %.80q", len(n), n)
		}
	}
	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("logged %d lines, want 1: %.200q", len(lines), buf.String())
	}
	if max := 128 + len(headH) + netexcerpt.ValueLimit; len(lines[0]) > max {
		t.Errorf("log line of %d bytes, want at most %d", len(lines[0]), max)
	}
}
