package decisionrecord_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/provin-line/oss/contentaddress"
	"github.com/provin-line/oss/decisionrecord"
)

// address is the content address s spells.
func address(t *testing.T, s string) contentaddress.Address {
	t.Helper()
	a, err := contentaddress.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// memSink keeps what it is given, and fails while err is set.
type memSink struct {
	mu        sync.Mutex
	records   []decisionrecord.Record
	summaries []decisionrecord.Summary
	err       error
}

func (m *memSink) Record(_ context.Context, r decisionrecord.Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.records = append(m.records, r)
	return nil
}

func (m *memSink) Summary(_ context.Context, s decisionrecord.Summary) error {
	if err := s.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.summaries = append(m.summaries, s)
	return nil
}

var t0 = time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)

func rec(id, point string, o decisionrecord.Outcome, check string) decisionrecord.Record {
	return decisionrecord.Record{DecisionID: id, Point: point, At: t0, Outcome: o, Check: check}
}

func quietLog() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewJSONHandler(&buf, nil)), &buf
}

func TestNewFilter_RefusesWhatIsNotChosen(t *testing.T) {
	sink := &memSink{}
	for _, lv := range []decisionrecord.Level{"", "everything", "ALL"} {
		if _, err := decisionrecord.NewFilter(lv, sink, nil); err == nil {
			t.Errorf("level %q: accepted", lv)
		}
	}
	for _, lv := range []decisionrecord.Level{decisionrecord.LevelAll, decisionrecord.LevelRefusals, decisionrecord.LevelSummary} {
		if _, err := decisionrecord.NewFilter(lv, nil, nil); err == nil {
			t.Errorf("level %q with no sink: accepted", lv)
		}
	}
	if _, err := decisionrecord.NewFilter(decisionrecord.LevelNone, nil, nil); err != nil {
		t.Errorf("level none with no sink: %v", err)
	}
}

func TestParseLevel(t *testing.T) {
	for _, s := range []string{"all", "refusals", "summary", "none"} {
		lv, err := decisionrecord.ParseLevel(s)
		if err != nil || string(lv) != s {
			t.Errorf("ParseLevel(%q) = %q, %v", s, lv, err)
		}
	}
	for _, s := range []string{"", "All", "off", "summary "} {
		if _, err := decisionrecord.ParseLevel(s); err == nil {
			t.Errorf("ParseLevel(%q): accepted", s)
		}
	}
}

// At the all level every record reaches the sink, and a sink that cannot
// write is an error, so the deciding party refuses.
func TestFilter_AllPassesEveryRecordAndReportsFailure(t *testing.T) {
	sink := &memSink{}
	f, err := decisionrecord.NewFilter(decisionrecord.LevelAll, sink, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, r := range []decisionrecord.Record{rec("1", "gate", decisionrecord.Accepted, ""), rec("2", "gate", decisionrecord.Refused, "route")} {
		if err := f.Record(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if len(sink.records) != 2 {
		t.Fatalf("sink has %d records, want 2", len(sink.records))
	}
	sink.err = errors.New("disk full")
	if err := f.Record(ctx, rec("3", "gate", decisionrecord.Accepted, "")); err == nil {
		t.Error("a failed write at the all level was not an error")
	}
	if err := f.Record(ctx, decisionrecord.Record{Point: "gate", At: t0, Outcome: decisionrecord.Accepted}); err == nil {
		t.Error("a record without a DecisionID at the all level was not an error")
	}
}

// Below the all level a write that fails does not change the decision: the
// filter warns and returns nil.
func TestFilter_BelowAllNeverChangesTheDecision(t *testing.T) {
	for _, lv := range []decisionrecord.Level{decisionrecord.LevelRefusals, decisionrecord.LevelSummary, decisionrecord.LevelNone} {
		sink := &memSink{err: errors.New("disk full")}
		warn, buf := quietLog()
		f, err := decisionrecord.NewFilter(lv, sink, warn)
		if err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		if err := f.Record(ctx, rec("1", "gate", decisionrecord.Refused, "route")); err != nil {
			t.Errorf("level %s: Record = %v, want nil", lv, err)
		}
		if err := f.Flush(ctx, t0.Add(time.Minute)); err != nil {
			t.Errorf("level %s: Flush = %v, want nil", lv, err)
		}
		if lv != decisionrecord.LevelNone && !strings.Contains(buf.String(), "decision record") {
			t.Errorf("level %s: no warning logged (%q)", lv, buf.String())
		}
	}
}

func TestFilter_RefusalsPassesOnlyRefusals(t *testing.T) {
	sink := &memSink{}
	f, err := decisionrecord.NewFilter(decisionrecord.LevelRefusals, sink, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, r := range []decisionrecord.Record{
		rec("1", "gate", decisionrecord.Accepted, ""),
		rec("2", "gate", decisionrecord.Refused, "route"),
		rec("1", "gate", decisionrecord.Refused, "expired"),
	} {
		if err := f.Record(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if len(sink.records) != 2 || sink.records[0].DecisionID != "2" || sink.records[1].Check != "expired" {
		t.Errorf("sink records = %+v, want the two refusals", sink.records)
	}
}

// At the summary level no record reaches the sink; Flush gives, per point,
// the counts per outcome and check since the last flush.
func TestFilter_SummaryCountsAndFlushes(t *testing.T) {
	sink := &memSink{}
	f, err := decisionrecord.NewFilter(decisionrecord.LevelSummary, sink, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, r := range []decisionrecord.Record{
		rec("1", "gate-a", decisionrecord.Accepted, ""),
		rec("2", "gate-a", decisionrecord.Accepted, ""),
		rec("3", "gate-a", decisionrecord.Refused, "route"),
		rec("4", "gate-b", decisionrecord.Refused, "once"),
	} {
		if err := f.Record(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if len(sink.records) != 0 {
		t.Fatalf("summary level passed %d records", len(sink.records))
	}
	until := t0.Add(time.Minute)
	if err := f.Flush(ctx, until); err != nil {
		t.Fatal(err)
	}
	if len(sink.summaries) != 2 {
		t.Fatalf("summaries = %+v, want one per point", sink.summaries)
	}
	a := sink.summaries[0]
	if a.Point != "gate-a" || !a.Until.Equal(until) || len(a.Counts) != 2 {
		t.Fatalf("gate-a summary = %+v", a)
	}
	want := map[decisionrecord.Count]bool{
		{Outcome: decisionrecord.Accepted, Check: "", N: 2}:     true,
		{Outcome: decisionrecord.Refused, Check: "route", N: 1}: true,
	}
	for _, c := range a.Counts {
		if !want[c] {
			t.Errorf("unexpected count %+v", c)
		}
	}
	if err := f.Flush(ctx, until.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(sink.summaries) != 2 {
		t.Errorf("an empty window produced a summary: %+v", sink.summaries[2:])
	}
}

func TestFilter_NoneWritesNothing(t *testing.T) {
	sink := &memSink{}
	f, err := decisionrecord.NewFilter(decisionrecord.LevelNone, sink, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := f.Record(ctx, rec("1", "gate", decisionrecord.Refused, "route")); err != nil {
		t.Fatal(err)
	}
	if err := f.Flush(ctx, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(sink.records)+len(sink.summaries) != 0 {
		t.Errorf("level none wrote %d records and %d summaries", len(sink.records), len(sink.summaries))
	}
}

// The JSON lines sink writes one object per line, records and summaries
// told apart by their kind, safely from many goroutines.
func TestJSONLines(t *testing.T) {
	var buf bytes.Buffer
	sink := decisionrecord.NewJSONLines(&buf)
	ctx := context.Background()
	r := decisionrecord.Record{
		DecisionID: "d1", Point: "gate", At: t0, Outcome: decisionrecord.Refused, Check: "route", Reason: "no route",
		Actors: []string{"did:example:a"}, Evidence: []decisionrecord.Evidence{{Role: "approval", Address: address(t, "sha256:"+strings.Repeat("ab", 32))}},
		Attributes: map[string]string{"operationType": "transfer"},
	}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := sink.Record(ctx, r); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if err := sink.Summary(ctx, decisionrecord.Summary{Point: "gate", From: t0, Until: t0.Add(time.Minute),
		Counts: []decisionrecord.Count{{Outcome: decisionrecord.Refused, Check: "route", N: 3}}}); err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(&buf)
	lines := 0
	for sc.Scan() {
		lines++
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("line %d is not JSON: %v (%q)", lines, err, sc.Text())
		}
		switch m["kind"] {
		case "record":
			ev, _ := m["evidence"].([]any)
			if m["v"] != 1.0 || m["decisionId"] != "d1" || m["outcome"] != "refused" || m["check"] != "route" || m["at"] != "2026-11-06T12:00:00.000000000Z" ||
				len(ev) != 1 || ev[0].(map[string]any)["address"] != "sha256:"+strings.Repeat("ab", 32) {
				t.Errorf("record line = %v", m)
			}
		case "summary":
			if m["point"] != "gate" {
				t.Errorf("summary line = %v", m)
			}
		default:
			t.Errorf("line %d has kind %v", lines, m["kind"])
		}
	}
	if lines != 51 {
		t.Errorf("%d lines, want 51", lines)
	}
}

func TestLog(t *testing.T) {
	var buf bytes.Buffer
	sink := decisionrecord.NewLog(slog.New(slog.NewJSONHandler(&buf, nil)))
	if err := sink.Record(context.Background(), rec("d1", "gate", decisionrecord.Accepted, "")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"decisionId":"d1"`) || !strings.Contains(buf.String(), `"outcome":"accepted"`) {
		t.Errorf("log line = %q", buf.String())
	}
}

// A Filter not made by NewFilter fails closed: it refuses every call.
func TestFilter_ZeroValueFailsClosed(t *testing.T) {
	var f decisionrecord.Filter
	ctx := context.Background()
	if err := f.Record(ctx, rec("1", "gate", decisionrecord.Accepted, "")); err == nil {
		t.Error("a zero Filter accepted a record")
	}
	if err := f.Record(ctx, decisionrecord.Record{}); err == nil {
		t.Error("a zero Filter accepted a malformed record")
	}
	if err := f.Flush(ctx, t0); err == nil {
		t.Error("a zero Filter flushed")
	}
	var nilFilter *decisionrecord.Filter
	if err := nilFilter.Record(ctx, rec("1", "gate", decisionrecord.Accepted, "")); err == nil {
		t.Error("a nil Filter accepted a record")
	}
}

// The outcome and the check agree, evidence is content addresses, and the
// fields a reader keys on are UTF-8.
func TestRecord_Validation(t *testing.T) {
	for name, r := range map[string]decisionrecord.Record{
		"refusal without a check":     rec("1", "gate", decisionrecord.Refused, ""),
		"acceptance with a check":     rec("1", "gate", decisionrecord.Accepted, "route"),
		"unknown outcome":             rec("1", "gate", "maybe", ""),
		"no time":                     {DecisionID: "1", Point: "gate", Outcome: decisionrecord.Accepted},
		"no id":                       rec("", "gate", decisionrecord.Accepted, ""),
		"no point":                    rec("1", "", decisionrecord.Accepted, ""),
		"evidence without an address": {DecisionID: "1", Point: "gate", At: t0, Outcome: decisionrecord.Accepted, Evidence: []decisionrecord.Evidence{{Role: "body"}}},
		"evidence without a role":     {DecisionID: "1", Point: "gate", At: t0, Outcome: decisionrecord.Accepted, Evidence: []decisionrecord.Evidence{{Address: contentaddress.Of(nil)}}},
		"invalid UTF-8 id":            rec("\xff", "gate", decisionrecord.Accepted, ""),
		"invalid UTF-8 check":         rec("1", "gate", decisionrecord.Refused, "\xff"),
		"invalid UTF-8 actor":         {DecisionID: "1", Point: "gate", At: t0, Outcome: decisionrecord.Accepted, Actors: []string{"did:example:a", "did:\xff"}},
		"an empty actor":              {DecisionID: "1", Point: "gate", At: t0, Outcome: decisionrecord.Accepted, Actors: []string{""}},
		"a time past year 9999":       {DecisionID: "1", Point: "gate", At: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), Outcome: decisionrecord.Accepted},
		"a time before year 0":        {DecisionID: "1", Point: "gate", At: time.Date(-1, 1, 1, 0, 0, 0, 0, time.UTC), Outcome: decisionrecord.Accepted},
		"empty attribute name":        {DecisionID: "1", Point: "gate", At: t0, Outcome: decisionrecord.Accepted, Attributes: map[string]string{"": "x"}},
	} {
		if err := r.Validate(); err == nil {
			t.Errorf("%s: Validate = nil", name)
		}
	}
	ok := decisionrecord.Record{DecisionID: "1", Point: "gate", At: t0, Outcome: decisionrecord.Refused, Check: "route",
		Reason: "path \xff", Actors: []string{"did:example:a"}, Evidence: []decisionrecord.Evidence{{Role: "body", Address: contentaddress.Of(nil)}},
		Attributes: map[string]string{"path": "/a\xff"}}
	if err := ok.Validate(); err != nil {
		t.Errorf("a well-formed record (invalid UTF-8 only in its reason and an attribute value): %v", err)
	}
}

// A malformed record is the caller's error, so the Filter refuses it at every
// level, none included, and gives it to no sink.
func TestFilter_RefusesAMalformedRecordAtEveryLevel(t *testing.T) {
	for _, lv := range []decisionrecord.Level{decisionrecord.LevelAll, decisionrecord.LevelRefusals, decisionrecord.LevelSummary, decisionrecord.LevelNone} {
		sink := &memSink{}
		f, err := decisionrecord.NewFilter(lv, sink, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Record(context.Background(), rec("1", "gate", decisionrecord.Refused, "")); err == nil {
			t.Errorf("level %s: a refusal without a check was taken", lv)
		}
		if err := f.Flush(context.Background(), t0.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		if len(sink.records)+len(sink.summaries) != 0 {
			t.Errorf("level %s: the sink got %d records and %d summaries", lv, len(sink.records), len(sink.summaries))
		}
	}
}

func TestSummary_Validation(t *testing.T) {
	ok := decisionrecord.Summary{Point: "gate", From: t0, Until: t0.Add(time.Minute), Counts: []decisionrecord.Count{
		{Outcome: decisionrecord.Accepted, N: 1<<53 - 1}, {Outcome: decisionrecord.Refused, Check: "route", N: 0},
	}}
	if err := ok.Validate(); err != nil {
		t.Errorf("a well-formed summary: %v", err)
	}
	for name, edit := range map[string]func(*decisionrecord.Summary){
		"no point":                 func(s *decisionrecord.Summary) { s.Point = "" },
		"invalid UTF-8 point":      func(s *decisionrecord.Summary) { s.Point = "\xff" },
		"no start":                 func(s *decisionrecord.Summary) { s.From = time.Time{} },
		"no end":                   func(s *decisionrecord.Summary) { s.Until = time.Time{} },
		"an end before its start":  func(s *decisionrecord.Summary) { s.Until = t0.Add(-time.Second) },
		"unknown outcome":          func(s *decisionrecord.Summary) { s.Counts[0].Outcome = "maybe" },
		"refusals without a check": func(s *decisionrecord.Summary) { s.Counts[1].Check = "" },
		"acceptances with a check": func(s *decisionrecord.Summary) { s.Counts[0].Check = "route" },
		"invalid UTF-8 check":      func(s *decisionrecord.Summary) { s.Counts[1].Check = "\xff" },
		"a negative count":         func(s *decisionrecord.Summary) { s.Counts[1].N = -1 },
		"counts out of order":      func(s *decisionrecord.Summary) { s.Counts[0], s.Counts[1] = s.Counts[1], s.Counts[0] },
		"a repeated count":         func(s *decisionrecord.Summary) { s.Counts[1] = s.Counts[0] },
		"a window past year 9999":  func(s *decisionrecord.Summary) { s.Until = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) },
	} {
		s := ok
		s.Counts = append([]decisionrecord.Count(nil), ok.Counts...)
		edit(&s)
		if err := s.Validate(); err == nil {
			t.Errorf("%s: Validate = nil", name)
		}
	}
	instant := ok
	instant.Until = instant.From
	if err := instant.Validate(); err != nil {
		t.Errorf("a window that ends where it starts: %v", err)
	}
	past := ok
	past.Counts = []decisionrecord.Count{{Outcome: decisionrecord.Accepted, N: 1 << 53}}
	if err := past.Validate(); err == nil {
		t.Error("a count past 2^53−1: Validate = nil")
	}
}

// A sink checks what it is given, for a caller that does not go through a
// Filter: a malformed record or summary is an error and is not written.
func TestSinks_RefuseWhatIsMalformed(t *testing.T) {
	var lines, logged bytes.Buffer
	ctx := context.Background()
	for name, sink := range map[string]decisionrecord.Sink{
		"JSON lines": decisionrecord.NewJSONLines(&lines),
		"log":        decisionrecord.NewLog(slog.New(slog.NewJSONHandler(&logged, nil))),
	} {
		if err := sink.Record(ctx, rec("1", "gate", decisionrecord.Refused, "")); err == nil {
			t.Errorf("%s: a malformed record was written", name)
		}
		if err := sink.Summary(ctx, decisionrecord.Summary{Point: "gate", From: t0, Until: t0.Add(-time.Second)}); err == nil {
			t.Errorf("%s: a malformed summary was written", name)
		}
	}
	if lines.Len()+logged.Len() != 0 {
		t.Errorf("written: %q %q", lines.String(), logged.String())
	}
}

// Text a decision may take from its input is written with invalid UTF-8
// replaced, so a refusal is not lost to its own bytes.
func TestJSONLines_InvalidUTF8InTextIsReplaced(t *testing.T) {
	var buf bytes.Buffer
	sink := decisionrecord.NewJSONLines(&buf)
	f, err := decisionrecord.NewFilter(decisionrecord.LevelRefusals, sink, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := rec("1", "gate", decisionrecord.Refused, "route")
	r.Reason = "path \xff\xfe"
	r.Attributes = map[string]string{"path": "/a\xff"}
	if err := f.Record(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "\ufffd") && !strings.Contains(buf.String(), "\uFFFD") && !strings.Contains(buf.String(), "\xef\xbf\xbd") {
		t.Errorf("line = %q, want the invalid bytes replaced", buf.String())
	}
	var m map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &m); err != nil {
		t.Fatalf("line is not JSON: %v", err)
	}
}

// failingWriter fails its first write after writing part of it.
type failingWriter struct {
	buf   bytes.Buffer
	fails int
}

func (w *failingWriter) Write(p []byte) (int, error) {
	if w.fails > 0 {
		w.fails--
		n := len(p) / 2
		w.buf.Write(p[:n])
		return n, errors.New("disk full")
	}
	return w.buf.Write(p)
}

// After a partial write, the next line starts on a line of its own.
func TestJSONLines_APartialWriteDoesNotSpoilTheNextLine(t *testing.T) {
	w := &failingWriter{fails: 1}
	sink := decisionrecord.NewJSONLines(w)
	ctx := context.Background()
	if err := sink.Record(ctx, rec("1", "gate", decisionrecord.Accepted, "")); err == nil {
		t.Fatal("a failed write returned nil")
	}
	if err := sink.Record(ctx, rec("2", "gate", decisionrecord.Accepted, "")); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(w.buf.String(), "\n"), "\n")
	last := lines[len(lines)-1]
	var m map[string]any
	if err := json.Unmarshal([]byte(last), &m); err != nil || m["decisionId"] != "2" {
		t.Errorf("the line after a partial write = %q (%v)", last, err)
	}
}

// Times are written with a fixed number of fraction digits, so that they
// sort as text.
func TestJSONLines_TimesSortAsText(t *testing.T) {
	var buf bytes.Buffer
	sink := decisionrecord.NewJSONLines(&buf)
	ctx := context.Background()
	for i, at := range []time.Time{t0, t0.Add(500 * time.Millisecond)} {
		r := rec(fmt.Sprint(i), "gate", decisionrecord.Accepted, "")
		r.At = at
		if err := sink.Record(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	var ats []string
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatal(err)
		}
		ats = append(ats, m["at"].(string))
	}
	if !(ats[0] < ats[1]) {
		t.Errorf("times %q do not sort as text", ats)
	}
}

// failingHandler takes every level and fails to handle.
type failingHandler struct{}

func (failingHandler) Enabled(context.Context, slog.Level) bool  { return true }
func (failingHandler) Handle(context.Context, slog.Record) error { return errors.New("handler down") }
func (h failingHandler) WithAttrs([]slog.Attr) slog.Handler      { return h }
func (h failingHandler) WithGroup(string) slog.Handler           { return h }

// A log that drops or fails a record is an error, so the all level refuses.
func TestLog_ReportsARecordNotWritten(t *testing.T) {
	ctx := context.Background()
	var buf bytes.Buffer
	warnOnly := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	for name, sink := range map[string]decisionrecord.Sink{
		"level above info": decisionrecord.NewLog(warnOnly),
		"failing handler":  decisionrecord.NewLog(slog.New(failingHandler{})),
		"nil logger":       decisionrecord.NewLog(nil),
		"nil writer":       decisionrecord.NewJSONLines(nil),
	} {
		f, err := decisionrecord.NewFilter(decisionrecord.LevelAll, sink, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Record(ctx, rec("1", "gate", decisionrecord.Accepted, "")); err == nil {
			t.Errorf("%s: the record was not written, and Record returned nil", name)
		}
	}
	if buf.Len() != 0 {
		t.Errorf("the warn-only log wrote %q", buf.String())
	}
}

// A decision refused after its acceptance was recorded is counted once, as
// refused.
func TestFilter_SummaryCountsARevisedDecisionOnce(t *testing.T) {
	sink := &memSink{}
	f, err := decisionrecord.NewFilter(decisionrecord.LevelSummary, sink, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, r := range []decisionrecord.Record{
		rec("1", "gate", decisionrecord.Accepted, ""),
		rec("2", "gate", decisionrecord.Accepted, ""),
		rec("1", "gate", decisionrecord.Refused, "expired"),
	} {
		if err := f.Record(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Flush(ctx, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	want := []decisionrecord.Count{{Outcome: decisionrecord.Accepted, N: 1}, {Outcome: decisionrecord.Refused, Check: "expired", N: 1}}
	if len(sink.summaries) != 1 || fmt.Sprint(sink.summaries[0].Counts) != fmt.Sprint(want) {
		t.Errorf("summaries = %+v, want counts %+v in that order", sink.summaries, want)
	}
}

// Flush refuses a window end that is zero or before the window's start; the
// next window starts where the last ended.
func TestFilter_FlushWindows(t *testing.T) {
	sink := &memSink{}
	f, err := decisionrecord.NewFilter(decisionrecord.LevelSummary, sink, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := f.Record(ctx, rec("1", "gate", decisionrecord.Accepted, "")); err != nil {
		t.Fatal(err)
	}
	if err := f.Flush(ctx, time.Time{}); err == nil {
		t.Error("Flush accepted a zero end")
	}
	if err := f.Flush(ctx, t0.Add(-time.Second)); err == nil {
		t.Error("Flush accepted an end before the window's start")
	}
	first := t0.Add(time.Minute)
	if err := f.Flush(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := f.Record(ctx, rec("2", "gate", decisionrecord.Accepted, "")); err != nil {
		t.Fatal(err)
	}
	if err := f.Flush(ctx, first.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(sink.summaries) != 2 || !sink.summaries[0].From.Equal(t0) || !sink.summaries[1].From.Equal(first) {
		t.Errorf("windows = %+v", sink.summaries)
	}
}

// Records and flushes from many goroutines lose no count.
func TestFilter_SummaryUnderConcurrency(t *testing.T) {
	sink := &memSink{}
	f, err := decisionrecord.NewFilter(decisionrecord.LevelSummary, sink, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				if err := f.Record(ctx, rec(fmt.Sprint(g, "-", i), "gate", decisionrecord.Accepted, "")); err != nil {
					t.Error(err)
				}
			}
		}(g)
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 1; ; i++ {
			select {
			case <-stop:
				return
			default:
				_ = f.Flush(ctx, t0.Add(time.Duration(i)*time.Millisecond))
			}
		}
	}()
	wg.Wait()
	close(stop)
	<-done
	if err := f.Flush(ctx, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, s := range sink.summaries {
		for _, c := range s.Counts {
			total += c.N
		}
	}
	if total != 1600 {
		t.Errorf("counted %d, want 1600", total)
	}
}

// A decision whose records follow the writer's rule (refused at most once,
// never accepted after that) is counted once, by its outcome in the window.
func TestFilter_SummaryCountsEachDecisionOnce(t *testing.T) {
	sink := &memSink{}
	f, err := decisionrecord.NewFilter(decisionrecord.LevelSummary, sink, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, r := range []decisionrecord.Record{
		rec("a", "gate", decisionrecord.Accepted, ""),
		rec("a", "gate", decisionrecord.Refused, "expired"),
		rec("b", "gate", decisionrecord.Refused, "route"),
		rec("c", "gate", decisionrecord.Accepted, ""),
		rec("c", "gate", decisionrecord.Accepted, ""),
	} {
		if err := f.Record(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Flush(ctx, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	want := []decisionrecord.Count{
		{Outcome: decisionrecord.Accepted, N: 1},
		{Outcome: decisionrecord.Refused, Check: "expired", N: 1},
		{Outcome: decisionrecord.Refused, Check: "route", N: 1},
	}
	if len(sink.summaries) != 1 || fmt.Sprint(sink.summaries[0].Counts) != fmt.Sprint(want) {
		t.Errorf("counts = %+v, want %+v", sink.summaries, want)
	}
}

// The summary window keeps the ids of accepted decisions only: a refusal of a
// decision not accepted in the window is counted as it comes, so refusals,
// which need no reservation, cannot grow the window's memory.
func TestFilter_SummaryKeepsNoIDOfARefusal(t *testing.T) {
	sink := &memSink{}
	f, err := decisionrecord.NewFilter(decisionrecord.LevelSummary, sink, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for i := 0; i < 10000; i++ {
		if err := f.Record(ctx, rec(fmt.Sprint("r", i), "gate", decisionrecord.Refused, "route")); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"a1", "a2", "a3"} {
		if err := f.Record(ctx, rec(id, "gate", decisionrecord.Accepted, "")); err != nil {
			t.Fatal(err)
		}
	}
	if n := decisionrecord.KeptDecisionIDs(f); n != 3 {
		t.Errorf("the window keeps %d ids, want the 3 accepted", n)
	}
	if err := f.Flush(ctx, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	want := []decisionrecord.Count{{Outcome: decisionrecord.Accepted, N: 3}, {Outcome: decisionrecord.Refused, Check: "route", N: 10000}}
	if len(sink.summaries) != 1 || fmt.Sprint(sink.summaries[0].Counts) != fmt.Sprint(want) {
		t.Errorf("counts = %+v, want %+v", sink.summaries, want)
	}
	if n := decisionrecord.KeptDecisionIDs(f); n != 0 {
		t.Errorf("after Flush the window keeps %d ids", n)
	}
}

// A Flush refused for its time reads the window under the lock, while records
// arrive (run with -race).
func TestFilter_RefusedFlushDoesNotRaceRecord(t *testing.T) {
	ctx := context.Background()
	for i := 0; i < 50; i++ {
		f, err := decisionrecord.NewFilter(decisionrecord.LevelSummary, &memSink{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			if err := f.Flush(ctx, time.Time{}); err == nil {
				t.Error("a flush until the zero time was taken")
			}
		}()
		go func() {
			defer wg.Done()
			if err := f.Record(ctx, rec("a", "gate", decisionrecord.Accepted, "")); err != nil {
				t.Error(err)
			}
		}()
		wg.Wait()
	}
}

// A decision accepted in one window and refused in the next is counted in
// each, by its outcome there, once.
func TestFilter_SummaryCountsADecisionAcrossWindowsOnceInEach(t *testing.T) {
	sink := &memSink{}
	f, err := decisionrecord.NewFilter(decisionrecord.LevelSummary, sink, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := f.Record(ctx, rec("a", "gate", decisionrecord.Accepted, "")); err != nil {
		t.Fatal(err)
	}
	if err := f.Flush(ctx, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	refused := rec("a", "gate", decisionrecord.Refused, "expired")
	refused.At = t0.Add(2 * time.Minute)
	if err := f.Record(ctx, refused); err != nil {
		t.Fatal(err)
	}
	if err := f.Flush(ctx, t0.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(sink.summaries) != 2 ||
		fmt.Sprint(sink.summaries[0].Counts) != fmt.Sprint([]decisionrecord.Count{{Outcome: decisionrecord.Accepted, N: 1}}) ||
		fmt.Sprint(sink.summaries[1].Counts) != fmt.Sprint([]decisionrecord.Count{{Outcome: decisionrecord.Refused, Check: "expired", N: 1}}) {
		t.Errorf("summaries = %+v", sink.summaries)
	}
}

// A window in which every accepted decision was refused writes no count of
// zero acceptances.
func TestFilter_SummaryWritesNoZeroCount(t *testing.T) {
	sink := &memSink{}
	f, err := decisionrecord.NewFilter(decisionrecord.LevelSummary, sink, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, r := range []decisionrecord.Record{
		rec("a", "gate", decisionrecord.Accepted, ""),
		rec("a", "gate", decisionrecord.Refused, "expired"),
	} {
		if err := f.Record(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Flush(ctx, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if want := []decisionrecord.Count{{Outcome: decisionrecord.Refused, Check: "expired", N: 1}}; len(sink.summaries) != 1 || fmt.Sprint(sink.summaries[0].Counts) != fmt.Sprint(want) {
		t.Errorf("summaries = %+v, want %+v", sink.summaries, want)
	}
}
