package decisionrecord_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/provin-line/oss/decisionrecord"
)

// heldRecord is a decision a check deferred, with the hops verified before
// it. A held decision was not refused, so it has no RefusedAt.
func heldRecord() decisionrecord.Record {
	r := rec("d-held", "gate-a", decisionrecord.Held, "approval.pending")
	r.VerifiedHops = []string{"hop-0", "hop-1"}
	return r
}

// positionedRecord is a decision whose refusal was not enforced, diagnosed
// at a hop named before its signature was verified, with the hops verified
// before it.
func positionedRecord() decisionrecord.Record {
	r := rec("d-positioned", "gate-a", decisionrecord.Unenforced, "signer.unknown")
	r.RefusedAt = &decisionrecord.Position{Hop: "hop-2", Confidence: decisionrecord.ConfidenceClaimed}
	r.VerifiedHops = []string{"hop-0", "hop-1"}
	return r
}

// The writers of a version refuse a version they do not know.
func TestNewFormat_RefusesAnUnknownVersion(t *testing.T) {
	for _, v := range []decisionrecord.FormatVersion{0, 3, -1} {
		if _, err := decisionrecord.NewJSONLinesFormat(&bytes.Buffer{}, v); err == nil {
			t.Errorf("NewJSONLinesFormat(%d): no error", v)
		}
		if _, err := decisionrecord.NewLogFormat(slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil)), v); err == nil {
			t.Errorf("NewLogFormat(%d): no error", v)
		}
	}
	for _, v := range []decisionrecord.FormatVersion{decisionrecord.FormatV1, decisionrecord.FormatV2} {
		if _, err := decisionrecord.NewJSONLinesFormat(&bytes.Buffer{}, v); err != nil {
			t.Errorf("NewJSONLinesFormat(%d): %v", v, err)
		}
		if _, err := decisionrecord.NewLogFormat(slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil)), v); err != nil {
			t.Errorf("NewLogFormat(%d): %v", v, err)
		}
	}
}

// v1Sinks are the format v1 sinks, each with the buffer it writes to.
func v1Sinks(t *testing.T) map[string]struct {
	sink decisionrecord.Sink
	out  *bytes.Buffer
} {
	t.Helper()
	sinks := map[string]struct {
		sink decisionrecord.Sink
		out  *bytes.Buffer
	}{}
	var jb, jfb, lb, lfb bytes.Buffer
	jf, err := decisionrecord.NewJSONLinesFormat(&jfb, decisionrecord.FormatV1)
	if err != nil {
		t.Fatal(err)
	}
	lf, err := decisionrecord.NewLogFormat(slog.New(slog.NewJSONHandler(&lfb, nil)), decisionrecord.FormatV1)
	if err != nil {
		t.Fatal(err)
	}
	sinks["NewJSONLines"] = struct {
		sink decisionrecord.Sink
		out  *bytes.Buffer
	}{decisionrecord.NewJSONLines(&jb), &jb}
	sinks["NewJSONLinesFormat v1"] = struct {
		sink decisionrecord.Sink
		out  *bytes.Buffer
	}{jf, &jfb}
	sinks["NewLog"] = struct {
		sink decisionrecord.Sink
		out  *bytes.Buffer
	}{decisionrecord.NewLog(slog.New(slog.NewJSONHandler(&lb, nil))), &lb}
	sinks["NewLogFormat v1"] = struct {
		sink decisionrecord.Sink
		out  *bytes.Buffer
	}{lf, &lfb}
	return sinks
}

// A format v1 sink refuses, and does not write, a record or summary that
// format v1 cannot express: a held decision, a refusal's position, verified
// hops, a count of held decisions. Hops of length 0 are no hops.
func TestFormatV1_RefusesWhatOnlyV2Has(t *testing.T) {
	held := rec("d1", "gate-a", decisionrecord.Held, "approval.pending")
	positioned := rec("d2", "gate-a", decisionrecord.Refused, "approval.expired")
	positioned.RefusedAt = &decisionrecord.Position{Confidence: decisionrecord.ConfidenceUnknown}
	hops := rec("d3", "gate-a", decisionrecord.Accepted, "")
	hops.VerifiedHops = []string{"hop-0"}
	summary := goldenSummary()
	summary.Counts = append(summary.Counts[:1:1], append([]decisionrecord.Count{{Outcome: decisionrecord.Held, Check: "approval.pending", N: 1}}, summary.Counts[1:]...)...)
	for name, s := range v1Sinks(t) {
		for what, err := range map[string]error{
			"a held decision":      s.sink.Record(context.Background(), held),
			"a refusal's position": s.sink.Record(context.Background(), positioned),
			"verified hops":        s.sink.Record(context.Background(), hops),
			"a count of held":      s.sink.Summary(context.Background(), summary),
		} {
			if !errors.Is(err, decisionrecord.ErrNotInFormat) {
				t.Errorf("%s, %s: %v, want ErrNotInFormat", name, what, err)
			}
		}
		if s.out.Len() != 0 {
			t.Errorf("%s wrote %q, want nothing", name, s.out.String())
		}
		noHops := rec("d4", "gate-a", decisionrecord.Accepted, "")
		noHops.VerifiedHops = []string{}
		if err := s.sink.Record(context.Background(), noHops); err != nil {
			t.Errorf("%s, hops of length 0: %v", name, err)
		}
		if strings.Contains(s.out.String(), "verifiedHops") {
			t.Errorf("%s wrote %q, want no verifiedHops", name, s.out.String())
		}
	}
}

// A format v2 sink writes every record and summary: v1's members, with the
// same meaning, "v": 2, a held outcome, the refusal's position and the
// verified hops.
func TestFormatV2_WritesHeldAndHops(t *testing.T) {
	var b bytes.Buffer
	s, err := decisionrecord.NewJSONLinesFormat(&b, decisionrecord.FormatV2)
	if err != nil {
		t.Fatal(err)
	}
	unknown := rec("d-unknown", "gate-a", decisionrecord.Refused, "hop.unnamed")
	unknown.RefusedAt = &decisionrecord.Position{Confidence: decisionrecord.ConfidenceUnknown}
	for _, r := range append(goldenRecords(t), heldRecord(), positionedRecord(), unknown) {
		if err := s.Record(context.Background(), r); err != nil {
			t.Fatal(err)
		}
	}
	summary := goldenSummary()
	summary.Counts = []decisionrecord.Count{{Outcome: decisionrecord.Accepted, N: 3}, {Outcome: decisionrecord.Held, Check: "approval.pending", N: 1}}
	if err := s.Summary(context.Background(), summary); err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitAfter(b.String(), "\n")
	for i, v1 := range goldenJSONLinesV1[:3] {
		if want := strings.Replace(v1, `"v":1}`, `"v":2}`, 1); lines[i] != want {
			t.Errorf("v2 line %d = %q, want v1's with \"v\":2: %q", i, lines[i], want)
		}
	}
	for i, want := range []string{
		`{"at":"2026-11-06T12:00:00.000000000Z","check":"approval.pending","decisionId":"d-held","kind":"record","outcome":"held","point":"gate-a","v":2,"verifiedHops":["hop-0","hop-1"]}` + "\n",
		`{"at":"2026-11-06T12:00:00.000000000Z","check":"signer.unknown","decisionId":"d-positioned","kind":"record","outcome":"unenforced","point":"gate-a","refusedAt":{"confidence":"claimed","hop":"hop-2"},"v":2,"verifiedHops":["hop-0","hop-1"]}` + "\n",
		`{"at":"2026-11-06T12:00:00.000000000Z","check":"hop.unnamed","decisionId":"d-unknown","kind":"record","outcome":"refused","point":"gate-a","refusedAt":{"confidence":"unknown"},"v":2}` + "\n",
		`{"counts":[{"n":3,"outcome":"accepted"},{"check":"approval.pending","n":1,"outcome":"held"}],"from":"2026-11-06T12:00:00.000000000Z","kind":"summary","point":"gate-a","until":"2026-11-06T12:01:00.000000000Z","v":2}` + "\n",
	} {
		if got := lines[3+i]; got != want {
			t.Errorf("v2 line %d = %q, want %q", 3+i, got, want)
		}
	}
}

// A format v2 log sink hands its handler the same members, "v": 2 among them.
func TestFormatV2_Log(t *testing.T) {
	var b bytes.Buffer
	s, err := decisionrecord.NewLogFormat(slog.New(slog.NewJSONHandler(&b, &slog.HandlerOptions{ReplaceAttr: withoutTime})), decisionrecord.FormatV2)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []decisionrecord.Record{heldRecord(), positionedRecord()} {
		if err := s.Record(context.Background(), r); err != nil {
			t.Fatal(err)
		}
	}
	want := `{"level":"INFO","msg":"decision record","at":"2026-11-06T12:00:00.000000000Z","check":"approval.pending","decisionId":"d-held","kind":"record","outcome":"held","point":"gate-a","v":2,"verifiedHops":["hop-0","hop-1"]}` + "\n" +
		`{"level":"INFO","msg":"decision record","at":"2026-11-06T12:00:00.000000000Z","check":"signer.unknown","decisionId":"d-positioned","kind":"record","outcome":"unenforced","point":"gate-a","refusedAt":{"confidence":"claimed","hop":"hop-2"},"v":2,"verifiedHops":["hop-0","hop-1"]}` + "\n"
	if got := b.String(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// Validate checks v2's members whatever the version: a held decision has its
// check; a position only on a refused or unenforced decision, with one of
// the three confidences, and a hop exactly when the confidence is not
// unknown; each verified hop a non-empty UTF-8 string.
func TestRecord_ValidatesV2Members(t *testing.T) {
	at := func(hop string, c decisionrecord.Confidence) *decisionrecord.Position {
		return &decisionrecord.Position{Hop: hop, Confidence: c}
	}
	for name, r := range map[string]decisionrecord.Record{
		"held without its check": rec("d", "p", decisionrecord.Held, ""),
		"a position on an acceptance": func() decisionrecord.Record {
			r := rec("d", "p", decisionrecord.Accepted, "")
			r.RefusedAt = at("h", decisionrecord.ConfidenceVerified)
			return r
		}(),
		"a position on a held decision": func() decisionrecord.Record {
			r := rec("d", "p", decisionrecord.Held, "c")
			r.RefusedAt = at("h", decisionrecord.ConfidenceVerified)
			return r
		}(),
		"no confidence": func() decisionrecord.Record {
			r := rec("d", "p", decisionrecord.Refused, "c")
			r.RefusedAt = at("h", "")
			return r
		}(),
		"an unknown confidence": func() decisionrecord.Record {
			r := rec("d", "p", decisionrecord.Refused, "c")
			r.RefusedAt = at("h", "certain")
			return r
		}(),
		"a claimed position without a hop": func() decisionrecord.Record {
			r := rec("d", "p", decisionrecord.Refused, "c")
			r.RefusedAt = at("", decisionrecord.ConfidenceClaimed)
			return r
		}(),
		"an unknown position with a hop": func() decisionrecord.Record {
			r := rec("d", "p", decisionrecord.Refused, "c")
			r.RefusedAt = at("h", decisionrecord.ConfidenceUnknown)
			return r
		}(),
		"a hop that is not UTF-8": func() decisionrecord.Record {
			r := rec("d", "p", decisionrecord.Refused, "c")
			r.RefusedAt = at("h\xff", decisionrecord.ConfidenceVerified)
			return r
		}(),
		"an empty verified hop": func() decisionrecord.Record {
			r := rec("d", "p", decisionrecord.Accepted, "")
			r.VerifiedHops = []string{"h", ""}
			return r
		}(),
		"a verified hop that is not UTF-8": func() decisionrecord.Record {
			r := rec("d", "p", decisionrecord.Accepted, "")
			r.VerifiedHops = []string{"h\xff"}
			return r
		}(),
	} {
		if err := r.Validate(); err == nil {
			t.Errorf("%s: valid", name)
		}
	}
	if err := heldRecord().Validate(); err != nil {
		t.Errorf("a held record with its hops: %v", err)
	}
	if err := positionedRecord().Validate(); err != nil {
		t.Errorf("an unenforced record with its position and hops: %v", err)
	}
	refusedAt := rec("d", "p", decisionrecord.Refused, "c")
	refusedAt.RefusedAt = at("h", decisionrecord.ConfidenceVerified)
	if err := refusedAt.Validate(); err != nil {
		t.Errorf("a refused record with its position: %v", err)
	}
	refusedWithHops := rec("d", "p", decisionrecord.Refused, "c")
	refusedWithHops.VerifiedHops = []string{"h0"}
	if err := refusedWithHops.Validate(); err != nil {
		t.Errorf("verified hops on a refusal: %v", err)
	}
	if err := (decisionrecord.Summary{Point: "p", From: t0, Until: t0, Counts: []decisionrecord.Count{{Outcome: decisionrecord.Held, N: 1}}}).Validate(); err == nil {
		t.Error("a count of held decisions without its check: valid")
	}
}

// Held ranks above accepted and below unenforced and refused: the summary
// level counts a decision accepted in the window by its strongest record, and
// a held decision not accepted in it as it comes. A held decision has one
// record by the writer's rule; the sequences of more than one here break the
// rule on purpose, to see the rank.
func TestFilter_HeldRanksBetweenAcceptedAndUnenforced(t *testing.T) {
	for name, c := range map[string]struct {
		records []decisionrecord.Record
		want    []decisionrecord.Count
	}{
		"held":                       {[]decisionrecord.Record{rec("d", "p", decisionrecord.Held, "c")}, []decisionrecord.Count{{Outcome: decisionrecord.Held, Check: "c", N: 1}}},
		"accepted, then held":        {[]decisionrecord.Record{rec("d", "p", decisionrecord.Accepted, ""), rec("d", "p", decisionrecord.Held, "c")}, []decisionrecord.Count{{Outcome: decisionrecord.Held, Check: "c", N: 1}}},
		"accepted, held, refused":    {[]decisionrecord.Record{rec("d", "p", decisionrecord.Accepted, ""), rec("d", "p", decisionrecord.Held, "c"), rec("d", "p", decisionrecord.Refused, "r")}, []decisionrecord.Count{{Outcome: decisionrecord.Refused, Check: "r", N: 1}}},
		"accepted, held, unenforced": {[]decisionrecord.Record{rec("d", "p", decisionrecord.Accepted, ""), rec("d", "p", decisionrecord.Held, "c"), rec("d", "p", decisionrecord.Unenforced, "u")}, []decisionrecord.Count{{Outcome: decisionrecord.Unenforced, Check: "u", N: 1}}},
		"accepted, unenforced, held": {[]decisionrecord.Record{rec("d", "p", decisionrecord.Accepted, ""), rec("d", "p", decisionrecord.Unenforced, "u"), rec("d", "p", decisionrecord.Held, "c")}, []decisionrecord.Count{{Outcome: decisionrecord.Unenforced, Check: "u", N: 1}}},
	} {
		sink := &memSink{}
		f, err := decisionrecord.NewFilter(decisionrecord.LevelSummary, sink, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range c.records {
			if err := f.Record(context.Background(), r); err != nil {
				t.Fatal(err)
			}
		}
		if err := f.Flush(context.Background(), t0); err != nil {
			t.Fatal(err)
		}
		if len(sink.summaries) != 1 || fmt.Sprint(sink.summaries[0].Counts) != fmt.Sprint(c.want) {
			t.Errorf("%s: summaries %v, want one with %v", name, sink.summaries, c.want)
		}
	}
}

// LevelRefusals writes held decisions, as it writes every decision that is
// not accepted.
func TestFilter_RefusalsWritesHeld(t *testing.T) {
	sink := &memSink{}
	f, err := decisionrecord.NewFilter(decisionrecord.LevelRefusals, sink, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Record(context.Background(), heldRecord()); err != nil {
		t.Fatal(err)
	}
	if len(sink.records) != 1 || sink.records[0].Outcome != decisionrecord.Held {
		t.Errorf("records = %v, want the held one", sink.records)
	}
}
