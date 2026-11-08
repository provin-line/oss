// Package decisionrecord is the record a deciding party — a gate, a boundary
// stage, a delivery decision — writes for each decision it makes, and the
// levels at which it is written: every decision, refusals only, counts per
// window, or none. Configuration defaults to every decision; this package has
// no default level, so a level is in effect only when it is chosen. It is not
// the record of used nonces a gate keeps to refuse replays; that is another
// record with another purpose.
//
// A record holds no payload: only the content addresses of what was decided
// on, the parties the decision is attributed to, and the deciding party's own
// fields. The vocabulary of a particular deciding party (an approval, a
// signer, an operation type) goes in Evidence, Actors and Attributes.
package decisionrecord

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/provin-line/oss/canon/jcs"
	"github.com/provin-line/oss/contentaddress"
)

// Outcome is what a decision decided.
type Outcome string

const (
	Accepted Outcome = "accepted"
	Refused  Outcome = "refused"
)

// Evidence is one thing a decision was made on: its role (e.g. "approval",
// "chain") and its content address. A role may repeat; the order is kept (a
// chain's records, a boundary stage's segment, in order).
type Evidence struct {
	Role    string
	Address contentaddress.Address
}

// Record is the record of one decision.
//
// A decision refused after its record was written — an approval that expired
// between the record and the execution, say — is recorded again with the same
// DecisionID, Outcome Refused, its Check, and At the time of the refusal. A
// decision is refused when any record of its DecisionID is refused, whatever
// the order the records are read in.
//
// A writer follows one rule for the records of a decision: it records the
// decision refused at most once, and never records it accepted after that
// refusal; it makes each record only once the previous one of the decision
// has been taken (Filter.Record returned). Recording a decision accepted again
// changes nothing. A writer that breaks the rule makes the summary level
// count the decision more than once, and nothing else: no decision's outcome,
// and no record, changes.
type Record struct {
	DecisionID string    // unique per decision; made by the deciding party (128 random bits, say)
	Point      string    // the deciding party's ID: a gate's, a boundary's
	At         time.Time // when the decision was made
	Outcome    Outcome
	Check      string            // the check that refused: a fixed name, required on refusal, empty on acceptance
	Reason     string            // for people
	Actors     []string          // whom the decision is attributed to (a gate: the signers)
	Evidence   []Evidence        // what was decided on, in order
	Attributes map[string]string // the deciding party's own fields
}

// Validate checks the fields a reader keys on: a DecisionID and a Point, a
// time within the years 0000–9999 (so it is written in RFC 3339 and sorts as
// text), an outcome with a Check exactly when it is a refusal, each Evidence a
// role and an address, each Actor and attribute name valid UTF-8 and not
// empty. Filter.Record and every Sink here check it, whatever the level: a
// malformed record is its writer's error. Text for people (Reason, attribute
// values) is not refused for invalid UTF-8; it is written with the invalid
// bytes replaced.
func (r Record) Validate() error {
	switch {
	case r.DecisionID == "" || !utf8.ValidString(r.DecisionID):
		return errors.New("decisionrecord: record without a valid DecisionID")
	case r.Point == "" || !utf8.ValidString(r.Point):
		return errors.New("decisionrecord: record without a valid Point")
	case r.At.IsZero():
		return errors.New("decisionrecord: record without a time")
	case !writableTime(r.At):
		return fmt.Errorf("decisionrecord: time %v outside the years 0000–9999", r.At)
	case r.Outcome == Refused && r.Check == "":
		return errors.New("decisionrecord: a refusal without the check that refused")
	case r.Outcome == Accepted && r.Check != "":
		return errors.New("decisionrecord: an acceptance with a refusing check")
	case r.Outcome != Accepted && r.Outcome != Refused:
		return fmt.Errorf("decisionrecord: record with outcome %q", r.Outcome)
	case !utf8.ValidString(r.Check):
		return errors.New("decisionrecord: record with a Check that is not UTF-8")
	}
	for _, e := range r.Evidence {
		if e.Role == "" || !utf8.ValidString(e.Role) || e.Address.IsZero() {
			return fmt.Errorf("decisionrecord: evidence %q is not a role and a content address", e.Role)
		}
	}
	for _, a := range r.Actors {
		if a == "" || !utf8.ValidString(a) {
			return errors.New("decisionrecord: an actor that is empty or not UTF-8")
		}
	}
	for k := range r.Attributes {
		if k == "" || !utf8.ValidString(k) {
			return errors.New("decisionrecord: an attribute name that is empty or not UTF-8")
		}
	}
	return nil
}

// Count is the number of decisions of one outcome and check in a window.
type Count struct {
	Outcome Outcome
	Check   string
	N       int64 // from 0 to 2^53−1
}

// maxCount is the largest Count.N, 2^53−1: a count is written as a JSON
// number, and every reader of one reads it exactly up to there.
const maxCount int64 = 1<<53 - 1

// Summary is what the summary level writes for a deciding party: the counts of
// its decisions recorded from From until Until.
type Summary struct {
	Point       string
	From, Until time.Time
	Counts      []Count // ordered by outcome, then check
}

// Validate checks a summary as Record.Validate checks a record: a Point, a
// window within the years 0000–9999 whose end is not before its start, and
// each Count an outcome with a Check exactly when it counts refusals, and N
// from 0 to 2^53−1, the Counts ordered by outcome, then check, with no two
// alike. Every Sink here checks it.
func (s Summary) Validate() error {
	switch {
	case s.Point == "" || !utf8.ValidString(s.Point):
		return errors.New("decisionrecord: summary without a valid Point")
	case s.From.IsZero() || s.Until.IsZero():
		return errors.New("decisionrecord: summary without its window")
	case !writableTime(s.From) || !writableTime(s.Until):
		return fmt.Errorf("decisionrecord: summary window %v–%v outside the years 0000–9999", s.From, s.Until)
	case s.Until.Before(s.From):
		return errors.New("decisionrecord: summary whose window ends before it starts")
	}
	for i, c := range s.Counts {
		switch {
		case c.Outcome != Accepted && c.Outcome != Refused:
			return fmt.Errorf("decisionrecord: count with outcome %q", c.Outcome)
		case c.Outcome == Refused && c.Check == "":
			return errors.New("decisionrecord: a count of refusals without their check")
		case c.Outcome == Accepted && c.Check != "":
			return errors.New("decisionrecord: a count of acceptances with a refusing check")
		case !utf8.ValidString(c.Check):
			return errors.New("decisionrecord: count with a Check that is not UTF-8")
		case c.N < 0 || c.N > maxCount:
			return fmt.Errorf("decisionrecord: count %d outside 0 to %d", c.N, maxCount)
		case i > 0 && !countBefore(s.Counts[i-1], c):
			return fmt.Errorf("decisionrecord: counts not ordered by outcome, then check, or repeated at %d", i)
		}
	}
	return nil
}

// countBefore reports whether a comes before b in a Summary's order: by
// outcome, then check.
func countBefore(a, b Count) bool {
	if a.Outcome != b.Outcome {
		return a.Outcome < b.Outcome
	}
	return a.Check < b.Check
}

// writableTime reports whether t's year in UTC is within 0000–9999, the years
// the four-digit RFC 3339 form writes.
func writableTime(t time.Time) bool {
	y := t.UTC().Year()
	return y >= 0 && y <= 9999
}

// Recorder takes records.
type Recorder interface {
	Record(ctx context.Context, r Record) error
}

// SummaryRecorder takes summaries.
type SummaryRecorder interface {
	Summary(ctx context.Context, s Summary) error
}

// Sink is where records and summaries are written. A Filter calls it from
// many goroutines, so it must be safe for concurrent use. At LevelAll a nil
// error from Record is what lets a decision be accepted, so a Sink returns nil
// only once the record is written where it is kept (an unbuffered or synced
// writer).
type Sink interface {
	Recorder
	SummaryRecorder
}

// Level is how much a Filter writes.
type Level string

const (
	LevelAll      Level = "all"
	LevelRefusals Level = "refusals"
	LevelSummary  Level = "summary"
	LevelNone     Level = "none"
)

// ParseLevel reads a level from configuration: exactly "all", "refusals",
// "summary" or "none".
func ParseLevel(s string) (Level, error) {
	switch l := Level(s); l {
	case LevelAll, LevelRefusals, LevelSummary, LevelNone:
		return l, nil
	}
	return "", fmt.Errorf("decisionrecord: unknown level %q (want all, refusals, summary or none)", s)
}

// errNotMade is a Filter's answer when it was not made by NewFilter: a zero
// Filter has no level, and fails closed.
var errNotMade = errors.New("decisionrecord: Filter not made by NewFilter")

// Filter writes records to a sink at a level. It is the one place the level
// decides what a sink's failure means, so that a deciding party follows one
// rule: if Record returns an error, refuse the decision. A malformed record
// (Record.Validate) is an error at every level, LevelNone included: it is the
// writer's error, not the sink's. At LevelAll, every record is given to the
// sink and the sink's failure is returned, so no decision is accepted without
// its record as far as the sink's nil means the record is kept (see Sink). At
// LevelRefusals and LevelSummary, the sink's failure is logged as a warning
// and Record returns nil: the decision does not change. At LevelNone nothing
// is written. A Filter not made by NewFilter returns an error from every call.
type Filter struct {
	level Level
	sink  Sink
	warn  *slog.Logger

	mu      sync.Mutex
	from    time.Time
	windows map[string]*window // point → its tally since from
}

// outcomeCheck is what a Count counts: an outcome and its refusing check.
type outcomeCheck struct {
	outcome Outcome
	check   string
}

// window is one deciding party's tally at LevelSummary. It keeps the ids of
// the decisions accepted in it only: an acceptance needs whatever the
// deciding party checks for, while any caller can cause a refusal, so the
// ids kept are bounded by what the deciding party admits. A refusal of a
// decision not accepted in it is counted as it comes and keeps no id. Its
// counts are keyed by outcome and check, fixed names of the deciding party.
type window struct {
	counts   map[outcomeCheck]int64
	accepted map[string]bool // DecisionID → still accepted (false once a refusal of it is counted)
}

// NewFilter returns a Filter at level, writing to sink. The zero Level is
// refused. sink may be nil only at LevelNone. warn receives the warnings of
// LevelRefusals and LevelSummary; nil means slog.Default().
func NewFilter(level Level, sink Sink, warn *slog.Logger) (*Filter, error) {
	if _, err := ParseLevel(string(level)); err != nil {
		return nil, err
	}
	if sink == nil && level != LevelNone {
		return nil, fmt.Errorf("decisionrecord: level %s needs a sink", level)
	}
	if warn == nil {
		warn = slog.Default()
	}
	f := &Filter{level: level, sink: sink, warn: warn}
	f.resetWindow(time.Time{})
	return f, nil
}

func (f *Filter) resetWindow(from time.Time) {
	f.from = from
	f.windows = map[string]*window{}
}

// Record writes r as the level says.
func (f *Filter) Record(ctx context.Context, r Record) error {
	if f == nil || f.level == "" {
		return errNotMade
	}
	if err := r.Validate(); err != nil {
		return err
	}
	switch f.level {
	case LevelAll:
		return f.sink.Record(ctx, r)
	case LevelRefusals:
		if r.Outcome != Refused {
			return nil
		}
		if err := f.sink.Record(ctx, r); err != nil {
			f.notWritten(ctx, err)
		}
	case LevelSummary:
		f.count(r)
	}
	return nil
}

// count adds r to the window. An accepted decision is counted once, however
// often it is recorded accepted; a refusal of it then moves it to that
// refusal's check. A refusal of a decision not accepted in the window is
// counted as it comes: under the writer's rule (see Record) a decision is
// refused at most once, so it is counted once.
func (f *Filter) count(r Record) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.from.IsZero() {
		f.from = r.At
	}
	w := f.windows[r.Point]
	if w == nil {
		w = &window{counts: map[outcomeCheck]int64{}, accepted: map[string]bool{}}
		f.windows[r.Point] = w
	}
	stillAccepted, seen := w.accepted[r.DecisionID]
	switch {
	case r.Outcome == Accepted && !seen:
		w.accepted[r.DecisionID] = true
		w.counts[outcomeCheck{outcome: Accepted}]++
	case r.Outcome == Accepted:
	case seen && stillAccepted:
		w.accepted[r.DecisionID] = false
		w.counts[outcomeCheck{outcome: Accepted}]--
		w.counts[outcomeCheck{outcome: Refused, check: r.Check}]++
	case seen:
	default:
		w.counts[outcomeCheck{outcome: Refused, check: r.Check}]++
	}
}

// Flush writes, at LevelSummary, one Summary per deciding party with the
// counts of its decisions recorded since the last Flush (or the first record):
// each decision once, by its outcome in the window, when its writer follows
// the rule for a decision's records (see Record). A decision whose records
// fall in two windows is counted in each. It starts a new window at until. A
// window without decisions writes nothing.
// until must not be zero or before the window's start. At other levels it does
// nothing. A sink's failure is a warning; the decisions do not change.
func (f *Filter) Flush(ctx context.Context, until time.Time) error {
	if f == nil || f.level == "" {
		return errNotMade
	}
	if f.level != LevelSummary {
		return nil
	}
	f.mu.Lock()
	windows, from := f.windows, f.from
	if until.IsZero() {
		f.mu.Unlock()
		return errors.New("decisionrecord: flush until the zero time")
	}
	if !from.IsZero() && until.Before(from) {
		f.mu.Unlock()
		return fmt.Errorf("decisionrecord: flush until %v, before the window's start %v", until, from)
	}
	f.resetWindow(until)
	f.mu.Unlock()
	points := make([]string, 0, len(windows))
	for p := range windows {
		points = append(points, p)
	}
	sort.Strings(points)
	for _, p := range points {
		s := Summary{Point: p, From: from, Until: until}
		for k, n := range windows[p].counts {
			if n > 0 {
				s.Counts = append(s.Counts, Count{Outcome: k.outcome, Check: k.check, N: n})
			}
		}
		sort.Slice(s.Counts, func(i, j int) bool { return countBefore(s.Counts[i], s.Counts[j]) })
		if err := f.sink.Summary(ctx, s); err != nil {
			f.warn.WarnContext(ctx, "decision record: summary not written", "point", p, "err", err)
		}
	}
	return nil
}

// notWritten warns that the sink did not write a record, at a level where
// that does not change the decision.
func (f *Filter) notWritten(ctx context.Context, err error) {
	f.warn.WarnContext(ctx, "decision record: not written", "level", string(f.level), "err", err)
}

// formatVersion is the version of the JSON form of records and summaries, the
// "v" member of every line.
const formatVersion = 1

// timeLayout is RFC 3339 in UTC with nine fraction digits, so that times sort
// as text.
const timeLayout = "2006-01-02T15:04:05.000000000Z"

// NewJSONLines returns a sink writing each record and summary to w as one line
// of RFC 8785 JSON, with "v" (the format version) and "kind" ("record" or
// "summary"). Line breaks inside values are escaped, but U+2028 and U+2029 are
// written as is (RFC 8785): a reader splits on "\n" only. A line is written
// with one Write; after a failed Write, the next line starts with "\n", so a
// partial line stays one unreadable line and the lines after it stay whole. A
// nil w makes every write fail.
func NewJSONLines(w io.Writer) Sink {
	return &jsonLines{w: w}
}

type jsonLines struct {
	mu     sync.Mutex
	w      io.Writer
	broken bool
}

func (j *jsonLines) Record(_ context.Context, r Record) error {
	if err := r.Validate(); err != nil {
		return err
	}
	return j.write(recordMap(r))
}

func (j *jsonLines) Summary(_ context.Context, s Summary) error {
	if err := s.Validate(); err != nil {
		return err
	}
	return j.write(summaryMap(s))
}

func (j *jsonLines) write(m map[string]any) error {
	if j.w == nil {
		return errors.New("decisionrecord: no writer")
	}
	b, err := jcs.CanonicalizeRFC8785(m)
	if err != nil {
		return fmt.Errorf("decisionrecord: %w", err)
	}
	line := append(b, '\n')
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.broken {
		line = append([]byte{'\n'}, line...)
	}
	if _, err := j.w.Write(line); err != nil {
		j.broken = true
		return fmt.Errorf("decisionrecord: %w", err)
	}
	j.broken = false
	return nil
}

// NewLog returns a sink writing each record and summary as one structured log
// entry at the info level, through the logger's handler so that its failure
// is the sink's: a handler that does not take info entries, or that fails to
// handle one, is an error (at LevelAll, the decision is refused). A handler
// that returns nil without keeping the entry cannot be detected here: at
// LevelAll, use a handler whose nil means kept. A nil l makes every write
// fail.
func NewLog(l *slog.Logger) Sink {
	return logSink{l: l}
}

type logSink struct{ l *slog.Logger }

func (s logSink) Record(ctx context.Context, r Record) error {
	if err := r.Validate(); err != nil {
		return err
	}
	return s.emit(ctx, "decision record", recordMap(r))
}

func (s logSink) Summary(ctx context.Context, sum Summary) error {
	if err := sum.Validate(); err != nil {
		return err
	}
	return s.emit(ctx, "decision summary", summaryMap(sum))
}

func (s logSink) emit(ctx context.Context, msg string, m map[string]any) error {
	if s.l == nil {
		return errors.New("decisionrecord: no logger")
	}
	h := s.l.Handler()
	if !h.Enabled(ctx, slog.LevelInfo) {
		return errors.New("decisionrecord: the logger does not take info entries")
	}
	rec := slog.NewRecord(time.Now(), slog.LevelInfo, msg, 0)
	rec.Add(mapAttrs(m)...)
	if err := h.Handle(ctx, rec); err != nil {
		return fmt.Errorf("decisionrecord: %w", err)
	}
	return nil
}

func mapAttrs(m map[string]any) []any {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]any, 0, 2*len(keys))
	for _, k := range keys {
		out = append(out, k, m[k])
	}
	return out
}

// text replaces invalid UTF-8 in a value a decision may take from its input,
// so that the record is written rather than lost.
func text(s string) string { return strings.ToValidUTF8(s, "�") }

func recordMap(r Record) map[string]any {
	m := map[string]any{
		"v":          formatVersion,
		"kind":       "record",
		"decisionId": r.DecisionID,
		"point":      r.Point,
		"at":         r.At.UTC().Format(timeLayout),
		"outcome":    string(r.Outcome),
	}
	if r.Check != "" {
		m["check"] = r.Check
	}
	if r.Reason != "" {
		m["reason"] = text(r.Reason)
	}
	if len(r.Actors) > 0 {
		actors := make([]any, len(r.Actors))
		for i, a := range r.Actors {
			actors[i] = a
		}
		m["actors"] = actors
	}
	if len(r.Evidence) > 0 {
		ev := make([]any, len(r.Evidence))
		for i, e := range r.Evidence {
			ev[i] = map[string]any{"role": e.Role, "address": e.Address.String()}
		}
		m["evidence"] = ev
	}
	if len(r.Attributes) > 0 {
		attrs := make(map[string]any, len(r.Attributes))
		for k, v := range r.Attributes {
			attrs[k] = text(v)
		}
		m["attributes"] = attrs
	}
	return m
}

func summaryMap(s Summary) map[string]any {
	counts := make([]any, len(s.Counts))
	for i, c := range s.Counts {
		cm := map[string]any{"outcome": string(c.Outcome), "n": c.N}
		if c.Check != "" {
			cm["check"] = c.Check
		}
		counts[i] = cm
	}
	return map[string]any{
		"v":      formatVersion,
		"kind":   "summary",
		"point":  s.Point,
		"from":   s.From.UTC().Format(timeLayout),
		"until":  s.Until.UTC().Format(timeLayout),
		"counts": counts,
	}
}
