// Package decisionrecord is the record a deciding party — a gate, a boundary
// stage, a delivery decision — writes for each decision it makes, and the
// levels at which it is written: every decision, the decisions not accepted
// (refused, held and unenforced) only, counts per window, or none.
// Configuration defaults to every decision; this package has no default
// level, so a level is in effect only when it is chosen. It is not
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
	"github.com/provin-line/oss/internal/excerpt"
)

// Outcome is what a decision decided. A record is written when the deciding
// party decides, before what was decided on is carried out, by the deciding
// party or by whoever it answers. A refused or held decision did not go
// ahead: the deciding party enforces the check that refused or deferred it.
// Of an accepted or unenforced decision, a record does not say whether it
// went ahead, and a reader takes it as one that may have.
type Outcome string

const (
	// Accepted: no check refused or deferred; the deciding party decided to
	// accept what was decided on. If it refuses it afterwards, it records
	// that too (see Record).
	Accepted Outcome = "accepted"
	// Refused: a check that the deciding party enforces refused; the deciding
	// party refused what was decided on, and it did not go ahead.
	Refused Outcome = "refused"
	// Unenforced: only checks that the deciding party records without
	// enforcing refused; the deciding party did not enforce the refusal, so
	// what was decided on may have gone ahead.
	Unenforced Outcome = "unenforced"
	// Held: a check the deciding party enforces deferred the decision; what
	// was decided on has not gone ahead, and may later be decided again under
	// another DecisionID. Only format v2 writes it (see FormatVersion).
	Held Outcome = "held"
)

// quoteLimit is the most bytes an error here takes to quote a value it
// refuses (internal/excerpt).
const quoteLimit = 128

// rank orders the outcomes: a decision has the outcome of its record of the
// highest rank. Held is stronger than an acceptance, which it defers, and
// weaker than a refusal, recorded or enforced. An unknown outcome has none.
func rank(o Outcome) int {
	switch o {
	case Accepted:
		return 1
	case Held:
		return 2
	case Unenforced:
		return 3
	case Refused:
		return 4
	}
	return 0
}

// Confidence is how far the hop a refusal is diagnosed at is established.
type Confidence string

const (
	// ConfidenceClaimed: the hop is named by what was decided on, before its
	// signature was verified.
	ConfidenceClaimed Confidence = "claimed"
	// ConfidenceVerified: the hop is named after its signature was verified.
	ConfidenceVerified Confidence = "verified"
	// ConfidenceUnknown: the check concerns a hop, but the deciding party
	// cannot name it.
	ConfidenceUnknown Confidence = "unknown"
)

// Position is where a refusal is diagnosed: a hop of what was decided on, one
// step it came through, in the deciding party's terms. This package does not
// read Hop; as with Actors, its meaning is the deciding party's.
type Position struct {
	Hop        string // the hop's ID; empty exactly when Confidence is ConfidenceUnknown
	Confidence Confidence
}

// Evidence is one thing a decision was made on: its role (e.g. "approval",
// "chain") and its content address. A role may repeat; the order is kept (a
// chain's records, a boundary stage's segment, in order).
type Evidence struct {
	Role    string
	Address contentaddress.Address
}

// Record is the record of one decision.
//
// A decision recorded accepted and refused afterwards — an approval that
// expired between the record and the execution, say — is recorded again with
// the same DecisionID, Outcome Refused, its Check, and At the time of the
// refusal. A
// decision has the strongest outcome among its records, whatever the order
// they are read in: it is refused when any of them is refused; otherwise
// unenforced when any of them is unenforced; otherwise held when any of them
// is held; otherwise accepted.
//
// A writer follows one rule for the records of a decision: it records the
// decision accepted any number of times, then unenforced or refused at most
// once, and after that records nothing more of it; it makes each record only
// once the previous one of the decision has been taken (Filter.Record
// returned). A held decision has one record, the held one: to decide again
// what it deferred, the deciding party makes another decision, with another
// DecisionID. The writer knows the outcome when it writes: refused when an
// enforced check refused, held when an enforced check deferred, unenforced
// when only checks it records without enforcing refused. Recording a decision
// accepted again changes nothing. A
// writer that breaks the rule makes the summary level count the decision
// more than once, or under the check of the first of its records of that
// outcome, never under a weaker outcome than its strongest record; nothing
// else changes: no decision's outcome, and no record.
type Record struct {
	DecisionID string    // unique per decision; made by the deciding party (128 random bits, say)
	Point      string    // the deciding party's ID: a gate's, a boundary's
	At         time.Time // when the decision was made
	Outcome    Outcome
	Check      string            // the check that refused or deferred: a fixed name, required unless Accepted
	Reason     string            // for people
	Actors     []string          // whom the decision is attributed to (a gate: the signers)
	Evidence   []Evidence        // what was decided on, in order
	Attributes map[string]string // the deciding party's own fields

	// RefusedAt is where the refusal is diagnosed, when the deciding party
	// can say: only with an outcome other than Accepted. Format v2 only.
	RefusedAt *Position
	// VerifiedHops are the hops whose signatures the deciding party
	// verified, in order, whatever the outcome. Format v2 only: of length 0
	// (nil included), every format takes it and writes no member.
	VerifiedHops []string
}

// Validate checks the fields a reader keys on: a DecisionID and a Point, a
// time within the years 0000–9999 (so it is written in RFC 3339 and sorts as
// text), an outcome with a Check exactly when a check refused or deferred
// (every outcome but Accepted), each Evidence a role and an address, each
// Actor and attribute name valid UTF-8 and not empty; a RefusedAt only with
// an outcome other than Accepted, its Confidence one of the three, its Hop
// empty exactly when the Confidence is ConfidenceUnknown and otherwise valid
// UTF-8; each of the VerifiedHops valid UTF-8 and not empty. It checks them
// whatever the format version. Filter.Record and every Sink here check it,
// whatever the level: a malformed record is its writer's error. Text for
// people (Reason, attribute values) is not refused for invalid UTF-8; it is
// written with the invalid bytes replaced.
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
	case rank(r.Outcome) == 0:
		return fmt.Errorf("decisionrecord: record with outcome %s", excerpt.Quoted(string(r.Outcome), quoteLimit))
	case r.Outcome != Accepted && r.Check == "":
		return fmt.Errorf("decisionrecord: record with outcome %s without the check that refused or deferred", r.Outcome)
	case r.Outcome == Accepted && r.Check != "":
		return errors.New("decisionrecord: an acceptance with a refusing check")
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
	if p := r.RefusedAt; p != nil {
		switch {
		case r.Outcome == Accepted:
			return errors.New("decisionrecord: an acceptance with the position of a refusal")
		case p.Confidence != ConfidenceClaimed && p.Confidence != ConfidenceVerified && p.Confidence != ConfidenceUnknown:
			return fmt.Errorf("decisionrecord: a position with confidence %s", excerpt.Quoted(string(p.Confidence), quoteLimit))
		case p.Confidence == ConfidenceUnknown && p.Hop != "":
			return errors.New("decisionrecord: a position of confidence unknown with a hop")
		case p.Confidence != ConfidenceUnknown && p.Hop == "":
			return fmt.Errorf("decisionrecord: a position of confidence %s without a hop", p.Confidence)
		case !utf8.ValidString(p.Hop):
			return errors.New("decisionrecord: a position whose hop is not UTF-8")
		}
	}
	for _, h := range r.VerifiedHops {
		if h == "" || !utf8.ValidString(h) {
			return errors.New("decisionrecord: a verified hop that is empty or not UTF-8")
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
	Counts      []Count // ordered by outcome, then check, each as text (accepted, held, refused, unenforced)
}

// Validate checks a summary as Record.Validate checks a record: a Point, a
// window within the years 0000–9999 whose end is not before its start, and
// each Count an outcome with a Check exactly when it counts decisions a check
// refused or deferred (every outcome but Accepted), and N from 0 to 2^53−1,
// the Counts ordered by outcome, then check, with no two alike; outcomes and
// checks are compared as text, so accepted, held, refused, unenforced. Every
// Sink here checks it.
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
		case rank(c.Outcome) == 0:
			return fmt.Errorf("decisionrecord: count with outcome %s", excerpt.Quoted(string(c.Outcome), quoteLimit))
		case c.Outcome != Accepted && c.Check == "":
			return fmt.Errorf("decisionrecord: count with outcome %s without its check", c.Outcome)
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
// error from Record is what lets a decision be accepted, or passed with its
// refusal unenforced, so a Sink returns nil only once the record is written
// where it is kept (an unbuffered or synced writer).
//
// The sinks here return as soon as the call's context ends, without waiting
// for a write to end: the error wraps ctx.Err(), so errors.Is matches
// context.DeadlineExceeded or context.Canceled, and its text names the sink
// and says whether the write had started. A record or summary whose context
// ended before its write started is not written, then or later. A write that
// started cannot be stopped: it may end, and be kept, after the call
// returned. A sink here makes one write at a time (the log sink, one call of
// its handler at a time); a call behind a write that does not end returns at
// its own context's end, and once the write ends the sink writes again. A
// write that never ends (an io.Writer or a handler stuck for good) is not
// recovered: it keeps the sink's turn, so each sink holds at most one such
// write.
//
// With a context that cannot end (context.Background(), or one from
// context.WithoutCancel), a call waits for its write, behind any write that
// does not end, as in 0.4.0. A nil context is context.Background(). A panic
// in the io.Writer or the handler reaches the caller while the caller waits;
// after the caller has returned it is dropped, and the write counts as
// failed.
type Sink interface {
	Recorder
	SummaryRecorder
}

// turn is a sink's right to write: one write at a time, waited for with a
// context. A write keeps the turn until it has really ended.
type turn chan struct{}

func newTurn() turn { return make(turn, 1) }

// run runs write while holding t, and returns its error. A nil ctx is
// context.Background(). With a context that cannot end (ctx.Done() is nil),
// write runs in the caller's goroutine, as under a mutex. Otherwise it runs
// in a goroutine; when ctx ends first, run returns ctx's error: as
// notStarted when the write did not start (ctx ended before t was taken, or
// by the time write was about to run), and as unfinished when it started:
// write goes on, gives t back when it ends, and its result is dropped. A
// panic in write reaches the caller while the caller waits; after the
// caller has returned, it is dropped, a failed write.
func (t turn) run(ctx context.Context, who string, write func() error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Done() == nil {
		t <- struct{}{}
		defer func() { <-t }()
		return write()
	}
	select {
	case t <- struct{}{}:
	case <-ctx.Done():
		return notStarted(who, ctx.Err())
	}
	done := make(chan writeResult, 1)
	go func() {
		// With t held, ctx is looked at once more right before write runs:
		// a write whose context has ended by then does not start.
		r := catch(func() error {
			if err := ctx.Err(); err != nil {
				return notStarted(who, err)
			}
			return write()
		})
		<-t
		done <- r
	}()
	select {
	case r := <-done:
		return r.result()
	case <-ctx.Done():
		select {
		case r := <-done:
			return r.result()
		default:
			return unfinished(who, ctx.Err())
		}
	}
}

// runLate runs write while holding t, for a write that may come late: when t
// is free it takes it whatever ctx says, and write gets ctx without its
// cancellation, so it runs even after the caller has gone. Only when t is
// held does runLate wait for it, and then no longer than ctx; it waits for
// write no longer than ctx either. A nil ctx and one that cannot end are as
// in run, and so is a panic in write.
func (t turn) runLate(ctx context.Context, write func(context.Context)) {
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Done() == nil {
		t <- struct{}{}
		defer func() { <-t }()
		write(ctx)
		return
	}
	select {
	case t <- struct{}{}:
	default:
		select {
		case t <- struct{}{}:
		case <-ctx.Done():
			return
		}
	}
	done := make(chan writeResult, 1)
	go func() {
		r := catch(func() error {
			write(context.WithoutCancel(ctx))
			return nil
		})
		<-t
		done <- r
	}()
	select {
	case r := <-done:
		_ = r.result()
	case <-ctx.Done():
	}
}

// writeResult is how a write in a goroutine ended: its error, or the value
// it panicked with.
type writeResult struct {
	err      error
	panicked bool
	value    any
}

// catch runs write and keeps a panic in it as a writeResult.
func catch(write func() error) (r writeResult) {
	defer func() {
		if v := recover(); v != nil {
			r = writeResult{panicked: true, value: v}
		}
	}()
	return writeResult{err: write()}
}

// result is r's error; when write panicked, result panics again with its
// value, in the caller's goroutine.
func (r writeResult) result() error {
	if r.panicked {
		panic(r.value)
	}
	return r.err
}

// notStarted is the error of a write that who did not start because the
// context ended with err.
func notStarted(who string, err error) error {
	return fmt.Errorf("decisionrecord: %s: not written, the context ended before the write started: %w", who, err)
}

// unfinished is the error of a write that who started and that had not ended
// when the context ended with err: it goes on, and may still be kept.
func unfinished(who string, err error) error {
	return fmt.Errorf("decisionrecord: %s: the context ended before the write did, which goes on and may still be kept: %w", who, err)
}

// Level is how much a Filter writes.
type Level string

const (
	LevelAll Level = "all"
	// LevelRefusals writes every decision that is not accepted: refused,
	// held and unenforced.
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
// sink and the sink's failure is returned, so no decision is accepted, or
// passed with its refusal unenforced, without its record as far as the
// sink's nil means the record is kept (see Sink). At LevelRefusals and
// LevelSummary, the sink's failure is logged as a warning and Record returns
// nil: the decision does not change, so an unenforced decision may go ahead
// without its record. A deciding party that must not pass one unrecorded
// uses LevelAll. At LevelNone nothing is written. A Filter not made by
// NewFilter returns an error from every call.
//
// Record and Flush return when the sink does once the context ends (see
// Sink). A warning does not wait past the context either: when no warning is
// being written, it is written, late if the context has ended; when one is,
// and the context ends first, it is not written. A warning logger that does
// not end holds back only the warnings after it, as a sink's write that does
// not end holds back its writes.
type Filter struct {
	level    Level
	sink     Sink
	warn     *slog.Logger
	warnTurn turn

	mu      sync.Mutex
	from    time.Time
	windows map[string]*window // point → its tally since from
}

// outcomeCheck is what a Count counts: an outcome and its refusing or
// deferring check.
type outcomeCheck struct {
	outcome Outcome
	check   string
}

// window is one deciding party's tally at LevelSummary. It keeps the ids of
// the decisions accepted in it only: an acceptance needs whatever the
// deciding party checks for, while any caller can cause a refused, held or
// unenforced record (where the deciding party records only), so the ids kept
// are bounded by what the deciding party admits. A refused, held or
// unenforced decision not accepted in it is counted as it comes and keeps no
// id. Its
// counts are keyed by outcome and check, fixed names of the deciding party.
type window struct {
	counts   map[outcomeCheck]int64
	accepted map[string]outcomeCheck // DecisionID of a decision accepted in the window → what it is counted as
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
	f := &Filter{level: level, sink: sink, warn: warn, warnTurn: newTurn()}
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
		if r.Outcome == Accepted {
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

// count adds r to the window. A decision accepted in it is counted once, by
// the strongest outcome of its records: a record of a stronger outcome moves
// it there, with that record's check, and any other changes nothing. A
// refused, held or unenforced record of a decision not accepted in the
// window is counted as it comes and keeps no id: under the writer's rule
// (see Record) a decision has at most one, so it is counted once.
func (f *Filter) count(r Record) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.from.IsZero() {
		f.from = r.At
	}
	w := f.windows[r.Point]
	if w == nil {
		w = &window{counts: map[outcomeCheck]int64{}, accepted: map[string]outcomeCheck{}}
		f.windows[r.Point] = w
	}
	k := outcomeCheck{outcome: r.Outcome, check: r.Check}
	prev, seen := w.accepted[r.DecisionID]
	switch {
	case !seen:
		if r.Outcome == Accepted {
			w.accepted[r.DecisionID] = k
		}
		w.counts[k]++
	case rank(r.Outcome) > rank(prev.outcome):
		w.accepted[r.DecisionID] = k
		w.counts[prev]--
		w.counts[k]++
	}
}

// Flush writes, at LevelSummary, one Summary per deciding party with the
// counts of its decisions recorded since the last Flush (or the first record):
// each decision once, by its outcome in the window, when its writer follows
// the rule for a decision's records (see Record). A decision whose records
// fall in two windows is counted in each. It starts a new window at until. A
// window without decisions writes nothing.
// until must not be zero or before the window's start. At other levels it does
// nothing. A sink's failure is a warning; the decisions do not change. A
// context that has ended when Flush is called is an error wrapping its
// ctx.Err(), and the window is kept, counts and all, for the next Flush.
func (f *Filter) Flush(ctx context.Context, until time.Time) error {
	if f == nil || f.level == "" {
		return errNotMade
	}
	if f.level != LevelSummary {
		return nil
	}
	if ctx != nil && ctx.Err() != nil {
		return fmt.Errorf("decisionrecord: flush with a context that has ended, the window kept for the next flush: %w", ctx.Err())
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
			f.warnf(ctx, "decision record: summary not written", "point", p, "err", err)
		}
	}
	return nil
}

// notWritten warns that the sink did not write a record, at a level where
// that does not change the decision.
func (f *Filter) notWritten(ctx context.Context, err error) {
	f.warnf(ctx, "decision record: not written", "level", string(f.level), "err", err)
}

// warnf writes a warning, one at a time, without waiting past ctx: when no
// warning is being written it is written, late if ctx has ended or ends
// first; when one is being written and ctx ends before it does, it is not
// written.
func (f *Filter) warnf(ctx context.Context, msg string, args ...any) {
	f.warnTurn.runLate(ctx, func(ctx context.Context) {
		f.warn.WarnContext(ctx, msg, args...)
	})
}

// FormatVersion is the version of the form in which the sinks here write
// records and summaries: the "v" member of every line and log entry. The
// version changes whenever a member changes, or the values of "kind",
// "outcome" or "confidence"; within a version neither changes. The values of
// "check" and the names in "attributes" are the deciding party's, and grow
// whatever the version.
type FormatVersion int

const (
	// FormatV1 is the form of 0.4.0: the outcomes accepted, refused and
	// unenforced.
	FormatV1 FormatVersion = 1
	// FormatV2 adds the outcome held and a record's "refusedAt" and
	// "verifiedHops".
	FormatV2 FormatVersion = 2
)

// known reports whether the sinks here write format v.
func (v FormatVersion) known() bool { return v == FormatV1 || v == FormatV2 }

// Error is the type of this package's sentinel errors. The sentinels are
// constants, so no importer can reassign them; errors.Is matches them as it
// matches any comparable error.
type Error string

func (e Error) Error() string { return string(e) }

// ErrNotInFormat reports a record or summary that a sink's format version
// cannot express: in format v1, a held outcome, a RefusedAt, VerifiedHops, or
// a count of held decisions. The sink writes nothing of it.
const ErrNotInFormat Error = "decisionrecord: not expressible in this format version"

// expressRecord is nil when format v expresses r, and otherwise names, as
// ErrNotInFormat, a member it does not.
func expressRecord(v FormatVersion, r Record) error {
	if v != FormatV1 {
		return nil
	}
	switch {
	case r.Outcome == Held:
		return fmt.Errorf("%w: format v1 has no outcome %s", ErrNotInFormat, Held)
	case r.RefusedAt != nil:
		return fmt.Errorf("%w: format v1 has no refusedAt", ErrNotInFormat)
	case len(r.VerifiedHops) > 0:
		return fmt.Errorf("%w: format v1 has no verifiedHops", ErrNotInFormat)
	}
	return nil
}

// expressSummary is expressRecord for a summary.
func expressSummary(v FormatVersion, s Summary) error {
	if v != FormatV1 {
		return nil
	}
	for _, c := range s.Counts {
		if c.Outcome == Held {
			return fmt.Errorf("%w: format v1 has no outcome %s", ErrNotInFormat, Held)
		}
	}
	return nil
}

// timeLayout is RFC 3339 in UTC with nine fraction digits, so that times sort
// as text.
const timeLayout = "2006-01-02T15:04:05.000000000Z"

// NewJSONLines returns a sink writing each record and summary to w in format
// v1 as one line of RFC 8785 JSON, with "v" (the format version) and "kind"
// ("record" or "summary"). Line breaks inside values are escaped, but U+2028
// and U+2029 are written as is (RFC 8785): a reader splits on "\n" only. A
// line is written with one Write; after a failed Write, the next line starts
// with "\n", so a partial line stays one unreadable line and the lines after
// it stay whole. A nil w makes every write fail. What format v1 cannot express
// is ErrNotInFormat. NewJSONLines(w) is NewJSONLinesFormat(w, FormatV1).
func NewJSONLines(w io.Writer) Sink {
	return &jsonLines{turn: newTurn(), w: w, v: FormatV1}
}

// NewJSONLinesFormat is NewJSONLines writing format v. A version the sinks
// here do not write is an error.
func NewJSONLinesFormat(w io.Writer, v FormatVersion) (Sink, error) {
	if !v.known() {
		return nil, fmt.Errorf("decisionrecord: unknown format version %d", v)
	}
	return &jsonLines{turn: newTurn(), w: w, v: v}, nil
}

type jsonLines struct {
	turn turn
	w    io.Writer
	v    FormatVersion
	// broken is set by a failed Write, so the next line starts on a line of
	// its own. Only the holder of turn reads or sets it.
	broken bool
}

func (j *jsonLines) Record(ctx context.Context, r Record) error {
	if err := r.Validate(); err != nil {
		return err
	}
	m, err := recordMap(r, j.v)
	if err != nil {
		return err
	}
	return j.write(ctx, m)
}

func (j *jsonLines) Summary(ctx context.Context, s Summary) error {
	if err := s.Validate(); err != nil {
		return err
	}
	m, err := summaryMap(s, j.v)
	if err != nil {
		return err
	}
	return j.write(ctx, m)
}

// write makes m's line before it waits for the turn, so the line is the
// caller's record as given, whatever the caller changes after the call.
func (j *jsonLines) write(ctx context.Context, m map[string]any) error {
	if j.w == nil {
		return errors.New("decisionrecord: no writer")
	}
	b, err := jcs.CanonicalizeRFC8785(m)
	if err != nil {
		return fmt.Errorf("decisionrecord: %w", err)
	}
	line := append(b, '\n')
	return j.turn.run(ctx, "JSON lines sink", func() error {
		out := line
		if j.broken {
			out = append([]byte{'\n'}, line...)
		}
		// broken holds until the Write succeeds, so a Write that fails or
		// panics leaves the next line to start on a line of its own.
		j.broken = true
		if _, err := j.w.Write(out); err != nil {
			return fmt.Errorf("decisionrecord: %w", err)
		}
		j.broken = false
		return nil
	})
}

// NewLog returns a sink writing each record and summary as one structured log
// entry at the info level, through the logger's handler so that its failure
// is the sink's: a handler that does not take info entries, or that fails to
// handle one, is an error (at LevelAll, the decision is refused). A handler
// that returns nil without keeping the entry cannot be detected here: at
// LevelAll, use a handler whose nil means kept. A nil l makes every write
// fail. An entry carries the members of a JSON line as its attributes, in
// format v1, "v" included; what format v1 cannot express is ErrNotInFormat.
// NewLog(l) is NewLogFormat(l, FormatV1).
func NewLog(l *slog.Logger) Sink {
	return logSink{turn: newTurn(), l: l, v: FormatV1}
}

// NewLogFormat is NewLog writing format v. A version the sinks here do not
// write is an error.
func NewLogFormat(l *slog.Logger, v FormatVersion) (Sink, error) {
	if !v.known() {
		return nil, fmt.Errorf("decisionrecord: unknown format version %d", v)
	}
	return logSink{turn: newTurn(), l: l, v: v}, nil
}

type logSink struct {
	turn turn
	l    *slog.Logger
	v    FormatVersion
}

func (s logSink) Record(ctx context.Context, r Record) error {
	if err := r.Validate(); err != nil {
		return err
	}
	m, err := recordMap(r, s.v)
	if err != nil {
		return err
	}
	return s.emit(ctx, "decision record", m)
}

func (s logSink) Summary(ctx context.Context, sum Summary) error {
	if err := sum.Validate(); err != nil {
		return err
	}
	m, err := summaryMap(sum, s.v)
	if err != nil {
		return err
	}
	return s.emit(ctx, "decision summary", m)
}

// emit makes the entry before it waits for the turn, so the entry is the
// caller's record as given; the handler's Enabled and Handle run with the
// turn held.
func (s logSink) emit(ctx context.Context, msg string, m map[string]any) error {
	if s.l == nil {
		return errors.New("decisionrecord: no logger")
	}
	h := s.l.Handler()
	rec := slog.NewRecord(time.Now(), slog.LevelInfo, msg, 0)
	rec.Add(mapAttrs(m)...)
	return s.turn.run(ctx, "log sink", func() error {
		if !h.Enabled(ctx, slog.LevelInfo) {
			return errors.New("decisionrecord: the logger does not take info entries")
		}
		if err := ctx.Err(); err != nil {
			return notStarted("log sink", err)
		}
		if err := h.Handle(ctx, rec); err != nil {
			return fmt.Errorf("decisionrecord: %w", err)
		}
		return nil
	})
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

// recordMap is r's members in format v, or ErrNotInFormat when v cannot
// express one of them: no map of a version holds a member the version lacks.
func recordMap(r Record, v FormatVersion) (map[string]any, error) {
	if err := expressRecord(v, r); err != nil {
		return nil, err
	}
	m := map[string]any{
		"v":          int(v),
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
	if p := r.RefusedAt; p != nil {
		pm := map[string]any{"confidence": string(p.Confidence)}
		if p.Hop != "" {
			pm["hop"] = p.Hop
		}
		m["refusedAt"] = pm
	}
	if len(r.VerifiedHops) > 0 {
		hops := make([]any, len(r.VerifiedHops))
		for i, h := range r.VerifiedHops {
			hops[i] = h
		}
		m["verifiedHops"] = hops
	}
	return m, nil
}

// summaryMap is recordMap for a summary.
func summaryMap(s Summary, v FormatVersion) (map[string]any, error) {
	if err := expressSummary(v, s); err != nil {
		return nil, err
	}
	counts := make([]any, len(s.Counts))
	for i, c := range s.Counts {
		cm := map[string]any{"outcome": string(c.Outcome), "n": c.N}
		if c.Check != "" {
			cm["check"] = c.Check
		}
		counts[i] = cm
	}
	return map[string]any{
		"v":      int(v),
		"kind":   "summary",
		"point":  s.Point,
		"from":   s.From.UTC().Format(timeLayout),
		"until":  s.Until.UTC().Format(timeLayout),
		"counts": counts,
	}, nil
}
