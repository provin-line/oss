# decisionrecord — the record of each decision

A deciding party (a gate, a boundary stage, a delivery decision) writes one
`Record` per decision: its id, the deciding party, the time, its outcome,
the check that refused or deferred and why, whom the decision is attributed to,
the content addresses of what was decided on, and the party's own fields. A
record never holds a payload.

| Outcome | Checks | The deciding party |
| --- | --- | --- |
| `accepted` | none refused or deferred | decided to accept what was decided on |
| `refused` | an enforced check refused | refused what was decided on: it did not go ahead |
| `unenforced` | only checks recorded without enforcing refused | did not enforce the refusal: what was decided on may have gone ahead |
| `held` (format v2) | an enforced check deferred the decision | held what was decided on back: it has not gone ahead, and may be decided again under another `DecisionID` |

A record is written when the deciding party decides, before what was decided
on is carried out, by the deciding party or by whoever it answers. A refused
or held decision did not go ahead. Of an accepted or unenforced decision, a record
does not say whether it went ahead, and a reader takes it as one that may
have gone ahead. An accepted decision refused afterwards is recorded again
(below).

`Filter` writes records to a `Sink` at a level chosen explicitly:

| Level | Writes | A record that cannot be written |
| --- | --- | --- |
| `all` | every record | is an error: the deciding party refuses the decision |
| `refusals` | the decisions not accepted only: refused, held and unenforced | is a warning; the decision stands |
| `summary` | a `Summary` (counts per outcome and check) per deciding party at each `Flush` | is a warning |
| `none` | nothing | — |

The zero level is refused, so a level is in effect only when it is chosen.
A deciding party follows one rule: if `Filter.Record` returns an error, refuse.
Below `all`, a record that cannot be written changes no decision, so an
unenforced decision may go ahead without its record; a deciding party that
must not pass an unenforced decision unrecorded uses `all`.
A malformed record (`Record.Validate`) is an error at every level, `none`
included: it is the writer's error, not the sink's. Every sink here checks
records and summaries (`Summary.Validate`) too, for a caller that writes to
one directly.

A decision recorded accepted and refused afterwards is recorded again with the
same `DecisionID`. A decision has the strongest outcome among its records, whatever
order they are read in: refused when **any** record of its id is refused,
otherwise unenforced when any is unenforced, otherwise held when any is held,
otherwise accepted. A writer
records a decision accepted any number of times, then unenforced or refused
at most once, and nothing after that; it knows the outcome when it writes. A
held decision has one record, the held one: what it deferred is decided
again as another decision, with another `DecisionID`. A writer
makes each record of a decision only once the previous one has been taken.
Then the summary level counts each decision once. It keeps the ids of
accepted decisions only, so its memory is bounded by what the deciding party
admits, not by refusals, held or unenforced decisions, which any caller can
cause; it counts any other refused, held or unenforced record as it comes. A
writer that
breaks the rule makes the summary count a decision more than once, or under
the check of its first record of that outcome, never under a weaker outcome
than its strongest record; nothing else changes. Counts are keyed by outcome
and check, which are fixed names of the deciding party. A record of any
outcome but accepted carries the check that refused or deferred, an accepted
one none.
`Evidence` is an ordered list of roles and content addresses
(`contentaddress.Address`), never a value. An actor is non-empty valid UTF-8,
as the id and the deciding party are: a reader keys on it. Times are within
the years 0000–9999. Text for people (the reason, attribute values) is
written with invalid UTF-8 replaced, so a record is not lost to its own
bytes. A count in a summary is from 0 to 2^53−1 (an `int64`), written as a
JSON number, and the counts are ordered by outcome, then check, each compared
as text (so `accepted`, `held`, `refused`, `unenforced`), none repeated.

Sinks must be safe for concurrent use, and at `all` return nil only once the
record is kept (an unbuffered or synced writer):

- `NewJSONLines`: one RFC 8785 JSON object per line, with `"v"` (the format
  version) and `"kind"`; times in UTC with nine fraction digits, so they sort
  as text. Split on `"\n"` only (U+2028 and U+2029 are written as is). The
  writer gets one `Write` at a time, even after a call has returned before
  its `Write` ended. After a failed write the next line starts on a line of
  its own.
- `NewLog`: one structured log entry per record or summary, through the
  handler, so a logger that drops info entries or fails is an error. A handler
  that returns nil without keeping the entry cannot be detected; at `all`, use
  one whose nil means kept. An entry carries the members of a JSON line as
  its attributes, `"v"` included.

These sinks return as soon as the call's context ends, without waiting for a
write to end: the error wraps `ctx.Err()` (so `errors.Is` matches
`context.DeadlineExceeded` or `context.Canceled`), names the sink, and says
either that the write did not start or that it may have started. A record
whose context ended before its write started is not written, then or later; a
write that started cannot be stopped, and may end, and be kept, after the call
returned. A write that does not end may hold back the sink's other writes
until it ends, each of their calls still returning at its own context's end. A
write that never ends (a writer or handler stuck for good) is not recovered,
and each sink holds at most one. With a context that cannot end
(`context.Background()`, or one from `context.WithoutCancel`) a call waits for
its write, behind any write that does not end, as in 0.4.0; a nil context is
`context.Background()`. A panic in the writer or the handler reaches the
caller. With a context that cannot end, the write runs in the caller's
goroutine, and the panic reaches the caller as itself. With one that can, the
write runs in a goroutine of its own, and the panic reaches the caller as a
`*decisionrecord.WritePanic` holding the value and the writer's stack (its
text has both; `Unwrap` gives the value when it is an error), unless the call
has returned at its context's end before the sink handed the panic over; then
the panic is dropped and the write counts as failed. A writer or handler that
calls `runtime.Goexit` in the sink's own goroutine fails its write; in the
caller's goroutine, `runtime.Goexit` ends that goroutine, as it does anywhere,
and the call does not return. Either way, the sink writes again after it.

At `all`, a record for which `Filter.Record` returned an error may still be
kept: its write may have started and end after the call returned, and a
writer or handler may keep a record and still return an error. A deciding
party that refuses the decision then, and wants a reader to see the refusal,
records the decision again, refused, with the same `DecisionID`, through the
same `Filter`: the decision has the strongest outcome among its records. The
rule for a decision's records allows that refusal, through the `Filter` whose
`Record` returned the error.

Below `all`, a `Filter`'s warning that a sink failed does not wait past the
context either: when no warning is being written it is written, late if the
context has ended; when one is, and the context ends first, it is not. The
handler of the warnings is a handler as above. Its panic reaches the caller of
`Filter.Record` or `Filter.Flush` in the same way. When it calls
`runtime.Goexit` in the warning's own goroutine, the warning is lost; in the
caller's goroutine, that goroutine ends. Either way, the `Filter` warns again
after it. `Filter.Flush` with a context that has already ended returns its
error and keeps the window, counts and all, for the next `Flush`. When the
context ends during a `Flush`, the window is not kept: a summary whose write
has not started by then is lost, as any summary the sink fails to write is (a
warning at most); one whose write had started may still be kept. So that no
summary of the last window is lost to the shutdown signal, the last `Flush`,
at shutdown, takes a context that the signal does not end and that has a
deadline of its own, as `context.WithTimeout(context.WithoutCancel(ctx), d)`.
Without a deadline it may wait for good behind a write that does not end. When
the deadline passes first, the counts not written by then are lost, as above.
A write that fails still loses its summary. A panic as `Flush` writes one
point's summary, in the sink or in the handler of the warning that the summary
was not written, goes on to the caller as it was raised, with its own stack,
once `Flush` has written every point after it; so does `runtime.Goexit` in the
caller's goroutine. `Flush` calls the sink again after it panicked, so a sink
not made here stays callable after a panic, and the panic reaches the caller
once those writes have returned. A panic as one of those is a warning that its
point's summary was not written, with its value; a panic in that warning's
handler is dropped.

## Format versions

A sink writes one format version, the `"v"` of every line and entry.
`NewJSONLines` and `NewLog` write format v1, as 0.4.0 does;
`NewJSONLinesFormat` and `NewLogFormat` write the version they are given,
`FormatV1` or `FormatV2`, and refuse any other.

| Version | Adds |
| --- | --- |
| 1 | the members above; outcomes `accepted`, `refused`, `unenforced` |
| 2 | the outcome `held`; in a record, `"refusedAt"` and `"verifiedHops"` |

In format v2, a record may carry:

- `"refusedAt"`: on a refused or unenforced decision only, where its
  refusal is diagnosed, a hop of what was decided on — one step it came
  through, in the deciding party's terms, as an actor is. A held decision
  was not refused and has none. `{"hop": "…", "confidence": "…"}`, the
  confidence one of `claimed` (the hop is named by what was decided on,
  before its signature was verified), `verified` (named after its signature
  was verified) and `unknown` (the check concerns a hop the deciding party
  cannot name; then there is no `"hop"`).
- `"verifiedHops"`: the hops whose signatures the deciding party verified,
  in order, on a record of any outcome. None is written as no member.

The confidence grades the position only: how far the hop's name is
established. It is not the verdict of a verification (in `vc`, a
`ConfidenceState` of failed, indeterminate or verified): `verified` does not
say that what was decided on, or any verification of it, is verified.
`"refusedAt"` and `"verifiedHops"` are independent: a `"refusedAt"` of
confidence `verified` need not name one of the `"verifiedHops"`.

A format v1 sink given what format v1 cannot express — a held outcome, a
`RefusedAt`, verified hops, a count of held decisions — returns an error
matching `ErrNotInFormat` and writes nothing of it; at `all`, the deciding
party refuses the decision. At `summary`, a `Filter` does not know its
sink's version: one held decision in a window makes a format v1 sink refuse
that deciding party's whole summary of the window, every count in it, and
the `Filter` warns. A deciding party that holds decisions writes format v2.
`Record.Validate` checks the format v2 members whatever the version.

The version changes whenever any of these changes: a member, the form or
the meaning of a member's value, the set of values of `"kind"`, `"outcome"`
or `"confidence"`, and, in the log sink, an entry's message or level. Within
a version none of them changes. A reader that refuses members it does not
know can read every line of the versions it knows. The values of `"check"`
and the names in `"attributes"` are the deciding party's, and grow whatever
the version.

A `Filter` not made by `NewFilter` refuses every call. This package is not the
record of used nonces a gate keeps against replays.
