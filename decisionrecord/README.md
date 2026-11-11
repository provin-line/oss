# decisionrecord — the record of each decision

A deciding party (a gate, a boundary stage, a delivery decision) writes one
`Record` per decision: its id, the deciding party, the time, its outcome,
the check that refused and why, whom the decision is attributed to,
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
  as text. Split on `"\n"` only (U+2028 and U+2029 are written as is). After a
  failed write the next line starts on a line of its own.
- `NewLog`: one structured log entry per record or summary, through the
  handler, so a logger that drops info entries or fails is an error. A handler
  that returns nil without keeping the entry cannot be detected; at `all`, use
  one whose nil means kept. An entry carries the members of a JSON line as
  its attributes, `"v"` included.

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

- `"refusedAt"`: where a decision that is not accepted is diagnosed, a hop
  of what was decided on — one step it came through, in the deciding
  party's terms, as an actor is. `{"hop": "…", "confidence": "…"}`, the
  confidence one of `claimed` (the hop is named by what was decided on,
  before its signature was verified), `verified` (named after its signature
  was verified) and `unknown` (the check concerns a hop the deciding party
  cannot name; then there is no `"hop"`).
- `"verifiedHops"`: the hops whose signatures the deciding party verified,
  in order, on a record of any outcome. None is written as no member.

A format v1 sink given what format v1 cannot express — a held outcome, a
`RefusedAt`, verified hops, a count of held decisions — returns an error
matching `ErrNotInFormat` and writes nothing of it; at `all`, the deciding
party refuses the decision. At `summary`, a `Filter` does not know its
sink's version: one held decision in a window makes a format v1 sink refuse
that deciding party's whole summary of the window, every count in it, and
the `Filter` warns. A deciding party that holds decisions writes format v2.
`Record.Validate` checks the format v2 members whatever the version.

The version changes whenever a member changes, or the values of `"kind"`,
`"outcome"` or `"confidence"`; within a version neither changes. A reader
that refuses members it does not know can read every line of the versions
it knows. The values of `"check"` and the names in `"attributes"` are the
deciding party's, and grow whatever the version.

A `Filter` not made by `NewFilter` refuses every call. This package is not the
record of used nonces a gate keeps against replays.
