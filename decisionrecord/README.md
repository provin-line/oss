# decisionrecord — the record of each decision

A deciding party (a gate, a boundary stage, a delivery decision) writes one
`Record` per decision: its id, the deciding party, the time, its outcome,
the check that refused and why, whom the decision is attributed to,
the content addresses of what was decided on, and the party's own fields. A
record never holds a payload.

| Outcome | Checks | What was decided on |
| --- | --- | --- |
| `accepted` | none refused | went ahead |
| `refused` | an enforced check refused | did not go ahead |
| `unenforced` | only checks recorded without enforcing refused | went ahead |

`Filter` writes records to a `Sink` at a level chosen explicitly:

| Level | Writes | A record that cannot be written |
| --- | --- | --- |
| `all` | every record | is an error: the deciding party refuses the decision |
| `refusals` | refused and unenforced decisions only | is a warning; the decision stands |
| `summary` | a `Summary` (counts per outcome and check) per deciding party at each `Flush` | is a warning |
| `none` | nothing | — |

The zero level is refused, so a level is in effect only when it is chosen.
A deciding party follows one rule: if `Filter.Record` returns an error, refuse.
Below `all`, a record that cannot be written changes no decision, so an
unenforced decision goes ahead without its record; a deciding party that must
not let one go ahead unrecorded uses `all`.
A malformed record (`Record.Validate`) is an error at every level, `none`
included: it is the writer's error, not the sink's. Every sink here checks
records and summaries (`Summary.Validate`) too, for a caller that writes to
one directly.

A decision recorded accepted and refused afterwards is recorded again with the
same `DecisionID`. A decision has the strongest outcome among its records, whatever
order they are read in: refused when **any** record of its id is refused,
otherwise unenforced when any is unenforced, otherwise accepted. A writer
records a decision accepted any number of times, then unenforced or refused
at most once, and nothing after that; it knows the outcome when it writes. It
makes each record of a decision only once the previous one has been taken.
Then the summary level counts each decision once. It keeps the ids of
accepted decisions only, so its memory is bounded by what the deciding party
admits, not by refusals or unenforced decisions, which any caller can cause;
it counts any other refused or unenforced record as it comes. A writer that
breaks the rule makes the summary count a decision more than once, or under
the check of its first record of that outcome, never under a weaker outcome
than its strongest record; nothing else changes. Counts are keyed by outcome
and check, which are fixed names of the deciding party. A refused or
unenforced record carries the check that refused, an accepted one none.
`Evidence` is an ordered list of roles and content addresses
(`contentaddress.Address`), never a value. An actor is non-empty valid UTF-8,
as the id and the deciding party are: a reader keys on it. Times are within
the years 0000–9999. Text for people (the reason, attribute values) is
written with invalid UTF-8 replaced, so a record is not lost to its own
bytes. A count in a summary is from 0 to 2^53−1 (an `int64`), written as a
JSON number, and the counts are ordered by outcome, then check, each compared
as text (so `accepted`, `refused`, `unenforced`), none repeated.

Sinks must be safe for concurrent use, and at `all` return nil only once the
record is kept (an unbuffered or synced writer):

- `NewJSONLines`: one RFC 8785 JSON object per line, with `"v"` (the format
  version) and `"kind"`; times in UTC with nine fraction digits, so they sort
  as text. Split on `"\n"` only (U+2028 and U+2029 are written as is). After a
  failed write the next line starts on a line of its own.
- `NewLog`: one structured log entry per record or summary, through the
  handler, so a logger that drops info entries or fails is an error. A handler
  that returns nil without keeping the entry cannot be detected; at `all`, use
  one whose nil means kept.

A `Filter` not made by `NewFilter` refuses every call. This package is not the
record of used nonces a gate keeps against replays.
