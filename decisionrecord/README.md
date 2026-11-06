# decisionrecord — the record of each decision

A deciding party (a gate, a boundary stage, a delivery decision) writes one
`Record` per decision: its id, the deciding party, the time, accepted or
refused, the check that refused and why, whom the decision is attributed to,
the content addresses of what was decided on, and the party's own fields. A
record never holds a payload.

`Filter` writes records to a `Sink` at a level chosen explicitly:

| Level | Writes | A record that cannot be written |
| --- | --- | --- |
| `all` | every record | is an error: the deciding party refuses the decision |
| `refusals` | refused decisions only | is a warning; the decision stands |
| `summary` | a `Summary` (counts per outcome and check) per deciding party at each `Flush` | is a warning |
| `none` | nothing | — |

The zero level is refused, so a level is in effect only when it is chosen.
A deciding party follows one rule: if `Filter.Record` returns an error, refuse.

A decision refused after its record was written is recorded again with the same
`DecisionID`. A decision is refused when **any** record of its id is refused,
whatever order the records are read in; the summary level counts such a
decision once, as refused. A refusal carries the check that refused, an
acceptance none. `Evidence` is an ordered list of roles and content addresses
(`sha256:` and 64 hex digits), never a value. Text taken from a decision's
input (reason, actors, attribute values) is written with invalid UTF-8
replaced, so a record is not lost to its own bytes.

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
