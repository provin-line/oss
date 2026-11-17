package decisionrecord_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/decisionrecord"
)

// goldenRecords are records that use every member format v1 has: an
// acceptance, a refusal with every optional member (a time with nanoseconds;
// a reason with a line break, a tab, a control character, a backslash, "<",
// "&", U+2028 and invalid UTF-8; actors, evidence and attributes), and an
// unenforced decision.
func goldenRecords(t *testing.T) []decisionrecord.Record {
	return []decisionrecord.Record{
		{DecisionID: "d-accepted", Point: "gate-a", At: t0, Outcome: decisionrecord.Accepted},
		{
			DecisionID: "d-refused", Point: "gate-a", At: t0.Add(123456789 * time.Nanosecond),
			Outcome: decisionrecord.Refused, Check: "approval.expired",
			Reason: "line one\nline two and \xff, tab\there, ctl\x01, back\\slash, <tag> & amp",
			Actors: []string{"did:dplaax:poc.dplaax.dev:org:acme", "did:dplaax:poc.dplaax.dev:org:other"},
			Evidence: []decisionrecord.Evidence{
				{Role: "approval", Address: address(t, "sha256:"+hex64('a'))},
				{Role: "chain", Address: address(t, "sha256:"+hex64('b'))},
			},
			Attributes: map[string]string{"op": "transfer", "zone": "eu\xff", "a b": "c\"d"},
		},
		{DecisionID: "d-unenforced", Point: "gate-b", At: t0.Add(time.Second), Outcome: decisionrecord.Unenforced, Check: "rate.limit", Reason: "observed only"},
	}
}

// goldenSummary is a summary with a count of each outcome format v1 has.
func goldenSummary() decisionrecord.Summary {
	return decisionrecord.Summary{
		Point: "gate-a", From: t0, Until: t0.Add(time.Minute),
		Counts: []decisionrecord.Count{
			{Outcome: decisionrecord.Accepted, N: 3},
			{Outcome: decisionrecord.Refused, Check: "approval.expired", N: 2},
			{Outcome: decisionrecord.Unenforced, Check: "rate.limit", N: 1},
		},
	}
}

// hex64 is 64 copies of c, the hex digest part of a content address.
func hex64(c byte) string {
	b := make([]byte, 64)
	for i := range b {
		b[i] = c
	}
	return string(b)
}

// valueHandler keeps, for each entry it is handed, its level, its message
// and its attributes in order, each as its key, its slog.Kind and its Go
// value: what a handler is handed, not how one renders it.
type valueHandler struct{ entries *[]string }

func (valueHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h valueHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %q", r.Level, r.Message)
	r.Attrs(func(a slog.Attr) bool {
		fmt.Fprintf(&b, " %s=%s:%s", a.Key, a.Value.Kind(), goValue(a.Value.Any()))
		return true
	})
	*h.entries = append(*h.entries, b.String())
	return nil
}

func (h valueHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h valueHandler) WithGroup(string) slog.Handler      { return h }

// goValue writes v with its Go type, going into the slices and maps of
// which a record's members are made.
func goValue(v any) string {
	switch v := v.(type) {
	case []any:
		parts := make([]string, len(v))
		for i, e := range v {
			parts[i] = goValue(e)
		}
		return "[]any{" + strings.Join(parts, ",") + "}"
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, len(keys))
		for i, k := range keys {
			parts[i] = fmt.Sprintf("%q:%s", k, goValue(v[k]))
		}
		return "map[string]any{" + strings.Join(parts, ",") + "}"
	}
	return fmt.Sprintf("%T(%#v)", v, v)
}

// withoutTime drops the time slog.JSONHandler adds to an entry.
func withoutTime(groups []string, a slog.Attr) slog.Attr {
	if len(groups) == 0 && a.Key == slog.TimeKey {
		return slog.Attr{}
	}
	return a
}

// writeGolden writes goldenRecords and goldenSummary to the three format v1
// sinks: NewJSONLines, NewLog through slog.JSONHandler without the time, and
// NewLog through a valueHandler.
func writeGolden(t *testing.T) (jsonLines, logLines string, logValues []string) {
	t.Helper()
	var jb, lb bytes.Buffer
	sinks := []decisionrecord.Sink{
		decisionrecord.NewJSONLines(&jb),
		decisionrecord.NewLog(slog.New(slog.NewJSONHandler(&lb, &slog.HandlerOptions{ReplaceAttr: withoutTime}))),
		decisionrecord.NewLog(slog.New(valueHandler{&logValues})),
	}
	for _, s := range sinks {
		for _, r := range goldenRecords(t) {
			if err := s.Record(context.Background(), r); err != nil {
				t.Fatal(err)
			}
		}
		if err := s.Summary(context.Background(), goldenSummary()); err != nil {
			t.Fatal(err)
		}
	}
	return jb.String(), lb.String(), logValues
}

// goldenJSONLinesV1 are the lines NewJSONLines writes for goldenRecords and
// goldenSummary, as 0.4.0 writes them.
var goldenJSONLinesV1 = []string{
	"{\"at\":\"2026-11-06T12:00:00.000000000Z\",\"decisionId\":\"d-accepted\",\"kind\":\"record\",\"outcome\":\"accepted\",\"point\":\"gate-a\",\"v\":1}\n",
	"{\"actors\":[\"did:dplaax:poc.dplaax.dev:org:acme\",\"did:dplaax:poc.dplaax.dev:org:other\"],\"at\":\"2026-11-06T12:00:00.123456789Z\",\"attributes\":{\"a b\":\"c\\\"d\",\"op\":\"transfer\",\"zone\":\"eu�\"},\"check\":\"approval.expired\",\"decisionId\":\"d-refused\",\"evidence\":[{\"address\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"role\":\"approval\"},{\"address\":\"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"role\":\"chain\"}],\"kind\":\"record\",\"outcome\":\"refused\",\"point\":\"gate-a\",\"reason\":\"line one\\nline two\u2028and �, tab\\there, ctl\\u0001, back\\\\slash, <tag> & amp\",\"v\":1}\n",
	"{\"at\":\"2026-11-06T12:00:01.000000000Z\",\"check\":\"rate.limit\",\"decisionId\":\"d-unenforced\",\"kind\":\"record\",\"outcome\":\"unenforced\",\"point\":\"gate-b\",\"reason\":\"observed only\",\"v\":1}\n",
	"{\"counts\":[{\"n\":3,\"outcome\":\"accepted\"},{\"check\":\"approval.expired\",\"n\":2,\"outcome\":\"refused\"},{\"check\":\"rate.limit\",\"n\":1,\"outcome\":\"unenforced\"}],\"from\":\"2026-11-06T12:00:00.000000000Z\",\"kind\":\"summary\",\"point\":\"gate-a\",\"until\":\"2026-11-06T12:01:00.000000000Z\",\"v\":1}\n",
}

// goldenLogV1 are the entries NewLog hands its handler for goldenRecords and
// goldenSummary, as 0.4.0 hands them, rendered by slog.JSONHandler without
// the time it adds.
var goldenLogV1 = []string{
	"{\"level\":\"INFO\",\"msg\":\"decision record\",\"at\":\"2026-11-06T12:00:00.000000000Z\",\"decisionId\":\"d-accepted\",\"kind\":\"record\",\"outcome\":\"accepted\",\"point\":\"gate-a\",\"v\":1}\n",
	"{\"level\":\"INFO\",\"msg\":\"decision record\",\"actors\":[\"did:dplaax:poc.dplaax.dev:org:acme\",\"did:dplaax:poc.dplaax.dev:org:other\"],\"at\":\"2026-11-06T12:00:00.123456789Z\",\"attributes\":{\"a b\":\"c\\\"d\",\"op\":\"transfer\",\"zone\":\"eu�\"},\"check\":\"approval.expired\",\"decisionId\":\"d-refused\",\"evidence\":[{\"address\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"role\":\"approval\"},{\"address\":\"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"role\":\"chain\"}],\"kind\":\"record\",\"outcome\":\"refused\",\"point\":\"gate-a\",\"reason\":\"line one\\nline two\\u2028and �, tab\\there, ctl\\u0001, back\\\\slash, <tag> & amp\",\"v\":1}\n",
	"{\"level\":\"INFO\",\"msg\":\"decision record\",\"at\":\"2026-11-06T12:00:01.000000000Z\",\"check\":\"rate.limit\",\"decisionId\":\"d-unenforced\",\"kind\":\"record\",\"outcome\":\"unenforced\",\"point\":\"gate-b\",\"reason\":\"observed only\",\"v\":1}\n",
	"{\"level\":\"INFO\",\"msg\":\"decision summary\",\"counts\":[{\"n\":3,\"outcome\":\"accepted\"},{\"check\":\"approval.expired\",\"n\":2,\"outcome\":\"refused\"},{\"check\":\"rate.limit\",\"n\":1,\"outcome\":\"unenforced\"}],\"from\":\"2026-11-06T12:00:00.000000000Z\",\"kind\":\"summary\",\"point\":\"gate-a\",\"until\":\"2026-11-06T12:01:00.000000000Z\",\"v\":1}\n",
}

// goldenLogValuesV1 are the same entries as a valueHandler keeps them: the
// level, the message and each attribute's key, kind and Go value, as 0.4.0
// hands them.
var goldenLogValuesV1 = []string{
	"INFO \"decision record\" at=String:string(\"2026-11-06T12:00:00.000000000Z\") decisionId=String:string(\"d-accepted\") kind=String:string(\"record\") outcome=String:string(\"accepted\") point=String:string(\"gate-a\") v=Int64:int64(1)",
	"INFO \"decision record\" actors=Any:[]any{string(\"did:dplaax:poc.dplaax.dev:org:acme\"),string(\"did:dplaax:poc.dplaax.dev:org:other\")} at=String:string(\"2026-11-06T12:00:00.123456789Z\") attributes=Any:map[string]any{\"a b\":string(\"c\\\"d\"),\"op\":string(\"transfer\"),\"zone\":string(\"eu�\")} check=String:string(\"approval.expired\") decisionId=String:string(\"d-refused\") evidence=Any:[]any{map[string]any{\"address\":string(\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"),\"role\":string(\"approval\")},map[string]any{\"address\":string(\"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"),\"role\":string(\"chain\")}} kind=String:string(\"record\") outcome=String:string(\"refused\") point=String:string(\"gate-a\") reason=String:string(\"line one\\nline two\\u2028and �, tab\\there, ctl\\x01, back\\\\slash, <tag> & amp\") v=Int64:int64(1)",
	"INFO \"decision record\" at=String:string(\"2026-11-06T12:00:01.000000000Z\") check=String:string(\"rate.limit\") decisionId=String:string(\"d-unenforced\") kind=String:string(\"record\") outcome=String:string(\"unenforced\") point=String:string(\"gate-b\") reason=String:string(\"observed only\") v=Int64:int64(1)",
	"INFO \"decision summary\" counts=Any:[]any{map[string]any{\"n\":int64(3),\"outcome\":string(\"accepted\")},map[string]any{\"check\":string(\"approval.expired\"),\"n\":int64(2),\"outcome\":string(\"refused\")},map[string]any{\"check\":string(\"rate.limit\"),\"n\":int64(1),\"outcome\":string(\"unenforced\")}} from=String:string(\"2026-11-06T12:00:00.000000000Z\") kind=String:string(\"summary\") point=String:string(\"gate-a\") until=String:string(\"2026-11-06T12:01:00.000000000Z\") v=Int64:int64(1)",
}

// A format v1 sink writes what 0.4.0 writes: NewJSONLines its lines, byte for
// byte; NewLog the level, message and attributes of its entries, each
// attribute's key, kind and Go value in order.
func TestFormatV1_IsWhat040Writes(t *testing.T) {
	jsonLines, logLines, logValues := writeGolden(t)
	if want := strings.Join(goldenJSONLinesV1, ""); jsonLines != want {
		t.Errorf("NewJSONLines wrote\n%s\nwant\n%s", jsonLines, want)
	}
	if want := strings.Join(goldenLogV1, ""); logLines != want {
		t.Errorf("NewLog handed JSONHandler\n%s\nwant\n%s", logLines, want)
	}
	if got, want := strings.Join(logValues, "\n"), strings.Join(goldenLogValuesV1, "\n"); got != want {
		t.Errorf("NewLog handed\n%s\nwant\n%s", got, want)
	}
}
