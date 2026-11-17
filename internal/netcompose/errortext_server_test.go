package netcompose

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/structpb"

	didpb "github.com/provin-line/oss/gen/go/dplaax/did/v1"
	"github.com/provin-line/oss/gen/go/dplaax/did/v1/didpbconnect"
	"github.com/provin-line/oss/internal/netexcerpt"
)

// serverErrorText is the text a caller receives in place of a server error's
// own; its group is the ref the server's log records the error under.
var serverErrorText = regexp.MustCompile(`^server error \(ref ([0-9a-f]{16})\); the server's log has the details$`)

// logBuffer is a bytes.Buffer safe for concurrent use.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// entry returns the JSON log entry whose ref is ref, or nil.
func (b *logBuffer) entry(t *testing.T, ref string) map[string]any {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	sc := bufio.NewScanner(bytes.NewReader(b.buf.Bytes()))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var e map[string]any
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("log line %q: %v", sc.Text(), err)
		}
		if e["ref"] == ref {
			return e
		}
	}
	return nil
}

func newLog() (*slog.Logger, *logBuffer) {
	buf := &logBuffer{}
	return slog.New(slog.NewJSONHandler(buf, nil)), buf
}

// secret is a server's own text that must not reach the caller.
const secret = "yamlstore: read: open /var/lib/provin/dids/org/acme.yaml: file name too long"

// A server error — the code Internal, Unknown or DataLoss — reaches the caller
// as a fixed text naming a ref, with its code and details, in each protocol
// and from a unary and a streaming RPC. The server's log records the error's
// own text under that ref, with the procedure, the code and the peer.
func TestErrorText_AnswersAServerErrorWithAFixedText(t *testing.T) {
	detailed := func(ce *connect.Error) *connect.Error {
		d, err := connect.NewErrorDetail(structpb.NewStringValue("kept"))
		if err != nil {
			t.Fatal(err)
		}
		ce.AddDetail(d)
		return ce
	}
	cases := []errorCase{
		{"internal", func() error {
			ce := detailed(connect.NewError(connect.CodeInternal, errors.New(secret)))
			ce.Meta().Set("X-Kept", "yes")
			return ce
		}, connect.CodeInternal},
		{"wrapped internal", func() error {
			return fmt.Errorf("lookup: %w", connect.NewError(connect.CodeInternal, errors.New(secret)))
		}, connect.CodeInternal},
		{"internal wire error", func() error {
			ce := connect.NewWireError(connect.CodeInternal, errors.New(secret))
			ce.Meta().Set("X-Kept", "yes")
			return ce
		}, connect.CodeInternal},
		{"unknown", func() error { return connect.NewError(connect.CodeUnknown, errors.New(secret)) }, connect.CodeUnknown},
		{"plain error", func() error { return errors.New(secret) }, connect.CodeUnknown},
		{"typed nil and a sibling", func() error {
			return errors.Join((*connect.Error)(nil), errors.New(secret))
		}, connect.CodeUnknown},
		{"data loss", func() error { return connect.NewError(connect.CodeDataLoss, errors.New(secret)) }, connect.CodeDataLoss},
		{"internal holding a not-found", func() error {
			return connect.NewError(connect.CodeInternal, fmt.Errorf("%s: %w", secret, connect.NewError(connect.CodeNotFound, errors.New("no such head"))))
		}, connect.CodeInternal},
	}
	var failure func() error
	log, logged := newLog()
	srv := echoServer(t, &failure, errorText(log))
	for _, c := range cases {
		failure = c.err
		for _, pr := range protocols {
			gotU, gotS := received(t, srv, pr.opts)
			for _, r := range []struct {
				rpc, procedure string
				got            error
			}{{"unary", "/test.v1.Echo/Unary", gotU}, {"stream", "/test.v1.Echo/Stream", gotS}} {
				what := c.name + " " + pr.name + " " + r.rpc
				var ce *connect.Error
				if !errors.As(r.got, &ce) {
					t.Fatalf("%s: %v, want a connect error", what, r.got)
				}
				if ce.Code() != c.code {
					t.Errorf("%s: code %v, want %v", what, ce.Code(), c.code)
				}
				m := serverErrorText.FindStringSubmatch(ce.Message())
				if m == nil {
					t.Errorf("%s: text %.120q, want the fixed text", what, ce.Message())
					continue
				}
				if c.name == "internal" && len(ce.Details()) != 1 {
					t.Errorf("%s: %d details, want 1", what, len(ce.Details()))
				}
				if w := map[string]string{"internal": "yes", "internal wire error": ""}; w[c.name] != ce.Meta().Get("X-Kept") {
					if _, checked := w[c.name]; checked {
						t.Errorf("%s: metadata X-Kept %q, want %q", what, ce.Meta().Get("X-Kept"), w[c.name])
					}
				}
				e := logged.entry(t, m[1])
				if e == nil {
					t.Errorf("%s: no log entry for ref %s", what, m[1])
					continue
				}
				if peer, _ := e["peer"].(string); e["level"] != "ERROR" || e["procedure"] != r.procedure || e["code"] != c.code.String() || peer == "" {
					t.Errorf("%s: log entry %v, want level ERROR, procedure %s, code %v and the peer", what, e, r.procedure, c.code)
				}
				if text, _ := e["err"].(string); !strings.Contains(text, secret) {
					t.Errorf("%s: log entry err %q, want the error's own text", what, text)
				}
			}
		}
	}
}

// The log records a server error's text within netexcerpt.TextLimit bytes, as
// the network writes every text it names: its head and its length.
func TestErrorText_LogsAServerErrorWithinTheLimit(t *testing.T) {
	long := secret + strings.Repeat("a", 200<<10)
	failure := func() error { return connect.NewError(connect.CodeInternal, errors.New(long)) }
	log, logged := newLog()
	srv := echoServer(t, &failure, errorText(log))
	got, _ := received(t, srv, nil)
	var ce *connect.Error
	if !errors.As(got, &ce) {
		t.Fatalf("%.120v: want a connect error", got)
	}
	m := serverErrorText.FindStringSubmatch(ce.Message())
	if m == nil {
		t.Fatalf("%.120v: want the fixed text", got)
	}
	e := logged.entry(t, m[1])
	if e == nil {
		t.Fatalf("no log entry for ref %s", m[1])
	}
	text, _ := e["err"].(string)
	whole := len(failure().Error())
	if len(text) > netexcerpt.TextLimit || !strings.Contains(text, fmt.Sprintf("(%d bytes)", whole)) {
		t.Errorf("log entry err has %d bytes, ending %q; want at most %d, naming the length %d", len(text), text[max(0, len(text)-40):], netexcerpt.TextLimit, whole)
	}
}

// Each server error gets its own ref.
func TestErrorText_GivesEachServerErrorItsOwnRef(t *testing.T) {
	failure := func() error { return connect.NewError(connect.CodeInternal, errors.New(secret)) }
	log, _ := newLog()
	srv := echoServer(t, &failure, errorText(log))
	seen := map[string]bool{}
	for i := 0; i < 8; i++ {
		got, _ := received(t, srv, nil)
		var ce *connect.Error
		if !errors.As(got, &ce) {
			t.Fatalf("%v: want a connect error", got)
		}
		m := serverErrorText.FindStringSubmatch(ce.Message())
		if m == nil {
			t.Fatalf("text %.120q, want the fixed text", ce.Message())
		}
		if seen[m[1]] {
			t.Fatalf("ref %s answered twice", m[1])
		}
		seen[m[1]] = true
	}
}

// A store failure the node answers with Internal — here a DID whose account
// ID is too long for a file name — reaches the caller with the fixed text, not
// the store's path in the data directory.
func TestBuildHandler_AnswersAStoreFailureWithAFixedText(t *testing.T) {
	srv, _ := http2Assembled(t)
	dids := didpbconnect.NewDIDServiceClient(srv.Client(), srv.URL)
	_, err := dids.ResolveDID(context.Background(), bearer(connect.NewRequest(&didpb.ResolveDIDRequest{Did: "did:dplaax:" + registryID + ":org:" + strings.Repeat("a", 64<<10)})))
	var ce *connect.Error
	if !errors.As(err, &ce) {
		t.Fatalf("%.200v: want a connect error", err)
	}
	if ce.Code() != connect.CodeInternal || !serverErrorText.MatchString(ce.Message()) {
		t.Errorf("code %v, text %.200q; want Internal with the fixed text", ce.Code(), ce.Message())
	}
}

// fixedMessage shows a fixed text and holds its cause, as the L1
// authorization interceptor answers an authorization check that failed.
type fixedMessage struct {
	msg string
	err error
}

func (m *fixedMessage) Error() string { return m.msg }
func (m *fixedMessage) Unwrap() error { return m.err }

// A server error whose text hides its cause behind Unwrap has the cause
// logged under its ref too, so the ref leads to it.
func TestErrorText_LogsTheCauseAServerErrorHides(t *testing.T) {
	failure := func() error {
		return connect.NewError(connect.CodeInternal, &fixedMessage{msg: "authorization check failed", err: errors.New(secret)})
	}
	log, logged := newLog()
	srv := echoServer(t, &failure, errorText(log))
	got, _ := received(t, srv, nil)
	var ce *connect.Error
	if !errors.As(got, &ce) {
		t.Fatalf("%v: want a connect error", got)
	}
	m := serverErrorText.FindStringSubmatch(ce.Message())
	if m == nil {
		t.Fatalf("text %.120q, want the fixed text", ce.Message())
	}
	e := logged.entry(t, m[1])
	if e == nil {
		t.Fatalf("no log entry for ref %s", m[1])
	}
	if cause, _ := e["cause"].(string); !strings.Contains(cause, secret) {
		t.Errorf("log entry %v, want the hidden cause %q", e, secret)
	}
}

// A handler's error that carries no connect error is the node's own text,
// whatever code connect gives it: its caller receives the code connect
// would answer (Canceled for a cancellation or a client that went away,
// DeadlineExceeded for a deadline) with the fixed text, in each protocol and
// from a unary and a streaming RPC, and the log records it under the ref, at
// level WARN for those two codes.
func TestErrorText_AnswersAnUncodedErrorWithConnectsCodeAndTheFixedText(t *testing.T) {
	for _, c := range []errorCase{
		{"cancellation", func() error { return fmt.Errorf("%s: %w", secret, context.Canceled) }, connect.CodeCanceled},
		{"deadline", func() error { return fmt.Errorf("%s: %w", secret, context.DeadlineExceeded) }, connect.CodeDeadlineExceeded},
		{"os deadline", func() error { return fmt.Errorf("%s: %w", secret, os.ErrDeadlineExceeded) }, connect.CodeDeadlineExceeded},
		{"connection reset", func() error { return fmt.Errorf("dial 10.0.0.5: %s: %w", secret, syscall.ECONNRESET) }, connect.CodeCanceled},
		{"broken pipe", func() error { return fmt.Errorf("%s: %w", secret, syscall.EPIPE) }, connect.CodeCanceled},
		{"client disconnected", func() error { return errors.New("client disconnected") }, connect.CodeCanceled},
		{"stream closed", func() error { return errors.New("http2: stream closed") }, connect.CodeCanceled},
	} {
		failure := c.err
		log, logged := newLog()
		srv := echoServer(t, &failure, errorText(log))
		plain := echoServer(t, &failure, connect.WithHandlerOptions())
		for _, pr := range protocols {
			wantU, wantS := received(t, plain, pr.opts)
			gotU, gotS := received(t, srv, pr.opts)
			for _, r := range []struct {
				rpc       string
				want, got error
			}{{"unary", wantU, gotU}, {"stream", wantS, gotS}} {
				what := c.name + " " + pr.name + " " + r.rpc
				if w := connect.CodeOf(r.want); w != c.code || connect.CodeOf(r.got) != w {
					t.Errorf("%s: code %v (%v without errorText), want %v", what, connect.CodeOf(r.got), w, c.code)
				}
				var ce *connect.Error
				if !errors.As(r.got, &ce) {
					t.Fatalf("%s: %v, want a connect error", what, r.got)
				}
				m := serverErrorText.FindStringSubmatch(ce.Message())
				if m == nil {
					t.Errorf("%s: text %.120q, want the fixed text", what, ce.Message())
					continue
				}
				if e := logged.entry(t, m[1]); e == nil || e["level"] != "WARN" {
					t.Errorf("%s: log entry %v, want one at level WARN", what, e)
				}
			}
		}
	}
}

// A code outside connect's own is a server error too: its caller gets the
// fixed text.
func TestErrorText_AnswersACodeOutsideConnectsAsAServerError(t *testing.T) {
	failure := func() error { return connect.NewError(connect.Code(99), errors.New(secret)) }
	srv := echoServer(t, &failure, errorText(nil))
	for _, pr := range protocols {
		gotU, gotS := received(t, srv, pr.opts)
		for _, got := range []error{gotU, gotS} {
			var ce *connect.Error
			if !errors.As(got, &ce) || !serverErrorText.MatchString(ce.Message()) {
				t.Errorf("%s: %.200v, want the fixed text", pr.name, got)
			}
		}
	}
}

// incomparable is an error whose value == cannot compare.
type incomparable struct{ parts []string }

func (e incomparable) Error() string { return strings.Join(e.parts, ", ") }

// A server error whose value cannot be compared is answered and logged.
func TestErrorText_AnswersAServerErrorThatDoesNotCompare(t *testing.T) {
	failure := func() error { return incomparable{parts: []string{secret}} }
	log, logged := newLog()
	srv := echoServer(t, &failure, errorText(log))
	got, _ := received(t, srv, nil)
	var ce *connect.Error
	if !errors.As(got, &ce) {
		t.Fatalf("%v: want a connect error", got)
	}
	m := serverErrorText.FindStringSubmatch(ce.Message())
	if m == nil || logged.entry(t, m[1]) == nil {
		t.Errorf("text %.120q: want the fixed text and its log entry", ce.Message())
	}
}
