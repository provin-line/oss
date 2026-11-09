package netcompose

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/provin-line/oss/internal/netexcerpt"
)

// Each case is an error a handler returns and the code its caller receives.
type errorCase struct {
	name string
	err  func() error
	code connect.Code
}

func longConnectError(code connect.Code) *connect.Error {
	ce := connect.NewError(code, errors.New("bad "+strings.Repeat("é", 100<<10)))
	detail, err := connect.NewErrorDetail(structpb.NewStringValue("kept"))
	if err != nil {
		panic(err)
	}
	ce.AddDetail(detail)
	ce.Meta().Set("X-Kept", "yes")
	return ce
}

var errorCases = []errorCase{
	{"connect error", func() error { return longConnectError(connect.CodeFailedPrecondition) }, connect.CodeFailedPrecondition},
	{"wire error", func() error {
		ce := longConnectError(connect.CodeUnavailable)
		wire := connect.NewWireError(ce.Code(), errors.New(ce.Message()))
		wire.AddDetail(ce.Details()[0])
		wire.Meta().Set("X-Kept", "yes")
		return wire
	}, connect.CodeUnavailable},
	{"wrapped connect error", func() error {
		return fmt.Errorf("outer %s: %w", strings.Repeat("o", 10<<10), longConnectError(connect.CodeNotFound))
	}, connect.CodeNotFound},
	{"plain error", func() error { return errors.New(strings.Repeat("p", 200<<10)) }, connect.CodeUnknown},
	{"cancellation", func() error { return fmt.Errorf("%s: %w", strings.Repeat("c", 200<<10), context.Canceled) }, connect.CodeCanceled},
	{"typed nil and a long sibling", func() error {
		return errors.Join((*connect.Error)(nil), errors.New(strings.Repeat("n", 200<<10)))
	}, connect.CodeUnknown},
}

// A text that is not UTF-8 reaches the caller as UTF-8 within
// netexcerpt.TextLimit bytes, with its code and details, short or long.
// Without errorText it does not always: the Connect protocol replaces its bytes
// on the wire, and gRPC, which cannot marshal it beside details, answers
// internal instead.
func TestErrorText_RepairsATextThatIsNotUTF8(t *testing.T) {
	var failure func() error
	bounded := echoServer(t, &failure, errorText())
	for _, text := range []string{"bad \xff", "bad " + strings.Repeat("é\xff", 100<<10)} {
		failure = func() error {
			ce := longConnectError(connect.CodeFailedPrecondition)
			out := connect.NewError(ce.Code(), errors.New(text))
			out.AddDetail(ce.Details()[0])
			return out
		}
		for _, pr := range protocols {
			gotU, gotS := received(t, bounded, pr.opts)
			for _, got := range []error{gotU, gotS} {
				what := fmt.Sprintf("%s %.10q", pr.name, text)
				if code := requireBoundedText(t, what, got); code != connect.CodeFailedPrecondition {
					t.Errorf("%s: code %v, want %v", what, code, connect.CodeFailedPrecondition)
				}
				var ce *connect.Error
				if errors.As(got, &ce) && len(ce.Details()) != 1 {
					t.Errorf("%s: %d details, want 1", what, len(ce.Details()))
				}
			}
		}
	}
}

// echoServer serves, with option, a unary RPC that returns failure's error
// and a server-streaming one that sends one message and then returns it.
func echoServer(t *testing.T, failure *func() error, option connect.HandlerOption) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle("/test.v1.Echo/Unary", connect.NewUnaryHandler("/test.v1.Echo/Unary",
		func(_ context.Context, _ *connect.Request[structpb.Struct]) (*connect.Response[structpb.Struct], error) {
			return nil, (*failure)()
		}, option))
	mux.Handle("/test.v1.Echo/Stream", connect.NewServerStreamHandler("/test.v1.Echo/Stream",
		func(_ context.Context, _ *connect.Request[structpb.Struct], s *connect.ServerStream[structpb.Struct]) error {
			if err := s.Send(&structpb.Struct{}); err != nil {
				return err
			}
			return (*failure)()
		}, option))
	srv := httptest.NewUnstartedServer(mux)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// received calls the unary and the streaming RPC of srv and returns the errors
// their caller receives.
func received(t *testing.T, srv *httptest.Server, opts []connect.ClientOption) (unary, stream error) {
	t.Helper()
	ctx := context.Background()
	u := connect.NewClient[structpb.Struct, structpb.Struct](srv.Client(), srv.URL+"/test.v1.Echo/Unary", opts...)
	_, unary = u.CallUnary(ctx, connect.NewRequest(&structpb.Struct{}))
	s := connect.NewClient[structpb.Struct, structpb.Struct](srv.Client(), srv.URL+"/test.v1.Echo/Stream", opts...)
	st, err := s.CallServerStream(ctx, connect.NewRequest(&structpb.Struct{}))
	if err != nil {
		return unary, err
	}
	for st.Receive() {
	}
	_ = st.Close()
	return unary, st.Err()
}

// The caller of a handler mounted with errorText receives, for each error
// below, in each protocol and from a unary and a streaming RPC, the code it
// would receive without it and a text of UTF-8 within netexcerpt.TextLimit
// bytes: the head of the text and the length of the text it replaces. The
// details of a connect error reach it, and the metadata of one that is not a
// wire error, as they would without errorText.
func TestErrorText_BoundsWhatTheCallerReceives(t *testing.T) {
	var failure func() error
	bounded := echoServer(t, &failure, errorText())
	plain := echoServer(t, &failure, connect.WithHandlerOptions())
	for _, c := range errorCases {
		failure = c.err
		for _, pr := range protocols {
			wantU, wantS := received(t, plain, pr.opts)
			gotU, gotS := received(t, bounded, pr.opts)
			for _, r := range []struct {
				rpc       string
				want, got error
			}{{"unary", wantU, gotU}, {"stream", wantS, gotS}} {
				what := c.name + " " + pr.name + " " + r.rpc
				var want, got *connect.Error
				if !errors.As(r.want, &want) || !errors.As(r.got, &got) {
					t.Fatalf("%s: want %v, got %v", what, r.want, r.got)
				}
				if got.Code() != c.code || want.Code() != c.code {
					t.Errorf("%s: code %v (%v without errorText), want %v", what, got.Code(), want.Code(), c.code)
				}
				msg := got.Message()
				if len(msg) > netexcerpt.TextLimit || !utf8.ValidString(msg) {
					t.Errorf("%s: %d bytes of text (UTF-8: %v)", what, len(msg), utf8.ValidString(msg))
				}
				if tail := fmt.Sprintf("… (%d bytes)", len(want.Message())); !strings.HasSuffix(msg, tail) {
					t.Errorf("%s: text %.80q… does not end in %q", what, msg, tail)
				}
				if !sameDetails(want, got) {
					t.Errorf("%s: details %v, want %v", what, got.Details(), want.Details())
				}
				if g, w := got.Meta().Get("X-Kept"), want.Meta().Get("X-Kept"); g != w {
					t.Errorf("%s: metadata X-Kept %q, want %q", what, g, w)
				}
			}
		}
	}
}

func sameDetails(a, b *connect.Error) bool {
	if len(a.Details()) != len(b.Details()) {
		return false
	}
	for i := range a.Details() {
		va, ea := a.Details()[i].Value()
		vb, eb := b.Details()[i].Value()
		if ea != nil || eb != nil || !proto.Equal(va, vb) {
			return false
		}
	}
	return true
}

// An error whose text already fits is returned as it is; one that does not
// still holds, for errors.Is and errors.As, every error it held: the joined
// sentinel and the connect error.
func TestBoundError_KeepsWhatTheErrorHolds(t *testing.T) {
	short := connect.NewError(connect.CodeNotFound, errors.New("no such head"))
	if got := boundError(short); got != error(short) {
		t.Errorf("boundError(short) = %v, want the error itself", got)
	}
	plain := errors.New("short")
	if got := boundError(plain); got != plain {
		t.Errorf("boundError(plain) = %v, want the error itself", got)
	}
	if boundError(nil) != nil {
		t.Error("boundError(nil) is not nil")
	}
	sentinel := errors.New("sentinel")
	long := longConnectError(connect.CodeAborted)
	got := boundError(errors.Join(long, sentinel))
	if !errors.Is(got, sentinel) {
		t.Error("the joined sentinel is lost")
	}
	var ce *connect.Error
	if !errors.As(got, &ce) || ce.Code() != connect.CodeAborted || len(ce.Message()) > netexcerpt.TextLimit {
		t.Errorf("boundError = %v", got)
	}
	if !errors.Is(got, long) {
		t.Error("the connect error is lost")
	}
}

type panickingError struct{}

func (panickingError) Error() string { panic("boom") }

type nilPointerError struct{ text string }

func (e *nilPointerError) Error() string { return e.text }

// selfPanickingError panics with itself, a value fmt cannot write either.
type selfPanickingError struct{}

func (e selfPanickingError) Error() string { panic(e) }

// A connect error that holds an error whose Error method panics, whatever it
// panics with, or which is a nil pointer, is returned as a connect error of
// the same code whose message is UTF-8 within netexcerpt.TextLimit bytes:
// neither boundError nor that message panics, and errors.Is still finds the
// connect error.
func TestBoundError_AConnectErrorWhoseInnerTextPanics(t *testing.T) {
	for _, c := range []struct {
		name  string
		inner error
		want  string // "" when only the bound is checked
	}{
		{"panics", panickingError{}, fmt.Sprint(panickingError{})},
		{"nil pointer", (*nilPointerError)(nil), "<nil>"},
		{"panics with a value fmt cannot write", selfPanickingError{}, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			ce := connect.NewError(connect.CodeFailedPrecondition, c.inner)
			var got error
			var message, text string
			done := false
			func() {
				defer func() {
					r := recover()
					if !done {
						t.Fatalf("panicked: %T", r)
					}
				}()
				got = boundError(ce)
				var out *connect.Error
				if errors.As(got, &out) {
					message = out.Message()
				}
				text = got.Error()
				done = true
			}()
			var out *connect.Error
			if !errors.As(got, &out) {
				t.Fatalf("boundError = %T, want a connect error", got)
			}
			if connect.CodeOf(got) != connect.CodeFailedPrecondition {
				t.Errorf("code %v, want %v", connect.CodeOf(got), connect.CodeFailedPrecondition)
			}
			if len(message) > netexcerpt.TextLimit || !utf8.ValidString(message) || message == "" {
				t.Errorf("message: %d bytes (UTF-8: %v): %.80q", len(message), utf8.ValidString(message), message)
			}
			if c.want != "" && message != c.want {
				t.Errorf("message = %q, want %q", message, c.want)
			}
			if !strings.Contains(text, message) {
				t.Errorf("text %q does not hold the message %q", text, message)
			}
			if !errors.Is(got, ce) {
				t.Error("errors.Is does not find the connect error")
			}
		})
	}
}

// panickingWrapper holds a connect error and panics when asked its own text.
type panickingWrapper struct{ err error }

func (w panickingWrapper) Error() string { panic("boom") }
func (w panickingWrapper) Unwrap() error { return w.err }

// connect writes an error by asking first the text of the whole error it is
// given, then the message of the connect error in it. A connect error that
// fits, held by an error whose own text panics (joined with a nil pointer, or
// in a wrapper that panics), is returned as a new connect error of the same
// code and message, whose text does not panic; errors.Is still finds what it
// held.
func TestBoundError_AConnectErrorHeldByAnErrorWhoseTextPanics(t *testing.T) {
	joined := connect.NewError(connect.CodeNotFound, errors.New("no such head"))
	wrapped := connect.NewError(connect.CodeAborted, errors.New("conflict"))
	for _, c := range []struct {
		name string
		ce   *connect.Error
		err  error
	}{
		{"joined with a nil pointer", joined, errors.Join(joined, (*nilPointerError)(nil))},
		{"in a wrapper that panics", wrapped, panickingWrapper{wrapped}},
	} {
		t.Run(c.name, func(t *testing.T) {
			var got error
			var text string
			done := false
			func() {
				defer func() {
					r := recover()
					if !done {
						t.Fatalf("panicked: %T", r)
					}
				}()
				got = boundError(c.err)
				text = got.Error()
				done = true
			}()
			var out *connect.Error
			if !errors.As(got, &out) || out.Code() != c.ce.Code() || out.Message() != c.ce.Message() {
				t.Fatalf("boundError = %q, want a connect error of code %v and message %q", text, c.ce.Code(), c.ce.Message())
			}
			if !errors.Is(got, c.ce) {
				t.Error("errors.Is does not find the connect error")
			}
		})
	}
}

// canceledPanics holds a context's cancellation and panics when asked its
// own text.
type canceledPanics struct{}

func (canceledPanics) Error() string { panic("boom") }
func (canceledPanics) Unwrap() error { return context.Canceled }

// A handler's error whose Error method panics, in a connect error, holding
// one or beside one, is answered in each protocol and from a unary and a
// streaming RPC, with the code and the message below, instead of failing the
// answer.
func TestErrorText_AnswersAnErrorWhoseTextPanics(t *testing.T) {
	fits := func(code connect.Code) *connect.Error { return connect.NewError(code, errors.New("no such head")) }
	for _, c := range []struct {
		name    string
		err     func() error
		code    connect.Code
		message string // "" when only the bound is checked
	}{
		{"connect error holding a panicking error", func() error { return connect.NewError(connect.CodeFailedPrecondition, panickingError{}) },
			connect.CodeFailedPrecondition, fmt.Sprint(panickingError{})},
		{"connect error holding a nil pointer", func() error { return connect.NewError(connect.CodeFailedPrecondition, (*nilPointerError)(nil)) },
			connect.CodeFailedPrecondition, "<nil>"},
		{"connect error holding an error fmt cannot write", func() error { return connect.NewError(connect.CodeAborted, selfPanickingError{}) },
			connect.CodeAborted, "%!v(PANIC=Error method of netcompose.selfPanickingError)"},
		{"connect error joined with a nil pointer", func() error { return errors.Join(fits(connect.CodeNotFound), (*nilPointerError)(nil)) },
			connect.CodeNotFound, "no such head"},
		{"connect error in a wrapper that panics", func() error { return panickingWrapper{fits(connect.CodeAborted)} },
			connect.CodeAborted, "no such head"},
		{"panicking error", func() error { return panickingError{} }, connect.CodeUnknown, fmt.Sprint(panickingError{})},
		{"cancellation in a wrapper that panics", func() error { return canceledPanics{} }, connect.CodeCanceled, fmt.Sprint(canceledPanics{})},
	} {
		failure := c.err
		bounded := echoServer(t, &failure, errorText())
		for _, pr := range protocols {
			gotU, gotS := received(t, bounded, pr.opts)
			for _, r := range []struct {
				rpc string
				got error
			}{{"unary", gotU}, {"stream", gotS}} {
				what := c.name + " " + pr.name + " " + r.rpc
				var got *connect.Error
				if !errors.As(r.got, &got) {
					t.Fatalf("%s: got %v, want a connect error", what, r.got)
				}
				if got.Code() != c.code {
					t.Errorf("%s: code %v, want %v", what, got.Code(), c.code)
				}
				if msg := got.Message(); len(msg) > netexcerpt.TextLimit || !utf8.ValidString(msg) || c.message != "" && msg != c.message {
					t.Errorf("%s: message %.80q, want %q", what, msg, c.message)
				}
			}
		}
	}
}

// A connect error whose message fits, held by another error or not, is
// answered as it is without errorText: the same code, message, details and
// metadata, in each protocol and from a unary and a streaming RPC.
func TestErrorText_AnswersAConnectErrorThatFitsAsWithoutIt(t *testing.T) {
	withDetail := func(ce *connect.Error) *connect.Error {
		detail, err := connect.NewErrorDetail(structpb.NewStringValue("kept"))
		if err != nil {
			panic(err)
		}
		ce.AddDetail(detail)
		ce.Meta().Set("X-Kept", "yes")
		return ce
	}
	for _, c := range []struct {
		name string
		err  func() error
	}{
		{"connect error", func() error { return withDetail(connect.NewError(connect.CodeNotFound, errors.New("no such head"))) }},
		{"wrapped connect error", func() error {
			return fmt.Errorf("lookup: %w", withDetail(connect.NewError(connect.CodeNotFound, errors.New("no such head"))))
		}},
		{"wrapped wire error", func() error {
			return fmt.Errorf("peer: %w", withDetail(connect.NewWireError(connect.CodeUnavailable, errors.New("busy"))))
		}},
		{"wrapped connect error holding no error", func() error {
			return fmt.Errorf("lookup: %w", withDetail(connect.NewError(connect.CodePermissionDenied, nil)))
		}},
		{"connect error holding a connect error", func() error {
			return connect.NewError(connect.CodeInternal, withDetail(connect.NewError(connect.CodeNotFound, errors.New("no such head"))))
		}},
	} {
		failure := c.err
		bounded := echoServer(t, &failure, errorText())
		plain := echoServer(t, &failure, connect.WithHandlerOptions())
		for _, pr := range protocols {
			wantU, wantS := received(t, plain, pr.opts)
			gotU, gotS := received(t, bounded, pr.opts)
			for _, r := range []struct {
				rpc       string
				want, got error
			}{{"unary", wantU, gotU}, {"stream", wantS, gotS}} {
				what := c.name + " " + pr.name + " " + r.rpc
				var want, got *connect.Error
				if !errors.As(r.want, &want) || !errors.As(r.got, &got) {
					t.Fatalf("%s: want %v, got %v", what, r.want, r.got)
				}
				if got.Code() != want.Code() || got.Message() != want.Message() {
					t.Errorf("%s: %v %q, want %v %q", what, got.Code(), got.Message(), want.Code(), want.Message())
				}
				if !sameDetails(want, got) {
					t.Errorf("%s: details %v, want %v", what, got.Details(), want.Details())
				}
				if g, w := got.Meta().Get("X-Kept"), want.Meta().Get("X-Kept"); g != w {
					t.Errorf("%s: metadata X-Kept %q, want %q", what, g, w)
				}
			}
		}
	}
}

// boundError reads a connect error whose message fits without writing into
// it: a handler may return one such error, held by another, from many
// requests at once.
func TestBoundError_ReadsAConnectErrorThatFitsWithoutWritingIntoIt(t *testing.T) {
	shared := connect.NewError(connect.CodeNotFound, errors.New("no such head"))
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				_ = boundError(fmt.Errorf("lookup: %w", shared))
			}
		}()
	}
	wg.Wait()
}

// sliceError is an error of a type == cannot compare.
type sliceError struct{ parts []string }

func (e sliceError) Error() string { return strings.Join(e.parts, ", ") }

// anyError is of a type == compares, holding a value it cannot.
type anyError struct{ value any }

func (e anyError) Error() string { return fmt.Sprint(e.value) }

// A connect error whose message fits is returned as it is, whatever the type
// of the error it holds, also one == cannot compare.
func TestBoundError_AConnectErrorThatFitsHoldingAnErrorThatDoesNotCompare(t *testing.T) {
	for name, inner := range map[string]error{
		"a type that does not compare":  sliceError{[]string{"a", "b"}},
		"a value that does not compare": anyError{[]int{1, 2}},
	} {
		t.Run(name, func(t *testing.T) {
			ce := connect.NewError(connect.CodeNotFound, inner)
			var got error
			done := false
			func() {
				defer func() {
					r := recover()
					if !done {
						t.Fatalf("panicked: %v", r)
					}
				}()
				got = boundError(ce)
				done = true
			}()
			if got != error(ce) {
				t.Errorf("boundError = %v, want the connect error itself", got)
			}
		})
	}
}

// Whatever the text and the code of a connect error, or the text of an error
// that is not one, boundError returns one whose text is UTF-8 within
// netexcerpt.TextLimit bytes, with the same code.
func FuzzBoundError(f *testing.F) {
	for _, s := range []string{"", "a", strings.Repeat("é", 2000), "\xff\xfe", strings.Repeat("x", netexcerpt.TextLimit), strings.Repeat("x", netexcerpt.TextLimit+1)} {
		f.Add(s, uint8(3), true)
		f.Add(s, uint8(0), false)
	}
	f.Fuzz(func(t *testing.T, text string, code uint8, coded bool) {
		var err error = errors.New(text)
		want := connect.CodeUnknown
		if coded {
			want = connect.Code(code%16 + 1)
			err = connect.NewError(want, err)
		}
		got := boundError(err)
		var ce *connect.Error
		msg := got.Error()
		if errors.As(got, &ce) {
			msg = ce.Message()
		}
		if len(msg) > netexcerpt.TextLimit || !utf8.ValidString(msg) {
			t.Fatalf("boundError(%q) has %d bytes of text (UTF-8: %v)", text, len(msg), utf8.ValidString(msg))
		}
		if connect.CodeOf(got) != want {
			t.Fatalf("boundError(%q): code %v, want %v", text, connect.CodeOf(got), want)
		}
		if utf8.ValidString(text) && len(text) <= netexcerpt.TextLimit && got != err {
			t.Fatalf("boundError(%q) replaced an error that fits", text)
		}
	})
}

// codecCase is one request to the echo RPCs and how it is sent.
type codecCase struct {
	name, contentType, body string
}

var codecCases = []codecCase{
	{"empty object", "application/json", `{}`},
	{"struct", "application/json", `{"a":1.5,"b":[true,null,"s"],"c":{"d":-0}}`},
	{"charset", "application/json; charset=utf-8", `{"x":"é"}`},
	{"descriptor", "application/json", `{"name":"x.proto","package":"p","messageType":[{"name":"M","field":[{"name":"f","number":1,"label":"LABEL_OPTIONAL","type":"TYPE_INT64","jsonName":"f","defaultValue":"9007199254740993"}]}],"syntax":"proto3","unknownMember":{"a":1}}`},
	{"enum by number", "application/json", `{"messageType":[{"field":[{"label":1,"number":"7"}]}]}`},
	{"empty body", "application/json", ``},
	{"not JSON", "application/json", `{`},
	{"wrong type", "application/json", `{"name":5}`},
	{"trailing token", "application/json", `{} x`},
	{"int overflow", "application/json", `{"messageType":[{"field":[{"number":2147483648}]}]}`},
	{"duplicate field", "application/json", `{"name":"a","name":"b"}`},
	{"not UTF-8", "application/json", "{\"name\":\"\xff\"}"},
}

// codecServer serves, with option, unary echo RPCs of a Struct and of a
// FileDescriptorProto (also over GET) and a server-streaming echo of a Struct.
func codecServer(t *testing.T, option connect.HandlerOption) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	get := connect.WithIdempotency(connect.IdempotencyNoSideEffects)
	mux.Handle("/test.v1.Echo/Struct", connect.NewUnaryHandler("/test.v1.Echo/Struct",
		func(_ context.Context, r *connect.Request[structpb.Struct]) (*connect.Response[structpb.Struct], error) {
			return connect.NewResponse(r.Msg), nil
		}, option, get))
	mux.Handle("/test.v1.Echo/Descriptor", connect.NewUnaryHandler("/test.v1.Echo/Descriptor",
		func(_ context.Context, r *connect.Request[descriptorpb.FileDescriptorProto]) (*connect.Response[descriptorpb.FileDescriptorProto], error) {
			return connect.NewResponse(r.Msg), nil
		}, option, get))
	mux.Handle("/test.v1.Echo/Stream", connect.NewServerStreamHandler("/test.v1.Echo/Stream",
		func(_ context.Context, r *connect.Request[structpb.Struct], s *connect.ServerStream[structpb.Struct]) error {
			if err := s.Send(r.Msg); err != nil {
				return err
			}
			return s.Send(r.Msg)
		}, option))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// exchange sends one HTTP request and returns its status, content type and body.
func exchange(t *testing.T, srv *httptest.Server, method, path, contentType string, body []byte) string {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%d %s %q", res.StatusCode, res.Header.Get("Content-Type"), b)
}

func envelope(b []byte) []byte {
	out := make([]byte, 5, 5+len(b))
	binary.BigEndian.PutUint32(out[1:], uint32(len(b)))
	return append(out, b...)
}

// The JSON codec errorText registers answers each request as connect's own
// JSON codec does: a request that decodes gets the same bytes back, and one
// that does not gets the same answer, in the Connect protocol over POST and
// GET and in a stream. A change of connect's own codec shows here.
func TestErrorText_JSONCodecAnswersAsConnectsOwn(t *testing.T) {
	bounded := codecServer(t, errorText())
	plain := codecServer(t, connect.WithHandlerOptions())
	for _, c := range codecCases {
		for _, path := range []string{"/test.v1.Echo/Struct", "/test.v1.Echo/Descriptor"} {
			want := exchange(t, plain, http.MethodPost, path, c.contentType, []byte(c.body))
			if got := exchange(t, bounded, http.MethodPost, path, c.contentType, []byte(c.body)); got != want {
				t.Errorf("%s POST %s:\n got %s\nwant %s", c.name, path, got, want)
			}
			query := "?encoding=json&message=" + url.QueryEscape(c.body)
			want = exchange(t, plain, http.MethodGet, path+query, "", nil)
			if got := exchange(t, bounded, http.MethodGet, path+query, "", nil); got != want {
				t.Errorf("%s GET %s:\n got %s\nwant %s", c.name, path, got, want)
			}
		}
		want := exchange(t, plain, http.MethodPost, "/test.v1.Echo/Stream", "application/connect+json", envelope([]byte(c.body)))
		if got := exchange(t, bounded, http.MethodPost, "/test.v1.Echo/Stream", "application/connect+json", envelope([]byte(c.body))); got != want {
			t.Errorf("%s stream:\n got %s\nwant %s", c.name, got, want)
		}
	}
}

// A body that does not decode, however long its token, is answered with the
// code connect's own codec gives and a text within netexcerpt.TextLimit
// bytes, the words connect puts before the codec's error included.
func TestErrorText_JSONCodecBoundsItsError(t *testing.T) {
	bounded := codecServer(t, errorText())
	plain := codecServer(t, connect.WithHandlerOptions())
	for _, body := range []string{`{} "` + longToken + `"`, `{"name":` + strings.Repeat("9", 200<<10) + `}`} {
		u := connect.NewClient[rawRequest, descriptorpb.FileDescriptorProto](bounded.Client(), bounded.URL+"/test.v1.Echo/Descriptor", connect.WithCodec(rawJSONCodec{}))
		p := connect.NewClient[rawRequest, descriptorpb.FileDescriptorProto](plain.Client(), plain.URL+"/test.v1.Echo/Descriptor", connect.WithCodec(rawJSONCodec{}))
		raw := rawRequest(body)
		_, got := u.CallUnary(context.Background(), connect.NewRequest(&raw))
		_, want := p.CallUnary(context.Background(), connect.NewRequest(&raw))
		code := requireBoundedText(t, fmt.Sprintf("%.20s…", body), got)
		if code != connect.CodeOf(want) {
			t.Errorf("%.20s…: code %v, want %v", body, code, connect.CodeOf(want))
		}
	}
}

// A failing readiness check is logged on one line, its error quoted within
// netexcerpt.TextLimit bytes, however long or many-lined the error's text.
func TestReadyz_LogsAFailedCheckWithinTheLimit(t *testing.T) {
	var logs bytes.Buffer
	prev, flags := log.Writer(), log.Flags()
	log.SetOutput(&logs)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(prev); log.SetFlags(flags) })
	runReadyChecks(context.Background(), []ReadinessCheck{{
		Name:  "pdp",
		Check: func(context.Context) error { return errors.New(strings.Repeat("line\n", 200<<10)) },
	}})
	line := strings.TrimSuffix(logs.String(), "\n")
	if strings.Contains(line, "\n") {
		t.Errorf("the error broke the log line: %.200q", line)
	}
	if max := len("readyz: check pdp failed: ") + netexcerpt.TextLimit; len(line) > max {
		t.Errorf("log line of %d bytes, want at most %d", len(line), max)
	}
}
