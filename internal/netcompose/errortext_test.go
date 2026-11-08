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
