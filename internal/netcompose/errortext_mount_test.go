package netcompose

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/known/emptypb"

	chainpb "github.com/provin-line/oss/gen/go/dplaax/chain/v1"
	chainpbconnect "github.com/provin-line/oss/gen/go/dplaax/chain/v1/chainpbconnect"
	didpb "github.com/provin-line/oss/gen/go/dplaax/did/v1"
	didpbconnect "github.com/provin-line/oss/gen/go/dplaax/did/v1/didpbconnect"
	payloadpb "github.com/provin-line/oss/gen/go/dplaax/payload/v1"
	payloadpbconnect "github.com/provin-line/oss/gen/go/dplaax/payload/v1/payloadpbconnect"
	tlogpbconnect "github.com/provin-line/oss/gen/go/dplaax/tlog/v1/tlogpbconnect"

	"github.com/provin-line/oss/internal/httpserve"
	"github.com/provin-line/oss/internal/netexcerpt"
	"github.com/provin-line/oss/network/pkg/core"
)

// longToken is far longer than any text the node is to write, and within every
// service's read cap.
var longToken = strings.Repeat("a", 200<<10)

// rawRequest is a request body sent as it is.
type rawRequest []byte

// rawJSONCodec sends a rawRequest as its bytes under the name of connect's
// JSON codec, so a test can send a body no message marshals to. It returns a
// copy: connect keeps what Marshal returns for its buffers.
type rawJSONCodec struct{}

func (rawJSONCodec) Name() string { return "json" }

func (rawJSONCodec) Marshal(m any) ([]byte, error) {
	if r, ok := m.(*rawRequest); ok {
		return bytes.Clone(*r), nil
	}
	return protojson.Marshal(m.(proto.Message))
}

func (rawJSONCodec) Unmarshal(b []byte, m any) error {
	return protojson.Unmarshal(b, m.(proto.Message))
}

// protocols are the three a connect handler answers.
var protocols = []struct {
	name string
	opts []connect.ClientOption
}{
	{"connect", nil},
	{"grpc", []connect.ClientOption{connect.WithGRPC()}},
	{"grpc-web", []connect.ClientOption{connect.WithGRPCWeb()}},
}

// http2Assembled serves the production mux over TLS with HTTP/2, so one server
// answers all three protocols; it returns the mux as well.
func http2Assembled(t *testing.T) (*httptest.Server, *http.ServeMux) {
	t.Helper()
	h, _, _ := assembledHandler(t)
	return serveHTTP2(t, h)
}

// serveHTTP2 serves the mux h over TLS with HTTP/2 and returns it as well.
func serveHTTP2(t *testing.T, h http.Handler) (*httptest.Server, *http.ServeMux) {
	t.Helper()
	mux, ok := h.(*http.ServeMux)
	if !ok {
		t.Fatalf("BuildHandler returned %T, want *http.ServeMux", h)
	}
	srv := httptest.NewUnstartedServer(h)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, mux
}

// procedure is one RPC of the dplaax API.
type procedure struct {
	path   string
	method protoreflect.MethodDescriptor
}

// dplaaxProcedures is every RPC of the dplaax API, each of which mux routes.
func dplaaxProcedures(t *testing.T, mux *http.ServeMux) []procedure {
	t.Helper()
	var out []procedure
	protoregistry.GlobalFiles.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		if !strings.HasPrefix(string(fd.Package()), "dplaax.") {
			return true
		}
		for i := range fd.Services().Len() {
			svc := fd.Services().Get(i)
			for j := range svc.Methods().Len() {
				m := svc.Methods().Get(j)
				path := "/" + string(svc.FullName()) + "/" + string(m.Name())
				if _, pattern := mux.Handler(httptest.NewRequest(http.MethodPost, path, nil)); pattern == "" {
					t.Errorf("%s is not routed", path)
				}
				out = append(out, procedure{path: path, method: m})
			}
		}
		return true
	})
	if len(out) == 0 {
		t.Fatal("the registry walk saw no dplaax service")
	}
	return out
}

// requireBoundedText fails unless err is one the server sent, its text UTF-8
// within netexcerpt.TextLimit bytes; it returns its code.
func requireBoundedText(t *testing.T, what string, err error) connect.Code {
	t.Helper()
	var ce *connect.Error
	if !errors.As(err, &ce) || !connect.IsWireError(err) {
		t.Errorf("%s: %.200v: want an error the server sent", what, err)
		return connect.CodeUnknown
	}
	if msg := ce.Message(); len(msg) > netexcerpt.TextLimit || !utf8.ValidString(msg) {
		t.Errorf("%s: the caller received %d bytes of text (UTF-8: %v): %.120q", what, len(msg), utf8.ValidString(msg), msg)
	}
	return ce.Code()
}

// requireCutFrom fails unless err's text is the head of one at least n bytes
// long, so the long input reached what wrote the error.
func requireCutFrom(t *testing.T, what string, err error, n int) {
	t.Helper()
	var ce *connect.Error
	if !errors.As(err, &ce) {
		return
	}
	i := strings.LastIndex(ce.Message(), "… (")
	var cut int
	if i < 0 || !strings.HasSuffix(ce.Message(), " bytes)") {
		t.Errorf("%s: text %.120q is not a cut one", what, ce.Message())
		return
	}
	if _, err := fmt.Sscanf(ce.Message()[i:], "… (%d bytes)", &cut); err != nil || cut < n {
		t.Errorf("%s: text %.120q was cut from %d bytes, want at least %d", what, ce.Message(), cut, n)
	}
}

// Every RPC the node serves answers a JSON body that does not decode, in each
// protocol, within netexcerpt.TextLimit bytes, however long the body's token:
// connect decodes a unary request before any interceptor runs, and protojson
// quotes the token whole. The client-streaming RPC is sent past L1, so its
// first frame is decoded.
func TestBuildHandler_BoundsTheTextOfAnUndecodableRequest(t *testing.T) {
	srv, mux := http2Assembled(t)
	body := rawRequest(`{} "` + longToken + `"`)
	for _, p := range dplaaxProcedures(t, mux) {
		for _, pr := range protocols {
			what := pr.name + " " + p.path
			opts := append([]connect.ClientOption{connect.WithCodec(rawJSONCodec{})}, pr.opts...)
			client := connect.NewClient[rawRequest, emptypb.Empty](srv.Client(), srv.URL+p.path, opts...)
			ctx := context.Background()
			var err error
			switch {
			case p.method.IsStreamingClient():
				stream := client.CallClientStream(ctx)
				stream.RequestHeader().Set("Authorization", "Bearer dummy")
				_ = stream.Send(&body)
				_, err = stream.CloseAndReceive()
			case p.method.IsStreamingServer():
				stream, serr := client.CallServerStream(ctx, connect.NewRequest(&body))
				if err = serr; err == nil {
					for stream.Receive() {
					}
					err = stream.Err()
					_ = stream.Close()
				}
			default:
				_, err = client.CallUnary(ctx, connect.NewRequest(&body))
			}
			if code := requireBoundedText(t, what, err); code != connect.CodeInvalidArgument {
				t.Errorf("%s: code %v, want %v", what, code, connect.CodeInvalidArgument)
			}
			requireCutFrom(t, what, err, len(longToken))
		}
	}
}

// With a mirror store wired, MirrorLogSegment is mounted on a route of its own
// and answers the same way.
func TestBuildHandler_BoundsTheTextOfAnUndecodableMirrorSegment(t *testing.T) {
	srv, _ := serveHTTP2(t, assembledHandlerWithMirror(t, 1<<20, 16, 1<<20))
	body := rawRequest(`{} "` + longToken + `"`)
	for _, pr := range protocols {
		what := pr.name + " " + tlogpbconnect.TlogServiceMirrorLogSegmentProcedure
		opts := append([]connect.ClientOption{connect.WithCodec(rawJSONCodec{})}, pr.opts...)
		client := connect.NewClient[rawRequest, emptypb.Empty](srv.Client(), srv.URL+tlogpbconnect.TlogServiceMirrorLogSegmentProcedure, opts...)
		_, err := client.CallUnary(context.Background(), connect.NewRequest(&body))
		if code := requireBoundedText(t, what, err); code != connect.CodeInvalidArgument {
			t.Errorf("%s: code %v, want %v", what, code, connect.CodeInvalidArgument)
		}
		requireCutFrom(t, what, err, len(longToken))
	}
}

// An error a handler returns quoting a field of its request reaches the caller
// within netexcerpt.TextLimit bytes, with its code: before L1 (the chain peer
// surface), after it (DID resolution naming a registry it does not serve), and
// from a server-streaming RPC, in each protocol.
func TestBuildHandler_BoundsTheTextOfAHandlersError(t *testing.T) {
	srv, _ := http2Assembled(t)
	ctx := context.Background()
	for _, pr := range protocols {
		peer := chainpbconnect.NewChainPeerServiceClient(srv.Client(), srv.URL, pr.opts...)
		_, err := peer.RegisterSubscription(ctx, connect.NewRequest(&chainpb.RegisterSubscriptionRequest{
			AuthProof: &chainpb.AuthProof{IssuedAt: longToken},
		}))
		requireCutFrom(t, pr.name+" RegisterSubscription", err, len(longToken))
		if code := requireBoundedText(t, pr.name+" RegisterSubscription", err); code != connect.CodeInvalidArgument {
			t.Errorf("%s RegisterSubscription: code %v, want %v", pr.name, code, connect.CodeInvalidArgument)
		}

		dids := didpbconnect.NewDIDServiceClient(srv.Client(), srv.URL, pr.opts...)
		_, err = dids.ResolveDID(ctx, bearer(connect.NewRequest(&didpb.ResolveDIDRequest{Did: "did:dplaax:" + longToken + ":org:x"})))
		requireCutFrom(t, pr.name+" ResolveDID", err, len(longToken))
		if code := requireBoundedText(t, pr.name+" ResolveDID", err); code != connect.CodePermissionDenied {
			t.Errorf("%s ResolveDID: code %v, want %v", pr.name, code, connect.CodePermissionDenied)
		}

		payloads := payloadpbconnect.NewPayloadServiceClient(srv.Client(), srv.URL, pr.opts...)
		stream, err := payloads.ResolvePayload(ctx, connect.NewRequest(&payloadpb.ResolvePayloadRequest{
			AuthProof: &chainpb.AuthProof{IssuedAt: longToken},
		}))
		if err == nil {
			for stream.Receive() {
			}
			err = stream.Err()
			_ = stream.Close()
		}
		requireCutFrom(t, pr.name+" ResolvePayload", err, len(longToken))
		if code := requireBoundedText(t, pr.name+" ResolvePayload", err); code != connect.CodeInvalidArgument {
			t.Errorf("%s ResolvePayload: code %v, want %v", pr.name, code, connect.CodeInvalidArgument)
		}
	}
}

// A protocol header or method connect cannot read is answered by connect
// itself, before any handler option sees the request, with a text that quotes
// its value with %q, which writes a byte as \xNN: that text reaches only the
// one who sent it, at most four times the value sent, within four times the
// headers the server reads and connect's own words, and the node writes it to
// no log.
func TestBuildHandler_AProtocolHeaderIsAnsweredToItsSenderAlone(t *testing.T) {
	h, _, _ := assembledHandler(t)
	srv, _, _, err := httpserve.BuildServer(&core.CoreConfig{ListenAddr: "127.0.0.1:0"}, nil, h, 1<<20)
	if err != nil {
		t.Fatalf("BuildServer: %v", err)
	}
	headerLimit := srv.MaxHeaderBytes
	// connectWords is room for what connect writes around the value.
	const connectWords = 128

	var logs bytes.Buffer
	prevLog, prevFlags, prevSlog := log.Writer(), log.Flags(), slog.Default()
	// The default slog logger also takes what the log package writes.
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() {
		slog.SetDefault(prevSlog)
		log.SetOutput(prevLog)
		log.SetFlags(prevFlags)
	})

	for _, b := range []string{"9", "\xff"} {
		value := strings.Repeat(b, headerLimit-4<<10)
		for _, header := range []string{"Connect-Timeout-Ms", "Content-Encoding"} {
			what := fmt.Sprintf("%s of %q", header, b)
			req := httptest.NewRequest(http.MethodPost, didpbconnect.DIDServiceResolveDIDProcedure, strings.NewReader("{}"))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(header, value)
			rec := httptest.NewRecorder()
			srv.Handler.ServeHTTP(rec, req)
			var answer struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &answer); err != nil {
				t.Fatalf("%s: answer %.200q: %v", what, rec.Body.String(), err)
			}
			if len(answer.Message) < len(value) {
				t.Errorf("%s: answer %.120q does not quote the value: the exception no longer holds as stated", what, answer.Message)
			}
			if max := 4*len(value) + connectWords; len(answer.Message) > max {
				t.Errorf("%s: answer of %d bytes is longer than four times the %d bytes sent", what, len(answer.Message), len(value))
			}
			if max := 4*headerLimit + connectWords; len(answer.Message) > max {
				t.Errorf("%s: answer of %d bytes is longer than four times the %d bytes of headers the server reads", what, len(answer.Message), headerLimit)
			}
		}
	}
	if logs.Len() != 0 {
		t.Errorf("answering a protocol header wrote a log: %.200q", logs.String())
	}
}
