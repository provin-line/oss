package netcompose

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"strings"
	"syscall"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/runtime/protoiface"

	"github.com/provin-line/oss/internal/excerpt"
	"github.com/provin-line/oss/internal/netexcerpt"
)

// errorText is the option BuildHandler gives every service it mounts, first,
// so its interceptor is the outermost: the text of an error a caller receives
// from a handler, from an interceptor (L1 included), or from the decoding of
// a JSON request is UTF-8 within netexcerpt.TextLimit bytes, its code and
// details as they were. Only the text is bounded: an error's details and
// metadata pass as they are, and no handler puts a request's text in them.
//
// A server error — one a caller receives as Internal, Unknown or DataLoss, one
// with a code outside connect's own, or one that carries no connect error at
// all, whatever code connect gives it (Canceled, DeadlineExceeded, Unknown) —
// says what went wrong inside the node (a store's path in the data directory, a
// dependency's own words, the node's own outbound call), which is not the
// caller's to read. Its caller receives, with its code, details and metadata,
// only the fixed text "server error (ref <16 hex digits>); the server's log has
// the details", and log records under that ref, at level ERROR (WARN for
// Canceled and DeadlineExceeded, often the caller's own doing), the error's own
// text (its head within netexcerpt.TextLimit bytes and its length), the cause
// its text hides behind Unwrap if any, the procedure, the code and the peer's
// address (a proxy's, behind one). A nil log is slog.Default() at the time of
// the error. Every other code keeps its text, as connect would answer it: it
// says what the caller sent or must change, or, for Unavailable, that it may
// retry.
//
// connect answers some requests before any handler option sees them, and
// those answers are outside it: a protocol header, query parameter or method
// connect cannot read (a timeout, a compression name, the protocol version)
// is quoted with %q, which writes a byte as \xNN, so the text is at most four
// times the value sent, within four times the headers the server reads and
// connect's own words; it goes to the one who sent it and to no log. How a
// request's body is read is package httpserve's.
func errorText(log *slog.Logger) connect.HandlerOption {
	return connect.WithHandlerOptions(
		connect.WithInterceptors(errorTextInterceptor{log: log}),
		connect.WithCodec(boundedJSON{name: "json"}),
		connect.WithCodec(boundedJSON{name: "json; charset=utf-8"}),
	)
}

// errorTextInterceptor answers a server error with a fixed text (see
// errorText) and passes every other error a handler returns through
// boundError.
type errorTextInterceptor struct{ log *slog.Logger }

func (i errorTextInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		res, err := next(ctx, req)
		return res, i.answer(ctx, req.Spec().Procedure, req.Peer().Addr, err)
	}
}

func (errorTextInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

func (i errorTextInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		return i.answer(ctx, conn.Spec().Procedure, conn.Peer().Addr, next(ctx, conn))
	}
}

// answer is err as the caller of procedure, at peer, is to receive it.
func (i errorTextInterceptor) answer(ctx context.Context, procedure, peer string, err error) error {
	if err == nil {
		return nil
	}
	switch code, coded := answeredCode(err); {
	case !coded,
		code == connect.CodeInternal, code == connect.CodeUnknown, code == connect.CodeDataLoss,
		code < connect.CodeCanceled, code > connect.CodeUnauthenticated:
		return i.serverError(ctx, code, procedure, peer, err)
	}
	return boundError(err)
}

// answeredCode is the code connect answers a handler's err with, as
// connect v1.21.1 maps it on the way to the wire: the code of the first
// connect error in err's chain; else Canceled for a context's cancellation
// or a client that went away (a broken pipe, a reset connection, or the
// texts net/http and x/net/http2 give one), DeadlineExceeded for a
// deadline, a context's or the os package's; else Unknown. coded reports
// whether the code is a connect error's: an error that carries none is the
// node's own text, whatever code connect gives it, as a connection reset or a
// deadline on the node's own outbound call names that call. A code a later
// connect maps otherwise is a test's to catch: they compare with connect's
// own answer.
func answeredCode(err error) (code connect.Code, coded bool) {
	var ce *connect.Error
	if errors.As(err, &ce) && ce != nil {
		return ce.Code(), true
	}
	switch {
	case errors.Is(err, context.Canceled):
		return connect.CodeCanceled, false
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		return connect.CodeDeadlineExceeded, false
	case errors.Is(err, syscall.EPIPE), errors.Is(err, syscall.ECONNRESET):
		return connect.CodeCanceled, false
	}
	switch excerpt.ErrorText(err) {
	case "client disconnected", "http2: stream closed":
		return connect.CodeCanceled, false
	}
	return connect.CodeUnknown, false
}

// serverError logs err under a new ref and returns the error its caller
// receives in its place: code, the fixed text naming the ref, and the details
// and metadata of err's connect error (but a wire error's metadata, which
// connect does not send). It holds err, so errors.Is and errors.As still find
// all err held.
func (i errorTextInterceptor) serverError(ctx context.Context, code connect.Code, procedure, peer string, err error) error {
	ref := newRef()
	log := i.log
	if log == nil {
		log = slog.Default()
	}
	attrs := []slog.Attr{
		slog.String("ref", ref),
		slog.String("procedure", procedure),
		slog.String("code", code.String()),
		slog.String("peer", peer),
		slog.String("err", netexcerpt.ErrorText(err)),
	}
	if causeErr := hiddenCause(err); causeErr != nil {
		attrs = append(attrs, slog.String("cause", netexcerpt.ErrorText(causeErr)))
	}
	// A cancellation or a deadline is often the caller's own doing, not a
	// fault of the node's: it is a warning.
	level := slog.LevelError
	if code == connect.CodeCanceled || code == connect.CodeDeadlineExceeded {
		level = slog.LevelWarn
	}
	// The request's context has often ended by now; its values stay.
	log.LogAttrs(context.WithoutCancel(ctx), level, "network: a server error answered with a fixed text", attrs...)
	// out is this node's own error, not a wire error, whatever err held:
	// its text is the node's.
	out := connect.NewError(code, &boundText{text: "server error (ref " + ref + "); the server's log has the details", err: err})
	var ce *connect.Error
	if errors.As(err, &ce) && ce != nil {
		for _, d := range ce.Details() {
			out.AddDetail(d)
		}
		if !connect.IsWireError(ce) {
			maps.Copy(out.Meta(), ce.Meta())
		}
	}
	return out
}

// hiddenCause is the error at the end of err's chain of single Unwraps when
// err's text does not hold that error's text, as a fixed text that holds its
// cause does (the L1 authorization interceptor answers a check that failed
// so); else nil. It follows at most maxCauseDepth Unwraps, and compares no
// errors, as an error's value may be one == cannot compare.
func hiddenCause(err error) error {
	cause, depth := err, 0
	for next := errors.Unwrap(cause); next != nil && depth < maxCauseDepth; next = errors.Unwrap(cause) {
		cause, depth = next, depth+1
	}
	if depth == 0 || strings.Contains(excerpt.ErrorText(err), excerpt.ErrorText(cause)) {
		return nil
	}
	return cause
}

// maxCauseDepth bounds hiddenCause's walk down a chain of Unwraps.
const maxCauseDepth = 64

// newRef is a new ref for a server error: 8 random bytes in hex.
func newRef() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// boundError is err as its caller is to receive it. connect asks err's whole
// text, then writes the message of the first *connect.Error in err's chain,
// or else that whole text with CodeUnknown (or the code of a context error).
//   - An error whose chain holds no connect error is returned as
//     excerpt.OfError returns it, within netexcerpt.TextLimit bytes.
//   - When the connect error's message is UTF-8 within netexcerpt.TextLimit
//     bytes, err is returned itself if it is that connect error, and else as
//     excerpt.OfError returns it: connect reads the connect error in it as it
//     is.
//   - Otherwise boundError returns a new connect error whose message is the
//     text excerpt.OfError takes and bounds for the error the connect error
//     holds, and which holds err, so errors.Is and errors.As still find all
//     err held. It keeps the code and details, and the metadata unless it is
//     a wire error, whose metadata connect does not send.
//
// It writes into no error it reads, but for the metadata of a connect error
// it replaces, whose map connect's Meta makes when it has none. A panic of
// the Error method of an error it reads (a nil pointer's, too) leaves neither
// boundError nor the text of the error it returns; the methods that walk
// err's chain (Unwrap, As, Is) are taken to return, and an Error method to
// return the same text each time it is called.
func boundError(err error) error {
	if err == nil {
		return nil
	}
	var ce *connect.Error
	if !errors.As(err, &ce) || ce == nil {
		return excerpt.OfError(err, netexcerpt.TextLimit)
	}
	inner, changed := excerpt.OfErrorChanged(ce.Unwrap(), netexcerpt.TextLimit)
	if !changed {
		if err == error(ce) {
			return err
		}
		return excerpt.OfError(err, netexcerpt.TextLimit)
	}
	held := &boundText{text: inner.Error(), err: err}
	var out *connect.Error
	if connect.IsWireError(ce) {
		out = connect.NewWireError(ce.Code(), held)
	} else {
		out = connect.NewError(ce.Code(), held)
		maps.Copy(out.Meta(), ce.Meta())
	}
	for _, d := range ce.Details() {
		out.AddDetail(d)
	}
	return out
}

// boundText is the text a caller receives in place of a longer one, holding
// the error that had it.
type boundText struct {
	text string
	err  error
}

func (b *boundText) Error() string { return b.text }
func (b *boundText) Unwrap() error { return b.err }

// decodeErrorRoom is what boundedJSON leaves, within netexcerpt.TextLimit,
// for the words connect puts before a codec's error ("unmarshal message: ").
const decodeErrorRoom = 64

// boundedJSON is connect's JSON codec (connect v1.21.1: unknown fields
// discarded, an empty message refused, stable output compacted) but for the
// error of Unmarshal, which protojson writes quoting the request's tokens
// whole and connect answers before any interceptor runs: it is cut to
// netexcerpt.TextLimit less decodeErrorRoom.
type boundedJSON struct{ name string }

func (c boundedJSON) Name() string { return c.name }

func (boundedJSON) Marshal(message any) ([]byte, error) {
	m, err := protoMessage(message)
	if err != nil {
		return nil, err
	}
	return protojson.MarshalOptions{}.Marshal(m)
}

func (boundedJSON) MarshalAppend(dst []byte, message any) ([]byte, error) {
	m, err := protoMessage(message)
	if err != nil {
		return nil, err
	}
	return protojson.MarshalOptions{}.MarshalAppend(dst, m)
}

func (boundedJSON) Unmarshal(data []byte, message any) error {
	m, err := protoMessage(message)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return errors.New("zero-length payload is not a valid JSON object")
	}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(data, m); err != nil {
		return excerpt.OfError(fmt.Errorf("unmarshal into %T: %w", message, err), netexcerpt.TextLimit-decodeErrorRoom)
	}
	return nil
}

func (c boundedJSON) MarshalStable(message any) ([]byte, error) {
	b, err := c.Marshal(message)
	if err != nil {
		return nil, err
	}
	compact := bytes.NewBuffer(b[:0])
	if err := json.Compact(compact, b); err != nil {
		return nil, err
	}
	return compact.Bytes(), nil
}

func (boundedJSON) IsBinary() bool { return false }

func protoMessage(message any) (proto.Message, error) {
	m, ok := message.(proto.Message)
	if ok {
		return m, nil
	}
	if _, ok := message.(protoiface.MessageV1); ok {
		return nil, fmt.Errorf("%T uses github.com/golang/protobuf, but connect-go only supports google.golang.org/protobuf: see https://go.dev/blog/protobuf-apiv2", message)
	}
	return nil, fmt.Errorf("%T doesn't implement proto.Message", message)
}
