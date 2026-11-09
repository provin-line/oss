package netcompose

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"

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
// connect answers some requests before any handler option sees them, and
// those answers are outside it: a protocol header, query parameter or method
// connect cannot read (a timeout, a compression name, the protocol version)
// is quoted with %q, which writes a byte as \xNN, so the text is at most four
// times the value sent, within four times the headers the server reads and
// connect's own words; it goes to the one who sent it and to no log. How a
// request's body is read is package httpserve's.
func errorText() connect.HandlerOption {
	return connect.WithHandlerOptions(
		connect.WithInterceptors(errorTextInterceptor{}),
		connect.WithCodec(boundedJSON{name: "json"}),
		connect.WithCodec(boundedJSON{name: "json; charset=utf-8"}),
	)
}

// errorTextInterceptor passes each error a handler returns through
// boundError.
type errorTextInterceptor struct{}

func (errorTextInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		res, err := next(ctx, req)
		return res, boundError(err)
	}
}

func (errorTextInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

func (errorTextInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		return boundError(next(ctx, conn))
	}
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
