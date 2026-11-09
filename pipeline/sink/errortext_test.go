package sink_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/provin-line/oss/pipeline/contract"
	"github.com/provin-line/oss/pipeline/internal/pipeexcerpt"
	"github.com/provin-line/oss/pipeline/sink"
	"github.com/provin-line/oss/vc"
)

// bigText is a text far over pipeexcerpt.TextLimit, with line breaks and bytes
// that are not UTF-8.
var bigText = strings.Repeat("ab\n\xff", 64<<10)

func requireWithin(t *testing.T, what, s string) {
	t.Helper()
	if len(s) > pipeexcerpt.TextLimit || !utf8.ValidString(s) {
		t.Errorf("%s: %d bytes (UTF-8: %v): %.80q", what, len(s), utf8.ValidString(s), s)
	}
}

// quotingCodec refuses every envelope with an error that quotes it whole, so
// a test sees the sink's own bound rather than a codec's.
type quotingCodec struct{}

func (quotingCodec) MarshalEnvelope(*contract.Envelope) ([]byte, error) {
	return nil, errors.New("quotingCodec marshals nothing")
}

func (quotingCodec) UnmarshalEnvelope(data []byte) (*contract.Envelope, error) {
	return nil, errors.New("cannot read envelope " + string(data))
}

// longHashCred is a credential declaring an outputHash of 64 KiB.
func longHashCred(t *testing.T) *vc.PipelinePassCredential {
	t.Helper()
	cred, err := vc.New(vc.CredentialFields{
		Issuer: "did:example:upstream", ValidFrom: time.Now(),
		Subject: vc.CredentialSubjectFields{PipelineID: "p", ProcessID: "u", TransformationClaim: vc.ClaimConvert, OutputHash: "sha256:" + strings.Repeat("f", 64<<10)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return cred
}

// A reject record holds no refused payload, whatever its size: on every reject
// path below its Detail and IssuerDID are each within pipeexcerpt.TextLimit
// bytes of UTF-8 and neither holds the payload or envelope (each over 2 KiB),
// which Detail may quote an excerpt of. The caller's Result.Error is within
// the same limit. A long value the reason names (a declared outputHash) does
// not push the rest of the reason out.
func TestProcess_RejectRecordHoldsNoRefusedPayload(t *testing.T) {
	payload := []byte(`{"blob":"` + strings.Repeat("payload-", 128<<10) + `"}`)
	cases := []struct {
		name     string
		verifier *fakeVerifier
		store    *fakeStore
		codec    contract.EnvelopeCodec
		wire     func(t *testing.T) []byte
		refused  func(wire []byte) []byte
		keeps    string
	}{
		{"decode failure", &fakeVerifier{result: verified()}, &fakeStore{}, quotingCodec{},
			func(*testing.T) []byte { return payload },
			func(wire []byte) []byte { return wire }, "cannot read envelope"},
		{"verdict, long issuer", &fakeVerifier{result: &vc.VerifyResult{Overall: vc.ConfidenceFailed}}, &fakeStore{}, nil,
			func(t *testing.T) []byte {
				return encode(t, boundCredIssuer(t, payload, "did:dplaax:"+strings.Repeat("x:", 32<<10)), payload)
			},
			func([]byte) []byte { return payload }, ""},
		{"ingress store failure", &fakeVerifier{result: verified()}, &fakeStore{returnErr: errors.New(bigText)}, nil,
			func(t *testing.T) []byte { return encode(t, boundCred(t, payload), payload) },
			func([]byte) []byte { return payload }, "store ingress VC"},
		{"binding gate, long declared hash", &fakeVerifier{result: verified()}, &fakeStore{}, nil,
			func(t *testing.T) []byte { return encode(t, longHashCred(t), payload) },
			func([]byte) []byte { return payload }, "tampered or substituted bytes"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rl := &fakeRejectLog{}
			cfg := baseConfig(c.verifier, c.store, &fakeWriter{})
			cfg.Kind = contract.SinkArchival
			cfg.RejectLog = rl
			cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
			if c.codec != nil {
				cfg.Codec = c.codec
			}
			p, err := sink.New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			wire := c.wire(t)
			r, err := p.Process(context.Background(), wire)
			if err != nil {
				t.Fatal(err)
			}
			requireWithin(t, "Result.Error", r.Error)
			if len(rl.records) != 1 {
				t.Fatalf("%d reject records, want 1", len(rl.records))
			}
			rec := rl.records[0]
			requireWithin(t, "Detail", rec.Detail)
			requireWithin(t, "IssuerDID", rec.IssuerDID)
			refused := string(c.refused(wire))
			if len(refused) <= 2<<10 {
				t.Fatalf("the refused bytes (%d) are not over 2 KiB", len(refused))
			}
			if strings.Contains(rec.Detail, refused) || strings.Contains(rec.IssuerDID, refused) {
				t.Error("the record holds the refused bytes")
			}
			if c.keeps != "" && !strings.Contains(rec.Detail, c.keeps) {
				t.Errorf("Detail %.120q lost %q", rec.Detail, c.keeps)
			}
		})
	}
}

// A log line of the sink names an error within pipeexcerpt.TextLimit bytes,
// on one line: a verifier's error, however long or many-lined.
func TestProcess_LogsAVerifierErrorWithinTheLimit(t *testing.T) {
	var buf bytes.Buffer
	cfg := baseConfig(&fakeVerifier{err: errors.New(bigText)}, &fakeStore{}, &fakeWriter{})
	cfg.Logger = slog.New(slog.NewTextHandler(&buf, nil))
	p, err := sink.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	good := []byte(`{"v":1}`)
	if _, err := p.Process(context.Background(), encode(t, boundCred(t, good), good)); err != nil {
		t.Fatal(err)
	}
	requireLogLines(t, buf.String())
	if !strings.Contains(buf.String(), "verification error") {
		t.Fatalf("the verifier's error was not logged: %.200q", buf.String())
	}
}

// requireLogLines fails unless each line of out is one record of the text
// handler (a line break in an attribute would start a line without "time=")
// within the bound a record naming one bounded error takes.
func requireLogLines(t *testing.T, out string) {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		if !strings.HasPrefix(line, "time=") {
			t.Errorf("a log record broke across lines: %.120q", line)
		}
		if max := 256 + 4*pipeexcerpt.TextLimit; len(line) > max {
			t.Errorf("log line of %d bytes, want at most %d: %.120q", len(line), max, line)
		}
	}
}
