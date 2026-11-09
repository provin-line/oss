package aggregate

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/provin-line/oss/pipeline/internal/pipeexcerpt"
	"github.com/provin-line/oss/vc"
)

type errVerifier struct{ err error }

func (v errVerifier) Verify(context.Context, *vc.PipelinePassCredential) (*vc.VerifyResult, error) {
	return nil, v.err
}

// The aggregate source logs an error within pipeexcerpt.TextLimit bytes, on
// one line, however long or many-lined: a verifier's error on an ingress
// credential.
func TestHandleIngress_LogsAnErrorWithinTheLimit(t *testing.T) {
	var buf bytes.Buffer
	h := newHarness(t, func(c *Config) {
		c.Verifier = errVerifier{errors.New(strings.Repeat("ab\n\xff", 64<<10))}
		c.Logger = slog.New(slog.NewTextHandler(&buf, nil))
	})
	payload := []byte(`{"v":1}`)
	h.feed(ingressEnvelope(t, "did:example:src", payload))
	if !strings.Contains(buf.String(), "verify ingress credential") {
		t.Fatalf("the verifier's error was not logged: %.200q", buf.String())
	}
	for _, line := range strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n") {
		if !strings.HasPrefix(line, "time=") {
			t.Errorf("a log record broke across lines: %.120q", line)
		}
		if max := 256 + 4*pipeexcerpt.TextLimit; len(line) > max {
			t.Errorf("log line of %d bytes, want at most %d: %.120q", len(line), max, line)
		}
	}
}
