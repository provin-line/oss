package transport_test

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/provin-line/oss/pipeline/contract"
	"github.com/provin-line/oss/pipeline/internal/pipeexcerpt"
	"github.com/provin-line/oss/pipeline/transport"
)

// lockedBuffer is a bytes.Buffer safe for the loop's goroutine and the test's.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// The loop logs a processor's errored Result, and a processor's error, within
// pipeexcerpt.TextLimit bytes on one line, however long: the processor may be
// one this module does not hold.
func TestLoop_LogsAProcessorsErrorWithinTheLimit(t *testing.T) {
	long := strings.Repeat("ab\n\xff", 64<<10)
	for _, c := range []struct {
		name   string
		result *contract.Result
		err    error
	}{
		{"errored result", &contract.Result{Status: contract.StatusErrored, Error: long}, nil},
		{"process error", nil, errors.New(long)},
	} {
		t.Run(c.name, func(t *testing.T) {
			var logs lockedBuffer
			sub := newSyncSubscriber([]byte("raw input"))
			loop, err := transport.NewLoop(transport.LoopConfig{
				Behavior:   contract.ChainPreserving,
				Strategy:   contract.VerificationAdjacent,
				Processor:  &fakeProcessor{results: []*contract.Result{c.result}, errs: []error{c.err}},
				Subscriber: sub,
				Publisher:  &fakePublisher{},
				Codec:      testCodec(),
				Emission:   &fakeTlog{},
				Logger:     slog.New(slog.NewTextHandler(&logs, nil)),
			})
			if err != nil {
				t.Fatal(err)
			}
			cancel, done := runLoop(t, loop, sub)
			sub.deliver()
			cancel()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			out := logs.String()
			if !strings.Contains(out, "transport: process") || !strings.Contains(out, " bytes)") {
				t.Fatalf("the error was not logged cut: %.200q", out)
			}
			for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
				if !strings.HasPrefix(line, "time=") {
					t.Errorf("a log record broke across lines: %.120q", line)
				}
				if max := 256 + 4*pipeexcerpt.TextLimit; len(line) > max {
					t.Errorf("log line of %d bytes, want at most %d: %.120q", len(line), max, line)
				}
			}
		})
	}
}
