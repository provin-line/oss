package logobserver_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/provin-line/oss/pipeline/contract"
	"github.com/provin-line/oss/pipeline/internal/pipeexcerpt"
	"github.com/provin-line/oss/pipeline/observer/logobserver"
)

// The observer logs a Result's error within pipeexcerpt.TextLimit bytes, on
// one line, whatever processor wrote it.
func TestOnProcessComplete_LogsAnErrorWithinTheLimit(t *testing.T) {
	var buf bytes.Buffer
	o := logobserver.New(slog.New(slog.NewTextHandler(&buf, nil)))
	ev := contract.ProcessEvent{Result: &contract.Result{Status: contract.StatusErrored, Error: strings.Repeat("ab\n\xff", 64<<10)}}
	if err := o.OnProcessComplete(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "time=") {
		t.Fatalf("logged %d lines: %.200q", len(lines), buf.String())
	}
	if max := 256 + 4*pipeexcerpt.TextLimit; len(lines[0]) > max {
		t.Errorf("log line of %d bytes, want at most %d", len(lines[0]), max)
	}
}
