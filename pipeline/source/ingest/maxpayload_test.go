package ingest_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/provin-line/oss/pipeline/contract"
	"github.com/provin-line/oss/pipeline/source/ingest"
)

func TestNew_RefusesANonPositiveMaxPayloadSize(t *testing.T) {
	for _, n := range []int{0, -1} {
		p, err := ingest.New(ingest.Config{Signer: &fakeSourceSigner{}, MaxPayloadSize: n})
		if !errors.Is(err, ingest.ErrInvalidMaxPayloadSize) {
			t.Errorf("MaxPayloadSize %d: got %v, want ErrInvalidMaxPayloadSize", n, err)
		}
		if p != nil {
			t.Errorf("MaxPayloadSize %d: New returned a processor with its error", n)
		}
	}
}

func TestProcess_InputPastMaxPayloadSize_Errored(t *testing.T) {
	signer := &fakeSourceSigner{}
	obs := &fakeObserver{}
	p, err := ingest.New(ingest.Config{Signer: signer, Observers: []contract.ProcessObserver{obs}, MaxPayloadSize: 8})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	result, goErr := p.Process(context.Background(), []byte(`"ZZZZZZZ"`))
	if goErr != nil {
		t.Fatalf("unexpected Go error: %v", goErr)
	}
	if result.Status != contract.StatusErrored {
		t.Fatalf("Status=%v, want StatusErrored for 9 bytes past a bound of 8", result.Status)
	}
	if !strings.Contains(result.Error, "9 bytes") || !strings.Contains(result.Error, "bound of 8") {
		t.Errorf("Error %q does not name the input's size and the bound", result.Error)
	}
	if strings.Contains(result.Error, "ZZZ") {
		t.Errorf("Error %q quotes the input", result.Error)
	}
	if len(signer.calls) != 0 {
		t.Errorf("Signer called %d times for an input past the bound, want 0", len(signer.calls))
	}
	if len(obs.calls) != 1 {
		t.Errorf("Observer calls=%d, want 1 on the errored event", len(obs.calls))
	}
}

func TestProcess_InputAtMaxPayloadSize_Passes(t *testing.T) {
	signer := &fakeSourceSigner{}
	p, err := ingest.New(ingest.Config{Signer: signer, MaxPayloadSize: 8})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	result, goErr := p.Process(context.Background(), []byte(`"ZZZZZZ"`))
	if goErr != nil {
		t.Fatalf("unexpected Go error: %v", goErr)
	}
	if result.Status != contract.StatusPassed {
		t.Fatalf("Status=%v (%s), want StatusPassed for 8 bytes at a bound of 8", result.Status, result.Error)
	}
}
