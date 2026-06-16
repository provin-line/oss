package noop_test

import (
	"testing"

	"github.com/provin-line/oss/network/pkg/services/chainmanager/infra/noop"
)

func TestPublishType(t *testing.T) {
	if got := noop.New().PublishType(); got != "noop" {
		t.Errorf("PublishType() = %q, want %q", got, "noop")
	}
}

func TestAddExport(t *testing.T) {
	info, err := noop.New().AddExport("did:dplaax:reg:org:acme:pipeline:p1")
	if err != nil {
		t.Fatalf("AddExport: %v", err)
	}
	if info["subject"] != "did:dplaax:reg:org:acme:pipeline:p1" || info["publishType"] != "noop" {
		t.Errorf("AddExport connection_info = %+v", info)
	}
}

// AddExport is idempotent: a second call for the same subject succeeds (D-p8 —
// shared per-publisher export, ref-counted by the domain).
func TestAddExport_Idempotent(t *testing.T) {
	op := noop.New()
	subject := "did:dplaax:reg:org:acme:pipeline:p1"
	if _, err := op.AddExport(subject); err != nil {
		t.Fatal(err)
	}
	if _, err := op.AddExport(subject); err != nil {
		t.Errorf("second AddExport for same subject: %v, want nil (idempotent)", err)
	}
}

func TestRemoveAndImportAreNoops(t *testing.T) {
	op := noop.New()
	if err := op.RemoveExport("s"); err != nil {
		t.Errorf("RemoveExport: %v", err)
	}
	if err := op.AddImport("remote", "key", "local"); err != nil {
		t.Errorf("AddImport: %v", err)
	}
	if err := op.RemoveImport("remote", "key"); err != nil {
		t.Errorf("RemoveImport: %v", err)
	}
}
