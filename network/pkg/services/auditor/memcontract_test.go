package auditor_test

import (
	"testing"

	"github.com/provin-line/oss/network/pkg/services/auditor"
	"github.com/provin-line/oss/network/pkg/services/auditor/internal/storecontract"
)

// The shared behavioral contract, run against the mem implementations — the
// file siblings run the SAME suite, so semantics cannot drift apart silently.
func TestContract_StatusStore(t *testing.T) {
	storecontract.StatusStore(t, func(t *testing.T) auditor.StatusStore { return auditor.NewMemStatusStore() })
}

func TestContract_ReceiptStore(t *testing.T) {
	storecontract.ReceiptStore(t, func(t *testing.T) auditor.ReceiptStore { return auditor.NewMemReceiptStore() })
}

func TestContract_Queue(t *testing.T) {
	storecontract.Queue(t, func(t *testing.T) auditor.AuditQueue { return auditor.NewMemQueue() })
}
