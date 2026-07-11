package evidence_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/provin-line/oss/network/pkg/services/chainmanager/evidence"
	"github.com/provin-line/oss/tlog/filelog"
)

func fullRecord() evidence.Record {
	return evidence.Record{
		Op:          "RegisterSubscription",
		ViewVersion: 1, // wireauth.ViewVersion — this package is a generic codec, so the value is inlined rather than importing wireauth
		SignerDID:   "did:dplaax:poc.dplaax.dev:org:sub",
		Nonce:       "n1",
		IssuedAt:    "2026-07-11T12:00:00Z",
		Signature:   []byte{0xde, 0xad, 0xbe, 0xef},
		Fields: map[string]any{
			"subscriber_did":   "did:dplaax:poc.dplaax.dev:org:sub",
			"publisher_did":    "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1",
			"payload_delivery": "inline",
		},
		KeyMaterial: evidence.KeyMaterial{
			Method:    "did:dplaax:poc.dplaax.dev:org:sub#auth",
			PublicKey: []byte{1, 2, 3, 4, 5},
			Type:      "authentication",
		},
	}
}

// A relationship-evidence record must survive a process restart byte-
// identically: Record over a filelog, close it (releasing the single-opener
// lock), reopen a SECOND filelog + evidence.Log instance over the same dir,
// and Get must return the exact Record — the restart property
// commitment-012 pins for the ingress VC store, here for relationship
// evidence.
func TestLog_Record_SurvivesRestartByteIdentical(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	fl, err := filelog.New(dir)
	if err != nil {
		t.Fatalf("filelog.New: %v", err)
	}
	log := evidence.New(fl)

	want := fullRecord()
	rec, err := log.Record(ctx, want)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if rec.Index != 0 {
		t.Fatalf("Index = %d, want 0", rec.Index)
	}
	if err := fl.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	fl2, err := filelog.New(dir) // a fresh instance over the same dir (the restart)
	if err != nil {
		t.Fatalf("filelog.New (restart): %v", err)
	}
	defer fl2.Close()
	log2 := evidence.New(fl2)
	got, err := log2.Get(ctx, 0)
	if err != nil {
		t.Fatalf("Get (restart): %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Get (restart) = %+v, want %+v", got, want)
	}
}

// Size delegates to the underlying tlog.Log.
func TestLog_Size(t *testing.T) {
	ctx := context.Background()
	fl, err := filelog.New(t.TempDir())
	if err != nil {
		t.Fatalf("filelog.New: %v", err)
	}
	log := evidence.New(fl)

	if n, err := log.Size(ctx); err != nil || n != 0 {
		t.Fatalf("Size (empty) = %d (err %v), want 0", n, err)
	}
	if _, err := log.Record(ctx, fullRecord()); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if n, err := log.Size(ctx); err != nil || n != 1 {
		t.Fatalf("Size = %d (err %v), want 1", n, err)
	}
}

// Get on an out-of-range index surfaces the underlying tlog error.
func TestLog_Get_OutOfRange(t *testing.T) {
	ctx := context.Background()
	fl, err := filelog.New(t.TempDir())
	if err != nil {
		t.Fatalf("filelog.New: %v", err)
	}
	log := evidence.New(fl)
	if _, err := log.Get(ctx, 0); err == nil {
		t.Error("Get on an empty log: want an error")
	}
}
