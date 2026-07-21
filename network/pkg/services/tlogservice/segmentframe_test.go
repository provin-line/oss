package tlogservice

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestFrameUnframeRoundTrip(t *testing.T) {
	cases := [][][]byte{
		{},                                       // empty list -> empty blob
		{{}},                                     // one zero-length payload
		{[]byte("a"), []byte(""), []byte("ccc")}, // mixed, incl. empty
		{bytes.Repeat([]byte("x"), 1000)},        // one large payload
	}
	for i, want := range cases {
		framed := FrameRecordPayloads(want)
		got, err := UnframeRecordPayloads(framed, 256, 1<<20)
		if err != nil {
			t.Fatalf("case %d: unframe: %v", i, err)
		}
		if len(got) != len(want) {
			t.Fatalf("case %d: got %d records, want %d", i, len(got), len(want))
		}
		for j := range want {
			if !bytes.Equal(got[j], want[j]) {
				t.Fatalf("case %d record %d: got %q want %q", i, j, got[j], want[j])
			}
		}
	}
	// empty list frames to an empty blob (no bytes on the wire).
	if len(FrameRecordPayloads(nil)) != 0 {
		t.Fatalf("empty list must frame to an empty blob")
	}
}

func TestUnframeRejectsOverRecordCapDuringScan(t *testing.T) {
	// maxRecords+1 zero-length frames -> ErrCapExceeded, and the scan stops at
	// the cap (never materializing an unbounded slice — the reshape's point).
	const maxRecords = 4
	framed := FrameRecordPayloads([][]byte{{}, {}, {}, {}, {}}) // 5 > 4
	got, err := UnframeRecordPayloads(framed, maxRecords, 1<<20)
	if !errors.Is(err, ErrCapExceeded) {
		t.Fatalf("want ErrCapExceeded, got %v", err)
	}
	if len(got) > maxRecords {
		t.Fatalf("scan materialized %d records, must stop at cap %d", len(got), maxRecords)
	}
}

func TestUnframeRejectsOverByteCap(t *testing.T) {
	framed := FrameRecordPayloads([][]byte{bytes.Repeat([]byte("x"), 10)})
	if _, err := UnframeRecordPayloads(framed, 256, 4); !errors.Is(err, ErrCapExceeded) {
		t.Fatalf("want ErrCapExceeded for 10 bytes over maxBytes=4, got %v", err)
	}
}

func TestUnframeRejectsTruncatedFrame(t *testing.T) {
	// A length prefix that overruns the remaining bytes is malformed.
	var buf []byte
	buf = binary.AppendUvarint(buf, 5) // claims 5 bytes...
	buf = append(buf, 'a', 'b')        // ...but only 2 follow
	if _, err := UnframeRecordPayloads(buf, 256, 1<<20); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("want ErrInvalidArgument for truncated frame, got %v", err)
	}
}

func TestUnframeRejectsBadVarint(t *testing.T) {
	// 10 x 0x80 = a varint that never terminates / overflows uint64.
	bad := bytes.Repeat([]byte{0x80}, 10)
	if _, err := UnframeRecordPayloads(bad, 256, 1<<20); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("want ErrInvalidArgument for bad varint, got %v", err)
	}
}

func TestUnframeRejectsNonPositiveCaps(t *testing.T) {
	if _, err := UnframeRecordPayloads(nil, 0, 1<<20); err == nil {
		t.Fatalf("want error for maxRecords=0")
	}
	if _, err := UnframeRecordPayloads(nil, 256, 0); err == nil {
		t.Fatalf("want error for maxBytes=0")
	}
}

// The cap operators admit EQUAL-to-cap (records: reject the N+1th, so N is OK;
// bytes: strict >, so ==maxBytes is OK). These positive-boundary cases lock the
// operators — a future flip of `==`/`>` to `>=` would pass every rejection test
// above but fail here.
func TestUnframeAdmitsExactlyMaxRecords(t *testing.T) {
	const maxRecords = 4
	framed := FrameRecordPayloads([][]byte{{}, {}, {}, {}}) // exactly 4
	got, err := UnframeRecordPayloads(framed, maxRecords, 1<<20)
	if err != nil {
		t.Fatalf("exactly maxRecords must be admitted, got %v", err)
	}
	if len(got) != maxRecords {
		t.Fatalf("got %d records, want %d", len(got), maxRecords)
	}
}

func TestUnframeAdmitsExactlyMaxBytes(t *testing.T) {
	const maxBytes = 8
	framed := FrameRecordPayloads([][]byte{bytes.Repeat([]byte("x"), maxBytes)})
	got, err := UnframeRecordPayloads(framed, 256, maxBytes)
	if err != nil {
		t.Fatalf("a payload of exactly maxBytes must be admitted, got %v", err)
	}
	if len(got) != 1 || len(got[0]) != maxBytes {
		t.Fatalf("got %d records (first len %d), want 1 record of %d bytes", len(got), len(got[0]), maxBytes)
	}
}
