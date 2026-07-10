package contract_test

import (
	"testing"

	"github.com/provin-line/oss/pipeline/contract"
)

// TestParsePayloadDelivery pins the mode-string grammar: empty and
// "by-reference" both mean by-reference (the negotiation default), "inline"
// means inline, and anything else is a decidable error (never a silent guess).
func TestParsePayloadDelivery(t *testing.T) {
	cases := []struct {
		in      string
		want    contract.PayloadDelivery
		wantErr bool
	}{
		{"", contract.DeliveryByReference, false},
		{"by-reference", contract.DeliveryByReference, false},
		{"inline", contract.DeliveryInline, false},
		{"By-Reference", contract.DeliveryInline, true}, // case-sensitive
		{"none", contract.DeliveryInline, true},
		{"reference", contract.DeliveryInline, true},
	}
	for _, tc := range cases {
		got, err := contract.ParsePayloadDelivery(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParsePayloadDelivery(%q) = (%v, nil), want error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParsePayloadDelivery(%q) unexpected error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParsePayloadDelivery(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestPayloadDelivery_String round-trips the canonical tokens.
func TestPayloadDelivery_String(t *testing.T) {
	if got := contract.DeliveryInline.String(); got != "inline" {
		t.Errorf("DeliveryInline.String() = %q, want inline", got)
	}
	if got := contract.DeliveryByReference.String(); got != "by-reference" {
		t.Errorf("DeliveryByReference.String() = %q, want by-reference", got)
	}
	// The zero value is inline (in-org default).
	var zero contract.PayloadDelivery
	if zero != contract.DeliveryInline {
		t.Errorf("zero PayloadDelivery = %v, want DeliveryInline", zero)
	}
}
