package orgverify

import (
	"strings"
	"testing"
)

func TestNormalizeFQDN(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		want    string
		wantOk  bool // true if FQDN-valid
		wantErr bool // true if syntactically invalid (parse error)
	}{
		// Valid FQDNs
		{"simple", "acme.com", "acme.com", true, false},
		{"uppercase normalized", "ACME.COM", "acme.com", true, false},
		{"trailing dot stripped", "acme.com.", "acme.com", true, false},
		{"deep subdomain", "a.b.acme.com", "a.b.acme.com", true, false},
		{"punycode preserved", "xn--ls8h.example", "xn--ls8h.example", true, false},

		// Not FQDN (returns ok=false, err=nil) -> EndorsementNA
		{"single label", "localhost", "", false, false},
		{"public suffix only", "com", "", false, false},
		{"public suffix multi", "co.jp", "", false, false},
		{"unicode IDN rejected", "\U0001F4A9.example", "", false, false},
		{"empty", "", "", false, false},

		// Syntactically invalid (returns err) -> input error
		{"label too long", "a" + strings.Repeat("x", 64) + ".com", "", false, true},
		{"leading hyphen", "-acme.com", "", false, true},
		{"trailing hyphen", "acme-.com", "", false, true},
		{"invalid char", "ac!me.com", "", false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok, err := NormalizeFQDN(c.input)
			if c.wantErr {
				if err == nil {
					t.Errorf("expected error for %q, got nil", c.input)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error for %q: %v", c.input, err)
				return
			}
			if ok != c.wantOk {
				t.Errorf("ok=%v, want %v for %q", ok, c.wantOk, c.input)
			}
			if got != c.want {
				t.Errorf("got=%q, want %q for input %q", got, c.want, c.input)
			}
		})
	}
}
