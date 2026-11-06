package didregistry

import "testing"

func TestIsOwnKeyID(t *testing.T) {
	const subject = "did:dplaax:poc.dplaax.dev:org:acme"
	for id, want := range map[string]bool{
		"#signing":                              true,
		subject + "#signing":                    true,
		"#key-1.v2_b":                           true,
		"":                                      false,
		"#":                                     false,
		"##":                                    false,
		"#a#":                                   false,
		"#a#b":                                  false,
		"signing":                               false,
		subject + "x#a":                         false,
		"did:dplaax:poc.dplaax.dev:org:other#a": false,
		"#..":                                   false,
		"#sign%69ng":                            false,
		"#sig\tning":                            false,
		"#signing ":                             false,
		"#sígning":                              false,
	} {
		if got := isOwnKeyID(subject, id); got != want {
			t.Errorf("isOwnKeyID(%q) = %v, want %v", id, got, want)
		}
	}
}
