package vectors_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"slices"
	"strconv"
	"testing"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/crypto/es256"
	"github.com/provin-line/oss/crypto/rs256"
)

// wycheproofFile is the part of a Wycheproof testvectors_v1 file the runner
// reads.
type wycheproofFile struct {
	NumberOfTests int               `json:"numberOfTests"`
	TestGroups    []wycheproofGroup `json:"testGroups"`
}

// wycheproofGroup is one group of a file: its key, in each form a file
// writes it, and its vectors.
type wycheproofGroup struct {
	PublicKey struct {
		Pk           string `json:"pk"`
		Uncompressed string `json:"uncompressed"`
	} `json:"publicKey"`
	PublicKeyAsn string `json:"publicKeyAsn"`
	Tests        []struct {
		TcID    int      `json:"tcId"`
		Comment string   `json:"comment"`
		Flags   []string `json:"flags"`
		Msg     string   `json:"msg"`
		Sig     string   `json:"sig"`
		Result  string   `json:"result"`
	} `json:"tests"`
}

// wycheproofSuite is a file the runner checks: its count of vectors, the
// product's verifier, and the group's key in the hex form that verifier takes.
type wycheproofSuite struct {
	file  string
	tests int
	v     crypto.Verifier
	key   func(g wycheproofGroup) string
}

// wycheproofSuites is every Wycheproof file the runner checks.
var wycheproofSuites = func() []wycheproofSuite {
	pk := func(g wycheproofGroup) string { return g.PublicKey.Pk }
	uncompressed := func(g wycheproofGroup) string { return g.PublicKey.Uncompressed }
	asn := func(g wycheproofGroup) string { return g.PublicKeyAsn }
	return []wycheproofSuite{
		{"ed25519_test.json", 210, ed25519.Verifier{}, pk},
		{"ecdsa_secp256r1_sha256_p1363_test.json", 262, es256.Verifier{}, uncompressed},
		{"rsa_signature_2048_sha256_test.json", 259, rs256.Verifier{}, asn},
		{"rsa_signature_3072_sha256_test.json", 259, rs256.Verifier{}, asn},
		{"rsa_signature_4096_sha256_test.json", 258, rs256.Verifier{}, asn},
	}
}()

func loadWycheproof(t *testing.T, name string) wycheproofFile {
	t.Helper()
	raw, err := os.ReadFile("testdata/wycheproof/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var f wycheproofFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return f
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}
	return b
}

// wycheproofExpected is wycheproof.expected.tsv: per file and tcId, the
// outcome the product's contract gives where it is not the vector's own
// valid/invalid, and every acceptable vector's.
type wycheproofExpected map[string]map[int]string

func loadWycheproofExpected(t *testing.T) wycheproofExpected {
	t.Helper()
	out := wycheproofExpected{}
	for _, r := range readExpected(t, "wycheproof.expected.tsv", 4) {
		id, err := strconv.Atoi(r[1])
		if err != nil {
			t.Fatalf("wycheproof.expected.tsv: tcId %q: %v", r[1], err)
		}
		if r[2] != "accept" && r[2] != "refuse" {
			t.Fatalf("wycheproof.expected.tsv: %s %d: outcome %q, want accept or refuse", r[0], id, r[2])
		}
		if out[r[0]] == nil {
			out[r[0]] = map[int]string{}
		}
		if _, dup := out[r[0]][id]; dup {
			t.Fatalf("wycheproof.expected.tsv: %s %d listed twice", r[0], id)
		}
		out[r[0]][id] = r[2]
	}
	return out
}

// runWycheproof checks every vector of s's file through its verifier against
// rows, the table's rows for that file. A vector's expected outcome is its
// row, else accept for valid and refuse for invalid; an acceptable vector
// without a row, a row for a tcId the file does not have, and a row that says
// what the default says all fail.
func runWycheproof(t *testing.T, s wycheproofSuite, rows map[int]string) {
	t.Helper()
	file := s.file
	f := loadWycheproof(t, file)
	seen := map[int]bool{}
	var total, accepted int
	for _, g := range f.TestGroups {
		key := unhex(t, s.key(g))
		for _, tc := range g.Tests {
			total++
			seen[tc.TcID] = true
			ok, err := s.v.Verify(key, unhex(t, tc.Msg), unhex(t, tc.Sig))
			got := "refuse"
			if ok && err == nil {
				got = "accept"
				accepted++
			}
			def := map[string]string{"valid": "accept", "invalid": "refuse"}[tc.Result]
			want, listed := rows[tc.TcID]
			switch {
			case listed && want == def:
				t.Errorf("%s tcId %d: the table says %s, which the vector says already", file, tc.TcID, want)
			case !listed && def == "":
				t.Errorf("%s tcId %d (%s %v): %s vector with no row in the table", file, tc.TcID, tc.Comment, tc.Flags, tc.Result)
				continue
			case !listed:
				want = def
			}
			if got != want {
				t.Errorf("%s tcId %d (%s %v, %s): %s, want %s (Verify: %v, %v)", file, tc.TcID, tc.Comment, tc.Flags, tc.Result, got, want, ok, err)
			}
		}
	}
	for id := range rows {
		if !seen[id] {
			t.Errorf("wycheproof.expected.tsv: %s has no tcId %d", file, id)
		}
	}
	if total != s.tests || total != f.NumberOfTests {
		t.Errorf("%s: ran %d vectors, the file says %d, recorded %d", file, total, f.NumberOfTests, s.tests)
	}
	t.Logf("%s: %d vectors, %d accepted, %d table rows", file, total, accepted, len(rows))
}

// uncheckedWycheproofFiles lists, sorted, the files rows names that no
// runner checks.
func uncheckedWycheproofFiles(rows wycheproofExpected) []string {
	var out []string
	for file := range rows {
		if !slices.ContainsFunc(wycheproofSuites, func(s wycheproofSuite) bool { return s.file == file }) {
			out = append(out, file)
		}
	}
	slices.Sort(out)
	return out
}

func TestUncheckedWycheproofFiles(t *testing.T) {
	rows := wycheproofExpected{
		"ed25519_test.json":                   {1: "refuse"},
		"rsa_signature_1024_sha256_test.json": {1: "refuse"},
	}
	if got, want := uncheckedWycheproofFiles(rows), []string{"rsa_signature_1024_sha256_test.json"}; !slices.Equal(got, want) {
		t.Errorf("unchecked files %q, want %q", got, want)
	}
}

// Every file of wycheproofSuites goes through its verifier, and a table row
// for a file no runner checks fails.
func TestWycheproof(t *testing.T) {
	rows := loadWycheproofExpected(t)
	for _, s := range wycheproofSuites {
		t.Run(s.file, func(t *testing.T) { runWycheproof(t, s, rows[s.file]) })
	}
	for _, file := range uncheckedWycheproofFiles(rows) {
		t.Errorf("wycheproof.expected.tsv: no runner checks %s", file)
	}
}
