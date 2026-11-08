// Added by 1o1 Co. Ltd. for github.com/provin-line/oss; not upstream code.
// See README.md in this directory.

package jsonschema

// Hash sign: a test of the local patch to v6.0.3 (README.md).

import (
	"encoding/json"
	"hash/maphash"
	"testing"
)

// Numbers that differ only in sign hash apart, so uniqueItems past 20 items
// compares only the values that hash alike rather than every pair of
// numbers of one magnitude.
func TestWriteHash_KeepsTheSign(t *testing.T) {
	seed := maphash.MakeSeed()
	hash := func(v any) uint64 {
		var h maphash.Hash
		h.SetSeed(seed)
		if k := writeHash(v, &h); k != nil {
			t.Fatal(k)
		}
		return h.Sum64()
	}
	for _, pair := range [][2]string{{"1", "-1"}, {"0.5", "-0.5"}, {"3e40", "-3e40"}} {
		if hash(json.Number(pair[0])) == hash(json.Number(pair[1])) {
			t.Errorf("%s and %s hash alike", pair[0], pair[1])
		}
	}
	if hash(json.Number("1")) != hash(json.Number("1.0")) {
		t.Error("1 and 1.0, one number, hash apart")
	}
}
