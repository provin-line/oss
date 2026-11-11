package keybinding_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/canon"
	"github.com/provin-line/oss/canon/jcs"
	"github.com/provin-line/oss/keybinding"
)

// go126 and go127 are the encodedLists that Go 1.26.8's and Go 1.27.1's gzip
// write, at the default level, for a list of MinStatusListSize entries marked
// at 3 and 131071: the same entries, other bytes.
const (
	go126 = "uH4sIAAAAAAAA_-zAMQEAAAgCMG1A_7TE4NlyAAAAAAAAAAAAAAAAAAAAwNg3AAD__-xSDbMAQAAA"
	go127 = "uH4sIAAAAAAAA_-zAMQEAAAgCMG1A_7TE4NlyAAAAAAAAAAAAAAAAAAAAwNh3AOxSDbMAQAAA"
)

// knownHash is the content hash of the list f.list issues from t0+59m marked
// at 3 and 131071, computed outside Go from the formula (RFC 8785 of the body
// without its proof, encodedList replaced by the digest of the bits).
const knownHash = "sha256:307e09a2f744b24c49cb1c369bd97bc08550f98b7aee3397d5df9791fc6fa592"

// listBits is a list of MinStatusListSize entries, marked at revoked.
func listBits(revoked ...uint64) []byte {
	bits := make([]byte, keybinding.MinStatusListSize/8)
	for _, i := range revoked {
		bits[i/8] |= 0x80 >> (i % 8)
	}
	return bits
}

// encodeList compresses each part as its own gzip member, at level, and
// encodes the whole as an encodedList.
func encodeList(t *testing.T, level int, parts ...[]byte) string {
	t.Helper()
	var gz bytes.Buffer
	for _, p := range parts {
		w, err := gzip.NewWriterLevel(&gz, level)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(p); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return "u" + b64(gz.Bytes())
}

// A list's content hash covers its bits, not their compression: the same
// list compressed otherwise (another level, another Go version's gzip, two
// gzip members) is the same list, the held one, also once restored. Another
// list with the same validFrom, other marks or more entries, is still a
// rewind.
func TestStatusList_TheSameListOtherwiseCompressedIsTheSameList(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	at := t0.Add(time.Hour)
	from := at.Add(-30 * time.Minute)
	bits := listBits(3, 131071)
	encodings := map[string]string{
		"best speed":       encodeList(t, gzip.BestSpeed, bits),
		"best compression": encodeList(t, gzip.BestCompression, bits),
		"no compression":   encodeList(t, gzip.NoCompression, bits),
		"Huffman only":     encodeList(t, gzip.HuffmanOnly, bits),
		"two gzip members": encodeList(t, gzip.DefaultCompression, bits[:100], bits[100:]),
		"Go 1.27.1":        go127,
	}
	seen := map[string]string{go126: "the held list (Go 1.26.8)"}
	for name, enc := range encodings {
		if other, ok := seen[enc]; ok {
			t.Fatalf("%s and %s are the same bytes", name, other)
		}
		seen[enc] = name
	}
	issue := func(enc string) []byte {
		t.Helper()
		raw, err := keybinding.IssueStatusListEncoded(f.signer, issuerDID, "issuer", listID, from, from.Add(time.Hour), enc)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	held, err := f.v.VerifyStatusList(ctx, issue(go126), f.anchor, nil, at)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := f.v.RestoreStatusList(ctx, issue(go126), f.anchor, at)
	if err != nil {
		t.Fatal(err)
	}
	for name, enc := range encodings {
		if got, err := f.v.VerifyStatusList(ctx, issue(enc), f.anchor, held, at); err != nil || got != held {
			t.Errorf("%s: %v, %v; want the held list", name, got, err)
		}
		if got, err := f.v.VerifyStatusList(ctx, issue(enc), f.anchor, restored, at); err != nil || got != restored {
			t.Errorf("%s, against the restored list: %v, %v; want the restored list", name, got, err)
		}
	}
	longer := make([]byte, 2*len(bits))
	copy(longer, bits)
	for name, enc := range map[string]string{
		"other marks":  encodeList(t, gzip.BestCompression, listBits(3, 4, 131071)),
		"more entries": encodeList(t, gzip.BestCompression, longer),
	} {
		if _, err := f.v.VerifyStatusList(ctx, issue(enc), f.anchor, held, at); !errors.Is(err, keybinding.ErrStatusListRewound) {
			t.Errorf("another list (%s), otherwise compressed: err = %v, want ErrStatusListRewound", name, err)
		}
	}
}

// The content hash is the SHA-256 of the RFC 8785 form of the credential
// without its proof, with encodedList replaced by "sha256:" and the lowercase
// hex SHA-256 of the expanded bits.
func TestStatusList_ContentHashIsTheBodyWithTheDigestOfItsBits(t *testing.T) {
	f := newFixture(t)
	at := t0.Add(time.Hour)
	raw := f.list(t, issuerDID, "issuer", at.Add(-time.Minute), 3, 131071)
	l, err := f.v.VerifyStatusList(context.Background(), raw, f.anchor, nil, at)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := canon.NewStrictDecoder(raw).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	delete(doc, "proof")
	sum := sha256.Sum256(listBits(3, 131071))
	doc["credentialSubject"].(map[string]any)["encodedList"] = "sha256:" + hex.EncodeToString(sum[:])
	want, err := jcs.HashRFC8785(doc)
	if err != nil {
		t.Fatal(err)
	}
	if got := keybinding.StatusListHash(l); got != want || got != knownHash {
		t.Errorf("content hash %s, want %s (known %s)", got, want, knownHash)
	}
}

// StatusListContentHash is the content hash VerifyStatusList compares, from
// the list credential alone: the known value, the same for the same bits
// however compressed, not dependent on the signature, and ErrMalformed for
// what is not a revocation list.
func TestStatusListContentHash(t *testing.T) {
	f := newFixture(t)
	at := t0.Add(time.Hour)
	raw := f.list(t, issuerDID, "issuer", at.Add(-time.Minute), 3, 131071)
	got, err := keybinding.StatusListContentHash(raw)
	if err != nil {
		t.Fatal(err)
	}
	l, err := f.v.VerifyStatusList(context.Background(), raw, f.anchor, nil, at)
	if err != nil {
		t.Fatal(err)
	}
	if got != knownHash || got != keybinding.StatusListHash(l) {
		t.Errorf("StatusListContentHash = %s, want the known %s and VerifyStatusList's %s", got, knownHash, keybinding.StatusListHash(l))
	}

	from := at.Add(-30 * time.Minute)
	var first string
	for name, enc := range map[string]string{
		"Go 1.26.8": go126, "Go 1.27.1": go127,
		"best speed": encodeList(t, gzip.BestSpeed, listBits(3, 131071)), "no compression": encodeList(t, gzip.NoCompression, listBits(3, 131071)),
	} {
		raw, err := keybinding.IssueStatusListEncoded(f.signer, issuerDID, "issuer", listID, from, from.Add(time.Hour), enc)
		if err != nil {
			t.Fatal(err)
		}
		h, err := keybinding.StatusListContentHash(raw)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if first == "" {
			first = h
		} else if h != first {
			t.Errorf("%s: %s, another compression of the same bits gave %s", name, h, first)
		}
	}

	forged := mutate(t, raw, func(m map[string]any) { m["proof"].(map[string]any)["proofValue"] = "z" + strings.Repeat("1", 86) })
	if h, err := keybinding.StatusListContentHash(forged); err != nil || h != knownHash {
		t.Errorf("a list whose signature is broken: %s, %v, want the same hash (the signature is not checked)", h, err)
	}
	for name, bad := range map[string][]byte{
		"not JSON":       []byte("{"),
		"no encodedList": mutate(t, raw, func(m map[string]any) { delete(m["credentialSubject"].(map[string]any), "encodedList") }),
		"encodedList not gz": mutate(t, raw, func(m map[string]any) {
			m["credentialSubject"].(map[string]any)["encodedList"] = "u" + b64([]byte("not gzip"))
		}),
		"not a status list": mutate(t, raw, func(m map[string]any) {
			m["type"] = []any{"VerifiableCredential", "KeyBindingCredential"}
		}),
		"v2 not first": mutate(t, raw, func(m map[string]any) {
			m["@context"] = []any{"https://www.w3.org/ns/credentials/undefined-terms/v2", "https://www.w3.org/ns/credentials/v2"}
		}),
	} {
		if _, err := keybinding.StatusListContentHash(bad); !errors.Is(err, keybinding.ErrMalformed) {
			t.Errorf("%s: %v, want ErrMalformed", name, err)
		}
	}
}
