// Command ucdgen writes package ucd's tables from the Unicode Character
// Database of one version itself (version): every general category Go's
// unicode package names, and the binary property White_Space. So the module
// reads these the same whatever Unicode version the Go toolchain's unicode
// package carries.
//
// It downloads UnicodeData.txt and PropList.txt of that version, refuses them
// unless their SHA-256 is the one pinned here, and writes the tables:
//
//	go generate ./internal/ucd
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"go/format"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// version is the UCD version the tables are generated from.
const version = "15.0.0"

const ucdBase = "https://www.unicode.org/Public/" + version + "/ucd/"

// pinned is the SHA-256 of each UCD file read.
var pinned = map[string]string{
	"UnicodeData.txt": "806e9aed65037197f1ec85e12be6e8cd870fc5608b4de0fffd990f689f376a73",
	"PropList.txt":    "e05c0a2811d113dae4abd832884199a3ea8d187ee1b872d8240a788a96540bfd",
}

// maxRune is the last code point.
const maxRune = 0x10FFFF

// subcategories are the general categories UnicodeData.txt gives a code
// point; a code point it does not list is unassigned, Cn.
var subcategories = []string{
	"Cc", "Cf", "Co", "Cs",
	"Ll", "Lm", "Lo", "Lt", "Lu",
	"Mc", "Me", "Mn",
	"Nd", "Nl", "No",
	"Pc", "Pd", "Pe", "Pf", "Pi", "Po", "Ps",
	"Sc", "Sk", "Sm", "So",
	"Zl", "Zp", "Zs",
}

// categoryNames are the names of the general categories written, as Go's
// unicode.Categories names them: the subcategories, Cn, the major classes
// (C L M N P S Z, each its subcategories together), and LC (Lu, Ll and Lt).
var categoryNames = append([]string{"Cn", "C", "L", "LC", "M", "N", "P", "S", "Z"}, subcategories...)

func main() {
	out := flag.String("o", "tables.go", "the Go file to write")
	flag.Parse()
	gc, err := generalCategories(bytes.NewReader(fetch("UnicodeData.txt")))
	if err != nil {
		log.Fatal(err)
	}
	ws, err := property(bytes.NewReader(fetch("PropList.txt")), "White_Space")
	if err != nil {
		log.Fatal(err)
	}
	src, err := source(gc, ws)
	if err != nil {
		log.Fatal(err)
	}
	tmp := *out + ".tmp"
	if err := os.WriteFile(tmp, src, 0o644); err != nil {
		log.Fatal(err)
	}
	if err := os.Rename(tmp, *out); err != nil {
		log.Fatal(err)
	}
}

// fetch downloads a UCD file and refuses it unless its SHA-256 is the
// pinned one.
func fetch(name string) []byte {
	client := &http.Client{Timeout: time.Minute}
	resp, err := client.Get(ucdBase + name)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("%s: %s", name, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		log.Fatal(err)
	}
	if err := verify(name, b); err != nil {
		log.Fatal(err)
	}
	return b
}

// verify refuses b unless it is the UCD file name, by its pinned SHA-256.
func verify(name string, b []byte) error {
	want, ok := pinned[name]
	if !ok {
		return fmt.Errorf("%s: no SHA-256 pinned", name)
	}
	sum := sha256.Sum256(b)
	if got := hex.EncodeToString(sum[:]); got != want {
		return fmt.Errorf("%s: SHA-256 %s, want %s", name, got, want)
	}
	return nil
}

// rng is an inclusive range of code points.
type rng struct{ lo, hi rune }

// generalCategories reads UnicodeData.txt and returns the general category of
// every code point, U+0000 to U+10FFFF: the one it lists, else Cn. A
// "<…, First>" line and the "<…, Last>" line right after it, of the same
// category, name a range. Any other use of them, a category that is not a
// subcategory, a code point listed twice and one that is not a code point
// are errors.
func generalCategories(r io.Reader) ([]string, error) {
	known := make(map[string]bool, len(subcategories))
	for _, c := range subcategories {
		known[c] = true
	}
	gc := make([]string, maxRune+1)
	set := func(lo, hi rune, cat string) error {
		for c := lo; c <= hi; c++ {
			if gc[c] != "" {
				return fmt.Errorf("UnicodeData: U+%04X is listed twice", c)
			}
			gc[c] = cat
		}
		return nil
	}
	first := rune(-1)
	var firstCat string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Split(sc.Text(), ";")
		if len(f) < 3 {
			continue
		}
		cp, err := strconv.ParseUint(f[0], 16, 32)
		if err != nil || cp > maxRune {
			return nil, fmt.Errorf("UnicodeData: %q is not a code point", f[0])
		}
		if !known[f[2]] {
			return nil, fmt.Errorf("UnicodeData: %s: %q is not a general category it lists", f[0], f[2])
		}
		switch {
		case first >= 0 && !strings.HasSuffix(f[1], ", Last>"):
			return nil, fmt.Errorf("UnicodeData: %s follows a First line, not its Last", f[0])
		case strings.HasSuffix(f[1], ", First>"):
			first, firstCat = rune(cp), f[2]
		case strings.HasSuffix(f[1], ", Last>"):
			if first < 0 || f[2] != firstCat || rune(cp) < first {
				return nil, fmt.Errorf("UnicodeData: %s is a Last line without its First", f[0])
			}
			if err := set(first, rune(cp), f[2]); err != nil {
				return nil, err
			}
			first = -1
		default:
			if err := set(rune(cp), rune(cp), f[2]); err != nil {
				return nil, err
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if first >= 0 {
		return nil, errors.New("UnicodeData: a First line without its Last")
	}
	for c := range gc {
		if gc[c] == "" {
			gc[c] = "Cn"
		}
	}
	return gc, nil
}

// categoryRanges returns the code points of the general category name, as
// ranges: a subcategory or Cn by itself, LC as Lu, Ll and Lt, and a major
// class as the subcategories its letter begins.
func categoryRanges(gc []string, name string) []rng {
	in := func(cat string) bool { return cat == name }
	switch {
	case name == "LC":
		in = func(cat string) bool { return cat == "Lu" || cat == "Ll" || cat == "Lt" }
	case len(name) == 1:
		in = func(cat string) bool { return cat[0] == name[0] }
	}
	var out []rng
	for c, cat := range gc {
		if !in(cat) {
			continue
		}
		if n := len(out); n > 0 && out[n-1].hi == rune(c)-1 {
			out[n-1].hi = rune(c)
			continue
		}
		out = append(out, rng{rune(c), rune(c)})
	}
	return out
}

// property reads PropList.txt and returns the code points with property
// prop, as ranges.
func property(r io.Reader, prop string) ([]rng, error) {
	var cps []rune
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line, _, _ := strings.Cut(sc.Text(), "#")
		cpField, name, ok := strings.Cut(line, ";")
		if !ok || strings.TrimSpace(name) != prop {
			continue
		}
		lo, hi, isRange := strings.Cut(strings.TrimSpace(cpField), "..")
		a, err := strconv.ParseUint(lo, 16, 32)
		if err != nil {
			return nil, fmt.Errorf("PropList: %q: %v", lo, err)
		}
		b := a
		if isRange {
			if b, err = strconv.ParseUint(hi, 16, 32); err != nil {
				return nil, fmt.Errorf("PropList: %q: %v", hi, err)
			}
		}
		if b < a || b > maxRune {
			return nil, fmt.Errorf("PropList: %s is not a range of code points", strings.TrimSpace(cpField))
		}
		for c := rune(a); c <= rune(b); c++ {
			cps = append(cps, c)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return ranges(cps), nil
}

// ranges merges code points into sorted, maximal ranges.
func ranges(cps []rune) []rng {
	sort.Slice(cps, func(i, j int) bool { return cps[i] < cps[j] })
	var out []rng
	for _, c := range cps {
		if n := len(out); n > 0 && c <= out[n-1].hi+1 {
			if c > out[n-1].hi {
				out[n-1].hi = c
			}
			continue
		}
		out = append(out, rng{c, c})
	}
	return out
}

// source returns package ucd's tables.go: Version, a table per general
// category (categoryNames) from gc, and White_Space from ws.
func source(gc []string, ws []rng) ([]byte, error) {
	names := append([]string(nil), categoryNames...)
	sort.Strings(names)
	var b strings.Builder
	fmt.Fprintf(&b, "// Code generated by internal/ucd/internal/ucdgen from UCD %s; DO NOT EDIT.\n\n", version)
	b.WriteString("package ucd\n\nimport \"unicode\"\n\n")
	b.WriteString("// Version is the Unicode version of the tables here.\n")
	fmt.Fprintf(&b, "const Version = %q\n\n", version)
	b.WriteString("var categories = map[string]*unicode.RangeTable{\n")
	for _, name := range names {
		fmt.Fprintf(&b, "\t%q: category%s,\n", name, name)
	}
	b.WriteString("}\n\n")
	b.WriteString("var properties = map[string]*unicode.RangeTable{\n\t\"White_Space\": propertyWhiteSpace,\n}\n\n")
	for _, name := range names {
		rs := categoryRanges(gc, name)
		if len(rs) == 0 {
			return nil, fmt.Errorf("%s: no code points", name)
		}
		b.WriteString(table("category"+name, rs))
	}
	if len(ws) == 0 {
		return nil, errors.New("White_Space: no code points")
	}
	b.WriteString(table("propertyWhiteSpace", ws))
	return format.Source([]byte(b.String()))
}

// table returns the Go declaration of a unicode.RangeTable named name holding
// rs: 16-bit ranges, then 32-bit ones, and LatinOffset the number of 16-bit
// ranges within Latin-1.
func table(name string, rs []rng) string {
	var r16, r32 strings.Builder
	latin := 0
	for _, r := range rs {
		switch {
		case r.hi <= 0xFFFF:
			fmt.Fprintf(&r16, "\t\t{Lo: 0x%04x, Hi: 0x%04x, Stride: 1},\n", r.lo, r.hi)
			if r.hi <= 0xFF {
				latin++
			}
		case r.lo > 0xFFFF:
			fmt.Fprintf(&r32, "\t\t{Lo: 0x%x, Hi: 0x%x, Stride: 1},\n", r.lo, r.hi)
		default:
			fmt.Fprintf(&r16, "\t\t{Lo: 0x%04x, Hi: 0xffff, Stride: 1},\n", r.lo)
			fmt.Fprintf(&r32, "\t\t{Lo: 0x10000, Hi: 0x%x, Stride: 1},\n", r.hi)
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "var %s = &unicode.RangeTable{\n", name)
	if r16.Len() > 0 {
		fmt.Fprintf(&b, "\tR16: []unicode.Range16{\n%s\t},\n", r16.String())
	}
	if r32.Len() > 0 {
		fmt.Fprintf(&b, "\tR32: []unicode.Range32{\n%s\t},\n", r32.String())
	}
	fmt.Fprintf(&b, "\tLatinOffset: %d,\n}\n\n", latin)
	return b.String()
}
