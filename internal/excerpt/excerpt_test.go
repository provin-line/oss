package excerpt_test

import (
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/provin-line/oss/internal/excerpt"
)

// A text that fits is written whole; a longer one is its head and its length.
func TestOf(t *testing.T) {
	for _, c := range []struct {
		s, want string
		max     int
		cut     bool
	}{
		{"short", "short", 40, false},
		{strings.Repeat("a", 40), strings.Repeat("a", 40), 40, false},
		{strings.Repeat("a", 41), strings.Repeat("a", 26) + "… (41 bytes)", 40, true},
		{strings.Repeat("é", 100), strings.Repeat("é", 12) + "… (200 bytes)", 40, true},
	} {
		got, cut := excerpt.Of(c.s, c.max)
		if got != c.want || cut != c.cut {
			t.Errorf("Of(%.20q…, %d) = %q, %v; want %q, %v", c.s, c.max, got, cut, c.want, c.cut)
		}
	}
}

// A name that fits is quoted whole; a longer one is its head quoted and its
// length after it, escapes counted.
func TestQuoted(t *testing.T) {
	for _, c := range []struct {
		s, want string
		max     int
	}{
		{"name", `"name"`, 40},
		{strings.Repeat("a", 38), `"` + strings.Repeat("a", 38) + `"`, 40},
		{strings.Repeat("a", 39), `"` + strings.Repeat("a", 24) + `"… (39 bytes)`, 40},
		{strings.Repeat("\x01", 100), `"` + strings.Repeat(`\x01`, 5) + `"… (100 bytes)`, 40},
		{`say "hi"` + strings.Repeat("!", 50), `"say \"hi\"` + strings.Repeat("!", 14) + `"… (58 bytes)`, 40},
	} {
		if got := excerpt.Quoted(c.s, c.max); got != c.want {
			t.Errorf("Quoted(%.20q…, %d) = %q; want %q", c.s, c.max, got, c.want)
		}
	}
}

// Text that is not UTF-8 is written with each run of such bytes replaced by
// U+FFFD, so nothing written ends in a part of a character; N stays the
// length of the text given, even where the replacements make the written
// text the longer one.
func TestTextThatIsNotUTF8(t *testing.T) {
	if got, cut := excerpt.Of("a\xffb", 40); got != "a�b" || cut {
		t.Errorf("Of = %q, %v", got, cut)
	}
	if got := excerpt.Quoted("a\xffb", 40); got != `"a`+"�"+`b"` {
		t.Errorf("Quoted = %q", got)
	}
	runs := strings.Repeat("\xffa", 20) // 40 bytes, 80 once replaced
	got, cut := excerpt.Of(runs, 40)
	if !cut || !utf8.ValidString(got) || len(got) > 40 || !strings.HasSuffix(got, "… (40 bytes)") {
		t.Errorf("Of(runs) = %q, %v", got, cut)
	}
	cutInside := "é" + strings.Repeat("\xc3", 60) // a lead byte without its continuation, repeated
	if got, _ := excerpt.Of(cutInside, 40); !utf8.ValidString(got) || len(got) > 40 {
		t.Errorf("Of(lead bytes) = %q", got)
	}
}

// Whatever the text and the limit (from MinLimit), what is written fits it, in
// valid UTF-8; a cut text is a head of the text given (once made valid) and
// ends with the length of the text given.
func FuzzOfAndQuoted(f *testing.F) {
	for _, s := range []string{"", "a", strings.Repeat("é", 300), strings.Repeat("\xf0\x9f\x98\x80", 40), "\xff\xfe\xfd", strings.Repeat("\x01\"\\", 50), "a\xc3"} {
		f.Add(s, uint16(0))
		f.Add(s, uint16(7))
	}
	f.Fuzz(func(t *testing.T, s string, extra uint16) {
		max := excerpt.MinLimit + int(extra%200)
		got, cut := excerpt.Of(s, max)
		valid := strings.ToValidUTF8(s, "�")
		if len(got) > max || !utf8.ValidString(got) {
			t.Fatalf("Of(%q, %d) = %q: %d bytes", s, max, got, len(got))
		}
		if tail := fmt.Sprintf("… (%d bytes)", len(s)); cut != (got != valid) || cut && (!strings.HasSuffix(got, tail) || !strings.HasPrefix(valid, strings.TrimSuffix(got, tail))) {
			t.Fatalf("Of(%q, %d) = %q, %v", s, max, got, cut)
		}
		q := excerpt.Quoted(s, max)
		if len(q) > max || !utf8.ValidString(q) {
			t.Fatalf("Quoted(%q, %d) = %q: %d bytes", s, max, q, len(q))
		}
		last := strings.LastIndex(q, `"`) // the tail holds no quote
		head, err := strconv.Unquote(q[:last+1])
		rest := q[last+1:]
		if !strings.HasPrefix(q, `"`) || err != nil || !strings.HasPrefix(valid, head) || (rest == "") != (head == valid) || rest != "" && rest != fmt.Sprintf("… (%d bytes)", len(s)) {
			t.Fatalf("Quoted(%q, %d) = %q", s, max, q)
		}
	})
}

// A limit under MinLimit is its caller's error: every function panics on it,
// whatever the text, even one that would fit.
func TestALimitUnderMinLimitPanics(t *testing.T) {
	for name, f := range map[string]func(){
		"Of":             func() { excerpt.Of("", excerpt.MinLimit-1) },
		"Quoted":         func() { excerpt.Quoted("", excerpt.MinLimit-1) },
		"OfError":        func() { excerpt.OfError(errors.New(""), excerpt.MinLimit-1) },
		"OfError of nil": func() { excerpt.OfError(nil, excerpt.MinLimit-1) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s did not panic", name)
				}
			}()
			f()
		}()
	}
	excerpt.Of(strings.Repeat("a", 1000), excerpt.MinLimit)
}

// An error whose text fits as it is is returned as it is; one whose text is
// changed (cut, or made UTF-8) is told by what Of writes of it, and still
// wraps the error it tells.
func TestOfError(t *testing.T) {
	short := errors.New("short")
	if got := excerpt.OfError(short, 40); got != short {
		t.Errorf("Error(short) = %v", got)
	}
	if excerpt.OfError(nil, 40) != nil {
		t.Error("Error(nil) is not nil")
	}
	invalid := errors.New("a\xffb") // fits, but is not UTF-8
	if got := excerpt.OfError(invalid, 40); got.Error() != "a\uFFFDb" || !errors.Is(got, invalid) {
		t.Errorf("Error(invalid) = %q", got)
	}
	long := fmt.Errorf("reading %s: %w", strings.Repeat("a", 100), fs.ErrNotExist)
	got := excerpt.OfError(long, 40)
	if got.Error() != "reading "+strings.Repeat("a", 17)+"… (129 bytes)" || !errors.Is(got, long) || !errors.Is(got, fs.ErrNotExist) {
		t.Errorf("Error(long) = %q", got)
	}
}
