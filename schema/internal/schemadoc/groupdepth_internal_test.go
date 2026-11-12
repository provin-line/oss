package schemadoc

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// TestMain runs the package's tests at the default bound, whatever the
// environment sets, but for TestGroupDepthHelper, which reports the bound the
// environment sets.
func TestMain(m *testing.M) {
	if os.Getenv(groupDepthHelperEnv) == "" {
		maxGroupDepth = defaultMaxGroupDepth
	}
	os.Exit(m.Run())
}

// The environment's setting is unset or empty for the default, 8, or a
// decimal integer from 1 to 32; anything else is an error naming the
// variable, the value and the range.
func TestParseMaxGroupDepth(t *testing.T) {
	// The package reads the setting as it is initialized, before go test
	// records what a test reads; reading it here keys go test's cache on it.
	os.LookupEnv(maxGroupDepthEnv)
	if defaultMaxGroupDepth != 8 || maxGroupDepthCeiling != 32 {
		t.Fatalf("default %d, ceiling %d; want 8 and 32", defaultMaxGroupDepth, maxGroupDepthCeiling)
	}
	for _, c := range []struct {
		value string
		set   bool
		want  int
	}{
		{"", false, 8},
		{"", true, 8},
		{"1", true, 1},
		{"8", true, 8},
		{"08", true, 8},
		{"16", true, 16},
		{"32", true, 32},
		{"0", true, 0},
		{"33", true, 0},
		{"-1", true, 0},
		{"+8", true, 0},
		{" 8", true, 0},
		{"8 ", true, 0},
		{"abc", true, 0},
		{"8.0", true, 0},
		{"99999999999999999999", true, 0},
	} {
		got, err := parseMaxGroupDepth(c.value, c.set)
		if c.want != 0 {
			if err != nil || got != c.want {
				t.Errorf("%q (set %v) = %d, %v; want %d", c.value, c.set, got, err, c.want)
			}
			continue
		}
		if err == nil {
			t.Errorf("%q = %d, want an error", c.value, got)
			continue
		}
		for _, part := range []string{maxGroupDepthEnv, strconv.Quote(c.value), "1 to 32"} {
			if !strings.Contains(err.Error(), part) {
				t.Errorf("%q: %v, want it to name %s", c.value, err, part)
			}
		}
	}
}

// groupDepthHelperEnv makes TestGroupDepthHelper run: the tests below run it
// in a process of their own, with the setting they give.
const groupDepthHelperEnv = "SCHEMADOC_GROUP_DEPTH_HELPER"

// TestGroupDepthHelper prints the bound in force and how a schema whose
// pattern's groups nest that deep, and one deeper, compile.
func TestGroupDepthHelper(t *testing.T) {
	if os.Getenv(groupDepthHelperEnv) == "" {
		t.Skip("run by the tests of the setting, in a process of its own")
	}
	fmt.Printf("bound %d\n", maxGroupDepth)
	for _, d := range []int{maxGroupDepth, maxGroupDepth + 1} {
		_, err := Compile([]byte(`{"pattern":"` + strings.Repeat("(", d) + "a" + strings.Repeat(")", d) + `"}`))
		fmt.Printf("depth %d: %v\n", d, err)
	}
}

// runGroupDepthHelper runs TestGroupDepthHelper in a process of its own,
// with the setting unset when setting is nil.
func runGroupDepthHelper(t *testing.T, setting *string) (string, error) {
	t.Helper()
	env := []string{groupDepthHelperEnv + "=1"}
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, maxGroupDepthEnv+"=") {
			env = append(env, kv)
		}
	}
	if setting != nil {
		env = append(env, maxGroupDepthEnv+"="+*setting)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestGroupDepthHelper$", "-test.count=1", "-test.v")
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// Unset or empty, the bound is 8: a pattern whose groups nest 8 deep
// compiles, and one 9 deep is refused.
func TestMaxGroupDepth_DefaultsTo8(t *testing.T) {
	empty := ""
	for name, setting := range map[string]*string{"unset": nil, "empty": &empty} {
		out, err := runGroupDepthHelper(t, setting)
		if err != nil {
			t.Fatalf("%s: %v\n%s", name, err, out)
		}
		for _, want := range []string{"bound 8\n", "depth 8: <nil>\n", "depth 9: ", "regexp: its groups nest more than 8 deep"} {
			if !strings.Contains(out, want) {
				t.Errorf("%s: output lacks %q:\n%s", name, want, out)
			}
		}
	}
}

// Set, the bound is read at the start: at 16, a pattern 16 deep compiles,
// and one 17 deep is refused.
func TestMaxGroupDepth_SetByTheEnvironment(t *testing.T) {
	setting := "16"
	out, err := runGroupDepthHelper(t, &setting)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, want := range []string{"bound 16\n", "depth 16: <nil>\n", "regexp: its groups nest more than 16 deep"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

// Out of range or malformed, the setting stops the package's initialization:
// a program that imports it does not start, and says why.
func TestMaxGroupDepth_ABadSettingStopsTheStart(t *testing.T) {
	for _, setting := range []string{"0", "33", "abc"} {
		out, err := runGroupDepthHelper(t, &setting)
		if err == nil {
			t.Errorf("%q: the program started:\n%s", setting, out)
			continue
		}
		if strings.Contains(out, "bound ") {
			t.Errorf("%q: the helper ran:\n%s", setting, out)
		}
		for _, want := range []string{"panic", maxGroupDepthEnv, strconv.Quote(setting), "1 to 32"} {
			if !strings.Contains(out, want) {
				t.Errorf("%q: output lacks %q:\n%s", setting, want, out)
			}
		}
	}
}

// atMaxGroupDepth sets maxGroupDepth to d for the rest of the test.
func atMaxGroupDepth(t *testing.T, d int) {
	t.Helper()
	prev := maxGroupDepth
	maxGroupDepth = d
	t.Cleanup(func() { maxGroupDepth = prev })
}
