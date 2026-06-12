// Package hoconconfig_test exercises the three-layer HOCON configuration loader.
// Tests are written to document discovered library behaviours and verify the
// contract defined in README.md / README.ja.md.
package hoconconfig_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/provin-line/oss/hoconconfig"
)

// regSeq is incremented once per RegisterPackageReference call so that each
// registration uses a unique name. This prevents ErrDuplicateReference when
// the test binary is run with -count>1 (the package-level registry persists
// across runs in the same process).
var regSeq atomic.Int64

func uniq(base string) string {
	return fmt.Sprintf("%s-%d", base, regSeq.Add(1))
}

// ─────────────────────────────────────────────────────────────────────────────
// helpers
// ─────────────────────────────────────────────────────────────────────────────

// writeFile creates a file at dir/name with the given content.
func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writeFile %s: %v", path, err)
	}
	return path
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Reference-only load
// ─────────────────────────────────────────────────────────────────────────────

func TestLoadReferenceOnly(t *testing.T) {
	hoconconfig.RegisterPackageReference(uniq("pkg-ref-only"),
		`provin.test.ref-only { key = "hello" }`)

	cfg, err := hoconconfig.Load(t.TempDir(), "")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	got, err := cfg.String("provin.test.ref-only.key")
	if err != nil {
		t.Fatalf("String: %v", err)
	}
	if got != "hello" {
		t.Errorf("got %q, want %q", got, "hello")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Application layer overrides reference
// ─────────────────────────────────────────────────────────────────────────────

func TestApplicationOverridesReference(t *testing.T) {
	hoconconfig.RegisterPackageReference(uniq("pkg-app-override"),
		`provin.test.app-override { level = 1 }`)

	dir := t.TempDir()
	cfgDir := filepath.Join(dir, "config")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, cfgDir, "application.conf",
		`provin.test.app-override { level = 2 }`)

	cfg, err := hoconconfig.Load(dir, "")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	got, err := cfg.Int("provin.test.app-override.level")
	if err != nil {
		t.Fatalf("Int: %v", err)
	}
	if got != 2 {
		t.Errorf("got %d, want 2", got)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Overlay layer overrides application
// ─────────────────────────────────────────────────────────────────────────────

func TestOverlayOverridesApplication(t *testing.T) {
	hoconconfig.RegisterPackageReference(uniq("pkg-overlay"),
		`provin.test.overlay { level = 1 }`)

	dir := t.TempDir()
	cfgDir := filepath.Join(dir, "config")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, cfgDir, "application.conf",
		`provin.test.overlay { level = 2 }`)

	overlayFile := writeFile(t, t.TempDir(), "overlay.conf",
		`provin.test.overlay { level = 3 }`)
	t.Setenv("TEST_OVERLAY_ENV", overlayFile)

	cfg, err := hoconconfig.Load(dir, "TEST_OVERLAY_ENV")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	got, err := cfg.Int("provin.test.overlay.level")
	if err != nil {
		t.Fatalf("Int: %v", err)
	}
	if got != 3 {
		t.Errorf("got %d, want 3", got)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Precedence chain: 3 layers, all present
// ─────────────────────────────────────────────────────────────────────────────

func TestPrecedenceChain(t *testing.T) {
	// a is overridden at every layer; b only in reference; c only in overlay.
	hoconconfig.RegisterPackageReference(uniq("pkg-chain"),
		`provin.test.chain { a = 1, b = "ref-b" }`)

	dir := t.TempDir()
	cfgDir := filepath.Join(dir, "config")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, cfgDir, "application.conf",
		`provin.test.chain { a = 2 }`)

	overlayFile := writeFile(t, t.TempDir(), "overlay.conf",
		`provin.test.chain { a = 3, c = "overlay-c" }`)
	t.Setenv("TEST_CHAIN_ENV", overlayFile)

	cfg, err := hoconconfig.Load(dir, "TEST_CHAIN_ENV")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if a, err := cfg.Int("provin.test.chain.a"); err != nil || a != 3 {
		t.Errorf("a: got (%d, %v), want (3, nil)", a, err)
	}
	if b, err := cfg.String("provin.test.chain.b"); err != nil || b != "ref-b" {
		t.Errorf("b: got (%q, %v), want (\"ref-b\", nil)", b, err)
	}
	if c, err := cfg.String("provin.test.chain.c"); err != nil || c != "overlay-c" {
		t.Errorf("c: got (%q, %v), want (\"overlay-c\", nil)", c, err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Missing application.conf is not an error
// ─────────────────────────────────────────────────────────────────────────────

func TestMissingApplicationConfIsOK(t *testing.T) {
	hoconconfig.RegisterPackageReference(uniq("pkg-no-app"),
		`provin.test.no-app { key = "ok" }`)

	// appDir has no config/ subdirectory at all.
	cfg, err := hoconconfig.Load(t.TempDir(), "")
	if err != nil {
		t.Fatalf("Load should succeed without application.conf: %v", err)
	}

	v, err := cfg.String("provin.test.no-app.key")
	if err != nil || v != "ok" {
		t.Errorf("got (%q, %v), want (\"ok\", nil)", v, err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Overlay env set but file unreadable → error (fail loud)
// ─────────────────────────────────────────────────────────────────────────────

func TestOverlayUnreadableIsError(t *testing.T) {
	hoconconfig.RegisterPackageReference(uniq("pkg-bad-overlay"),
		`provin.test.bad-overlay { key = "x" }`)

	t.Setenv("TEST_BAD_OVERLAY", "/nonexistent/path/overlay.conf")

	_, err := hoconconfig.Load(t.TempDir(), "TEST_BAD_OVERLAY")
	if err == nil {
		t.Fatal("expected error when overlay file is unreadable")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. Substitution across layers
// ─────────────────────────────────────────────────────────────────────────────

func TestSubstitutionAcrossLayers(t *testing.T) {
	// reference defines the base key; overlay references it via substitution.
	// After single-parse resolution the substitution ${...} becomes the
	// referenced value's type, so String() can handle it normally.
	hoconconfig.RegisterPackageReference(uniq("pkg-subst"),
		`provin.test.subst { base = "pipeline-42" }`)

	overlayFile := writeFile(t, t.TempDir(), "overlay.conf",
		`provin.test.subst { derived = ${provin.test.subst.base} }`)
	t.Setenv("TEST_SUBST_ENV", overlayFile)

	cfg, err := hoconconfig.Load(t.TempDir(), "TEST_SUBST_ENV")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	got, err := cfg.String("provin.test.subst.derived")
	if err != nil {
		t.Fatalf("String: %v", err)
	}
	if got != "pipeline-42" {
		t.Errorf("got %q, want %q", got, "pipeline-42")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. Typed accessor: String — happy path and missing-key error
// ─────────────────────────────────────────────────────────────────────────────

func TestStringAccessor(t *testing.T) {
	hoconconfig.RegisterPackageReference(uniq("pkg-str"),
		`provin.test.str { present = "value" }`)

	cfg, err := hoconconfig.Load(t.TempDir(), "")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// happy path
	v, err := cfg.String("provin.test.str.present")
	if err != nil || v != "value" {
		t.Errorf("String happy: got (%q, %v)", v, err)
	}

	// missing key
	_, err = cfg.String("provin.test.str.absent")
	if !errors.Is(err, hoconconfig.ErrMissingKey) {
		t.Errorf("String missing: want ErrMissingKey, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. Typed accessor: Int — happy, missing, type-mismatch
// ─────────────────────────────────────────────────────────────────────────────

func TestIntAccessor(t *testing.T) {
	hoconconfig.RegisterPackageReference(uniq("pkg-int"),
		`provin.test.int { n = 42, s = "notanumber" }`)

	cfg, err := hoconconfig.Load(t.TempDir(), "")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// happy path
	n, err := cfg.Int("provin.test.int.n")
	if err != nil || n != 42 {
		t.Errorf("Int happy: got (%d, %v)", n, err)
	}

	// missing
	_, err = cfg.Int("provin.test.int.absent")
	if !errors.Is(err, hoconconfig.ErrMissingKey) {
		t.Errorf("Int missing: want ErrMissingKey, got %v", err)
	}

	// type mismatch: string value read as int
	_, err = cfg.Int("provin.test.int.s")
	if !errors.Is(err, hoconconfig.ErrTypeMismatch) {
		t.Errorf("Int mismatch: want ErrTypeMismatch, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. Typed accessor: Bool — happy, missing, type-mismatch
// ─────────────────────────────────────────────────────────────────────────────

func TestBoolAccessor(t *testing.T) {
	hoconconfig.RegisterPackageReference(uniq("pkg-bool"),
		`provin.test.bool { flag = true, num = 42 }`)

	cfg, err := hoconconfig.Load(t.TempDir(), "")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// happy
	b, err := cfg.Bool("provin.test.bool.flag")
	if err != nil || !b {
		t.Errorf("Bool happy: got (%v, %v)", b, err)
	}

	// missing
	_, err = cfg.Bool("provin.test.bool.absent")
	if !errors.Is(err, hoconconfig.ErrMissingKey) {
		t.Errorf("Bool missing: want ErrMissingKey, got %v", err)
	}

	// type mismatch: int is not a bool
	_, err = cfg.Bool("provin.test.bool.num")
	if !errors.Is(err, hoconconfig.ErrTypeMismatch) {
		t.Errorf("Bool mismatch: want ErrTypeMismatch, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 11. Typed accessor: Duration — happy path ("250ms"), missing, type-mismatch
// ─────────────────────────────────────────────────────────────────────────────

func TestDurationAccessor(t *testing.T) {
	hoconconfig.RegisterPackageReference(uniq("pkg-dur"),
		`provin.test.dur { interval = 250 ms, notdur = "hello" }`)

	cfg, err := hoconconfig.Load(t.TempDir(), "")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// happy path — library parses "250 ms" as Duration(250ms)
	d, err := cfg.Duration("provin.test.dur.interval")
	if err != nil {
		t.Fatalf("Duration happy: %v", err)
	}
	if d != 250*time.Millisecond {
		t.Errorf("Duration: got %v, want 250ms", d)
	}

	// missing
	_, err = cfg.Duration("provin.test.dur.absent")
	if !errors.Is(err, hoconconfig.ErrMissingKey) {
		t.Errorf("Duration missing: want ErrMissingKey, got %v", err)
	}

	// type mismatch: plain string is not a Duration
	_, err = cfg.Duration("provin.test.dur.notdur")
	if !errors.Is(err, hoconconfig.ErrTypeMismatch) {
		t.Errorf("Duration mismatch: want ErrTypeMismatch, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 12. Typed accessor: StringList — happy path, missing, type-mismatch
// ─────────────────────────────────────────────────────────────────────────────

func TestStringListAccessor(t *testing.T) {
	hoconconfig.RegisterPackageReference(uniq("pkg-list"),
		`provin.test.list { items = ["a", "b", "c"], scalar = "x" }`)

	cfg, err := hoconconfig.Load(t.TempDir(), "")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// happy path
	list, err := cfg.StringList("provin.test.list.items")
	if err != nil {
		t.Fatalf("StringList happy: %v", err)
	}
	if len(list) != 3 || list[0] != "a" || list[1] != "b" || list[2] != "c" {
		t.Errorf("StringList: got %v", list)
	}

	// missing
	_, err = cfg.StringList("provin.test.list.absent")
	if !errors.Is(err, hoconconfig.ErrMissingKey) {
		t.Errorf("StringList missing: want ErrMissingKey, got %v", err)
	}

	// type mismatch: scalar is not an array
	_, err = cfg.StringList("provin.test.list.scalar")
	if !errors.Is(err, hoconconfig.ErrTypeMismatch) {
		t.Errorf("StringList mismatch: want ErrTypeMismatch, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 13. Has — present and absent
// ─────────────────────────────────────────────────────────────────────────────

func TestHas(t *testing.T) {
	hoconconfig.RegisterPackageReference(uniq("pkg-has"),
		`provin.test.has { key = "v" }`)

	cfg, err := hoconconfig.Load(t.TempDir(), "")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if !cfg.Has("provin.test.has.key") {
		t.Error("Has: expected true for present key")
	}
	if cfg.Has("provin.test.has.missing") {
		t.Error("Has: expected false for absent key")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 14. Duplicate registration panics
// ─────────────────────────────────────────────────────────────────────────────

func TestDuplicateRegistrationPanics(t *testing.T) {
	name := uniq("pkg-dup")
	hoconconfig.RegisterPackageReference(name, `provin.dup { x = 1 }`)

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic on duplicate registration, got none")
		}
		// The panic value should wrap ErrDuplicateReference.
		err, ok := r.(error)
		if !ok {
			t.Fatalf("panic value is not an error: %v", r)
		}
		if !errors.Is(err, hoconconfig.ErrDuplicateReference) {
			t.Errorf("panic error: want ErrDuplicateReference, got %v", err)
		}
	}()

	hoconconfig.RegisterPackageReference(name, `provin.dup { x = 2 }`)
}

// ─────────────────────────────────────────────────────────────────────────────
// 15. Overlay env unset is not an error
// ─────────────────────────────────────────────────────────────────────────────

func TestOverlayEnvUnsetIsOK(t *testing.T) {
	hoconconfig.RegisterPackageReference(uniq("pkg-no-overlay"),
		`provin.test.no-overlay { key = "ok" }`)

	// overlayEnv is a non-empty name but the env var is not set.
	os.Unsetenv("TEST_UNSET_OVERLAY")

	cfg, err := hoconconfig.Load(t.TempDir(), "TEST_UNSET_OVERLAY")
	if err != nil {
		t.Fatalf("Load should succeed when overlay env var is unset: %v", err)
	}

	v, err := cfg.String("provin.test.no-overlay.key")
	if err != nil || v != "ok" {
		t.Errorf("got (%q, %v)", v, err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 16. Multiple registered references are all merged
// ─────────────────────────────────────────────────────────────────────────────

func TestMultipleReferences(t *testing.T) {
	hoconconfig.RegisterPackageReference(uniq("pkg-multi-a"),
		`provin.test.multi { a = "from-a" }`)
	hoconconfig.RegisterPackageReference(uniq("pkg-multi-b"),
		`provin.test.multi { b = "from-b" }`)

	cfg, err := hoconconfig.Load(t.TempDir(), "")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if v, err := cfg.String("provin.test.multi.a"); err != nil || v != "from-a" {
		t.Errorf("multi.a: got (%q, %v)", v, err)
	}
	if v, err := cfg.String("provin.test.multi.b"); err != nil || v != "from-b" {
		t.Errorf("multi.b: got (%q, %v)", v, err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// F1. StringList — URL and DID values round-trip without quote wrapping;
//     non-string array elements → ErrTypeMismatch.
// ─────────────────────────────────────────────────────────────────────────────

func TestStringListURLRoundTrip(t *testing.T) {
	hoconconfig.RegisterPackageReference(uniq("pkg-f1-url"),
		`provin.test.f1 { urls = ["nats://localhost:4222", "did:dplaax:a:b"] }`)

	cfg, err := hoconconfig.Load(t.TempDir(), "")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	list, err := cfg.StringList("provin.test.f1.urls")
	if err != nil {
		t.Fatalf("StringList URL: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("StringList URL: want 2 elements, got %d: %v", len(list), list)
	}
	if list[0] != "nats://localhost:4222" {
		t.Errorf("element 0: got %q, want %q", list[0], "nats://localhost:4222")
	}
	if list[1] != "did:dplaax:a:b" {
		t.Errorf("element 1: got %q, want %q", list[1], "did:dplaax:a:b")
	}
}

func TestStringListIntElementsTypeMismatch(t *testing.T) {
	hoconconfig.RegisterPackageReference(uniq("pkg-f1-int"),
		`provin.test.f1int { nums = [1, 2] }`)

	cfg, err := hoconconfig.Load(t.TempDir(), "")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	_, err = cfg.StringList("provin.test.f1int.nums")
	if !errors.Is(err, hoconconfig.ErrTypeMismatch) {
		t.Errorf("StringList int elements: want ErrTypeMismatch, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// F2. Scalar-parent lookup → ErrTypeMismatch (not panic); Has does not panic.
// ─────────────────────────────────────────────────────────────────────────────

func TestScalarParentNopanicString(t *testing.T) {
	hoconconfig.RegisterPackageReference(uniq("pkg-f2-str"),
		`provin.test.f2 { scalar = "x" }`)

	cfg, err := hoconconfig.Load(t.TempDir(), "")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	_, err = cfg.String("provin.test.f2.scalar.key")
	if !errors.Is(err, hoconconfig.ErrTypeMismatch) {
		t.Errorf("scalar parent String: want ErrTypeMismatch, got %v", err)
	}
}

func TestScalarParentNopanicHas(t *testing.T) {
	hoconconfig.RegisterPackageReference(uniq("pkg-f2-has"),
		`provin.test.f2has { scalar = "x" }`)

	cfg, err := hoconconfig.Load(t.TempDir(), "")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Must not panic; must return false.
	got := cfg.Has("provin.test.f2has.scalar.key")
	if got {
		t.Error("Has on scalar parent: want false, got true")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// F3. String round-trip — value with special chars survives without corruption.
// ─────────────────────────────────────────────────────────────────────────────

func TestStringSpecialCharsRoundTrip(t *testing.T) {
	hoconconfig.RegisterPackageReference(uniq("pkg-f3"),
		`provin.test.f3 { addr = "nats://h:4222 path" }`)

	cfg, err := hoconconfig.Load(t.TempDir(), "")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	got, err := cfg.String("provin.test.f3.addr")
	if err != nil {
		t.Fatalf("String special: %v", err)
	}
	const want = "nats://h:4222 path"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// F4. Present-but-null: Has → true; typed accessors → ErrTypeMismatch.
// ─────────────────────────────────────────────────────────────────────────────

func TestNullValueBehavior(t *testing.T) {
	hoconconfig.RegisterPackageReference(uniq("pkg-f4"),
		`provin.test.f4 { nullkey = null }`)

	cfg, err := hoconconfig.Load(t.TempDir(), "")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if !cfg.Has("provin.test.f4.nullkey") {
		t.Error("Has null key: want true, got false")
	}

	_, err = cfg.String("provin.test.f4.nullkey")
	if !errors.Is(err, hoconconfig.ErrTypeMismatch) {
		t.Errorf("String null: want ErrTypeMismatch, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// F5. go test -count=2: covered by the uniq() helper applied to all
//     RegisterPackageReference calls above. No additional test needed here;
//     the suite itself IS the test — run with -count=2 to verify.
// ─────────────────────────────────────────────────────────────────────────────
