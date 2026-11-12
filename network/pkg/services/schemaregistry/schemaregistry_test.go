package schemaregistry_test

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/network/pkg/services/schemaregistry"
	"github.com/provin-line/oss/network/pkg/services/schemaregistry/store"
	"github.com/provin-line/oss/network/pkg/services/schemaregistry/store/yamlstore"
)

var validBody = []byte(`{"type":"object","required":["reading"],"properties":{"reading":{"type":"number"}}}`)

var versionRE = regexp.MustCompile(`^2026-06-14-[0-9a-f]{16}$`)

func fixedClock() func() time.Time {
	return func() time.Time { return time.Date(2026, 6, 14, 9, 0, 0, 0, time.UTC) }
}

func newService(t *testing.T) *schemaregistry.Service {
	t.Helper()
	return schemaregistry.New(yamlstore.New(t.TempDir()), schemaregistry.WithClock(fixedClock()))
}

func TestRegister_AssignsContentAddressedVersion(t *testing.T) {
	svc := newService(t)
	sc, err := svc.Register(context.Background(), "reading", "JsonSchema", validBody, "")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if !versionRE.MatchString(sc.Version) {
		t.Errorf("version %q does not match YYYY-MM-DD-{16hex}", sc.Version)
	}
	if sc.Name != "reading" || sc.SchemaFormat != "JsonSchema" {
		t.Errorf("fields not set: %+v", sc)
	}
}

func TestRegister_IdempotentWithinDay(t *testing.T) {
	svc := newService(t)
	a, err := svc.Register(context.Background(), "reading", "JsonSchema", validBody, "")
	if err != nil {
		t.Fatalf("first Register: %v", err)
	}
	b, err := svc.Register(context.Background(), "reading", "JsonSchema", validBody, "")
	if err != nil {
		t.Fatalf("second Register: %v", err)
	}
	if a.Version != b.Version {
		t.Errorf("idempotency broken: %q != %q", a.Version, b.Version)
	}
	all, err := svc.List(context.Background(), "reading", true, true)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 1 {
		t.Errorf("idempotent re-register created %d versions, want 1", len(all))
	}
}

// Pins the documented wire contract: the version hash is SHA-256 over
// length-prefixed (format, body, prerelease) in that order. An independent
// recompute must match the service — a reorder or a dropped length prefix
// (cross-implementation hash divergence) breaks this.
func TestRegister_VersionMatchesDocumentedHashRecipe(t *testing.T) {
	svc := newService(t)
	sc, err := svc.Register(context.Background(), "reading", "JsonSchema", validBody, "rc1")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	h := sha256.New()
	for _, f := range [][]byte{[]byte("JsonSchema"), validBody, []byte("rc1")} {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(f)))
		h.Write(n[:])
		h.Write(f)
	}
	want := "2026-06-14-" + hex.EncodeToString(h.Sum(nil))[:16]
	if sc.Version != want {
		t.Errorf("version %q does not match the documented recipe %q", sc.Version, want)
	}
}

// Re-registering content that was since deprecated is idempotent success and
// returns the existing (deprecated) record — deprecation has no inverse.
func TestRegister_DeprecatedContentReRegister_ReturnsDeprecated(t *testing.T) {
	svc := newService(t)
	first, err := svc.Register(context.Background(), "reading", "JsonSchema", validBody, "")
	if err != nil {
		t.Fatalf("first Register: %v", err)
	}
	if err := svc.Deprecate(context.Background(), "reading", first.Version); err != nil {
		t.Fatalf("Deprecate: %v", err)
	}
	again, err := svc.Register(context.Background(), "reading", "JsonSchema", validBody, "")
	if err != nil {
		t.Fatalf("re-Register after deprecate: %v", err)
	}
	if again.Version != first.Version {
		t.Errorf("re-register changed version: %q != %q", again.Version, first.Version)
	}
	if !again.Deprecated {
		t.Error("re-registering deprecated content must return the deprecated record (no revival)")
	}
}

func TestRegister_PrereleaseYieldsDistinctVersion(t *testing.T) {
	svc := newService(t)
	stable, err := svc.Register(context.Background(), "reading", "JsonSchema", validBody, "")
	if err != nil {
		t.Fatalf("stable Register: %v", err)
	}
	pre, err := svc.Register(context.Background(), "reading", "JsonSchema", validBody, "rc1")
	if err != nil {
		t.Fatalf("prerelease Register: %v", err)
	}
	if stable.Version == pre.Version {
		t.Errorf("same body+different prerelease must differ: both %q", stable.Version)
	}
}

func TestRegister_InvalidArguments(t *testing.T) {
	svc := newService(t)
	cases := map[string]struct {
		name, format string
		body         []byte
	}{
		"empty name":   {"", "JsonSchema", validBody},
		"empty format": {"reading", "", validBody},
		"empty body":   {"reading", "JsonSchema", nil},
	}
	for label, c := range cases {
		if _, err := svc.Register(context.Background(), c.name, c.format, c.body, ""); !errors.Is(err, schemaregistry.ErrInvalidArgument) {
			t.Errorf("%s: got %v, want ErrInvalidArgument", label, err)
		}
	}
}

func TestRegister_UnsupportedFormat(t *testing.T) {
	svc := newService(t)
	if _, err := svc.Register(context.Background(), "reading", "Cddl", validBody, ""); !errors.Is(err, schemaregistry.ErrUnsupportedFormat) {
		t.Errorf("got %v, want ErrUnsupportedFormat", err)
	}
}

// D2: a body that is not a valid, self-contained JsonSchema is rejected at
// Register and never enters the registry.
func TestRegister_RejectsInvalidSchemaBody(t *testing.T) {
	svc := newService(t)
	cases := map[string][]byte{
		"structurally invalid": []byte(`{"type":123}`),
		"external $ref":        []byte(`{"$ref":"file:///etc/passwd"}`),
		"duplicate key":        []byte(`{"type":"object","type":"array"}`),
	}
	for label, body := range cases {
		if _, err := svc.Register(context.Background(), "reading", "JsonSchema", body, ""); !errors.Is(err, schemaregistry.ErrInvalidArgument) {
			t.Errorf("%s: got %v, want ErrInvalidArgument", label, err)
		}
	}
	all, err := svc.List(context.Background(), "reading", true, true)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 0 {
		t.Errorf("rejected schemas leaked into the registry: %d", len(all))
	}
}

// schemaOfSize is a valid JsonSchema exactly n bytes long.
func schemaOfSize(t *testing.T, n int) []byte {
	t.Helper()
	const head, tail = `{"type":"object","description":"`, `"}`
	pad := n - len(head) - len(tail)
	if pad < 0 {
		t.Fatalf("no schema of %d bytes", n)
	}
	return []byte(head + strings.Repeat("x", pad) + tail)
}

// A schema body is at most 1 MiB: one of exactly that size is admitted, one
// byte more is refused and nothing is stored.
func TestRegister_BodyIsAtMostOneMiB(t *testing.T) {
	const bound = 1 << 20
	svc := newService(t)
	if _, err := svc.Register(context.Background(), "reading", "JsonSchema", schemaOfSize(t, bound), ""); err != nil {
		t.Fatalf("a %d-byte schema: %v", bound, err)
	}

	svc = newService(t)
	if _, err := svc.Register(context.Background(), "reading", "JsonSchema", schemaOfSize(t, bound+1), ""); !errors.Is(err, schemaregistry.ErrInvalidArgument) {
		t.Fatalf("a %d-byte schema: got %v, want ErrInvalidArgument", bound+1, err)
	}
	all, err := svc.List(context.Background(), "reading", true, true)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 0 {
		t.Errorf("a refused schema was stored: %d", len(all))
	}
}

// The size is checked before the body is read as a schema: an oversized body
// that is not JSON is refused for its size.
func TestRegister_SizeIsCheckedBeforeTheBodyIsRead(t *testing.T) {
	svc := newService(t)
	body := []byte(strings.Repeat("{", 1<<20+1))
	_, err := svc.Register(context.Background(), "reading", "JsonSchema", body, "")
	if !errors.Is(err, schemaregistry.ErrInvalidArgument) || !strings.Contains(err.Error(), "beyond the bound of 1048576") {
		t.Errorf("got %v, want ErrInvalidArgument naming the size bound", err)
	}
}

func TestGet_NotFound(t *testing.T) {
	svc := newService(t)
	if _, err := svc.Get(context.Background(), "reading", "2026-06-14-deadbeefdeadbeef"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("got %v, want store.ErrNotFound", err)
	}
}

func TestDeprecate_ThenGetShowsFlag(t *testing.T) {
	svc := newService(t)
	sc, err := svc.Register(context.Background(), "reading", "JsonSchema", validBody, "")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := svc.Deprecate(context.Background(), "reading", sc.Version); err != nil {
		t.Fatalf("Deprecate: %v", err)
	}
	got, err := svc.Get(context.Background(), "reading", sc.Version)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.Deprecated {
		t.Error("Deprecate flag not set")
	}
}

func TestDeprecate_NotFound(t *testing.T) {
	svc := newService(t)
	if err := svc.Deprecate(context.Background(), "reading", "2026-06-14-deadbeefdeadbeef"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("got %v, want store.ErrNotFound", err)
	}
}
