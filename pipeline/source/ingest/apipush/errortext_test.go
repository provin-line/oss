package apipush_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/provin-line/oss/pipeline/internal/pipeexcerpt"
)

// errReader fails every read with err's text.
type errReader struct{ text string }

func (r errReader) Read([]byte) (int, error) { return 0, readErr(r.text) }

type readErr string

func (e readErr) Error() string { return string(e) }

// A push the handler answers 400 gets a text within pipeexcerpt.TextLimit
// bytes of UTF-8, however long the error it names: a body that does not
// decode as strict JSON, and a body whose read fails. The handler bounds it
// itself, whatever server it is mounted in.
func TestPush_BadRequestAnswersWithinTheLimit(t *testing.T) {
	h := newHandler(t, &stubPublisher{}, 4<<20)
	long := strings.Repeat("ab\n\xff", 64<<10)
	for _, c := range []struct {
		name string
		req  *http.Request
	}{
		{"strict JSON", httptest.NewRequest(http.MethodPost, "/push", strings.NewReader(`{"a":1} `+strings.Repeat("9", 1<<20)))},
		{"body read", httptest.NewRequest(http.MethodPost, "/push", errReader{long})},
	} {
		c.req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, c.req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: status %d, want 400", c.name, rec.Code)
		}
		body := strings.TrimSuffix(rec.Body.String(), "\n")
		if len(body) > pipeexcerpt.TextLimit || !utf8.ValidString(body) {
			t.Errorf("%s: answer of %d bytes (UTF-8: %v): %.80q", c.name, len(body), utf8.ValidString(body), body)
		}
	}
}
