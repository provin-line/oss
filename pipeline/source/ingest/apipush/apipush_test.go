package apipush_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/provin-line/oss/pipeline/source/ingest/apipush"
)

// stubPublisher records publishes and simulates broker health/failure.
type stubPublisher struct {
	published  [][]byte
	publishErr error
	healthy    bool
}

func (s *stubPublisher) Publish(data []byte) error {
	if s.publishErr != nil {
		return s.publishErr
	}
	s.published = append(s.published, data)
	return nil
}
func (s *stubPublisher) Healthy() bool { return s.healthy }
func (s *stubPublisher) Close() error  { return nil }

func newHandler(t *testing.T, p *stubPublisher, maxBytes int) http.Handler {
	t.Helper()
	h, err := apipush.New(apipush.Config{Publisher: p, MaxBodyBytes: maxBytes})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return h
}

func doPush(t *testing.T, h http.Handler, contentType, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/push", strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestNew_Validation(t *testing.T) {
	if _, err := apipush.New(apipush.Config{Publisher: nil, MaxBodyBytes: 1}); !errors.Is(err, apipush.ErrMissingPublisher) {
		t.Errorf("nil publisher: got %v, want ErrMissingPublisher", err)
	}
	if _, err := apipush.New(apipush.Config{Publisher: &stubPublisher{}, MaxBodyBytes: 0}); !errors.Is(err, apipush.ErrInvalidBodyCap) {
		t.Errorf("zero cap: got %v, want ErrInvalidBodyCap", err)
	}
	if _, err := apipush.New(apipush.Config{Publisher: &stubPublisher{}, MaxBodyBytes: -1}); !errors.Is(err, apipush.ErrInvalidBodyCap) {
		t.Errorf("negative cap: got %v, want ErrInvalidBodyCap", err)
	}
}

func TestPush_MethodGate(t *testing.T) {
	p := &stubPublisher{healthy: true}
	h := newHandler(t, p, 1<<20)
	for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(m, "/push", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /push: got %d, want 405", m, rec.Code)
		}
	}
	if len(p.published) != 0 {
		t.Errorf("method-gated requests published %d messages", len(p.published))
	}
}

func TestPush_ContentTypeGate(t *testing.T) {
	cases := []struct {
		ct   string
		want int
	}{
		{"application/json", http.StatusAccepted},
		{"application/json; charset=utf-8", http.StatusAccepted},
		{"text/plain", http.StatusUnsupportedMediaType},
		{"", http.StatusUnsupportedMediaType},
		{"application/", http.StatusUnsupportedMediaType},
	}
	for _, tc := range cases {
		p := &stubPublisher{healthy: true}
		h := newHandler(t, p, 1<<20)
		rec := doPush(t, h, tc.ct, `{"a":1}`)
		if rec.Code != tc.want {
			t.Errorf("Content-Type %q: got %d, want %d", tc.ct, rec.Code, tc.want)
		}
	}
}

func TestPush_OverCap413(t *testing.T) {
	p := &stubPublisher{healthy: true}
	h := newHandler(t, p, 16)
	rec := doPush(t, h, "application/json", `{"a":"`+strings.Repeat("x", 64)+`"}`)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("over-cap: got %d, want 413", rec.Code)
	}
	if len(p.published) != 0 {
		t.Error("over-cap body was published")
	}
}

// A chunked request (no Content-Length) must still be capped by the reader.
func TestPush_OverCap413_Chunked(t *testing.T) {
	p := &stubPublisher{healthy: true}
	handler := newHandler(t, p, 16)
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	body := io.NopCloser(strings.NewReader(`{"a":"` + strings.Repeat("x", 64) + `"}`))
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/push", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = -1 // force chunked transfer encoding
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("chunked POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("chunked over-cap: got %d, want 413", resp.StatusCode)
	}
}

func TestPush_EmptyBody400(t *testing.T) {
	p := &stubPublisher{healthy: true}
	h := newHandler(t, p, 1<<20)
	if rec := doPush(t, h, "application/json", ""); rec.Code != http.StatusBadRequest {
		t.Errorf("empty body: got %d, want 400", rec.Code)
	}
}

func TestPush_StrictJSONGate400(t *testing.T) {
	p := &stubPublisher{healthy: true}
	h := newHandler(t, p, 1<<20)
	for _, body := range []string{
		`{"a":1,"a":2}`, // duplicate key
		`{"a":1} trailing`,
		`not json`,
	} {
		if rec := doPush(t, h, "application/json", body); rec.Code != http.StatusBadRequest {
			t.Errorf("body %q: got %d, want 400", body, rec.Code)
		}
	}
	if len(p.published) != 0 {
		t.Errorf("malformed bodies published %d messages", len(p.published))
	}
}

func TestPush_PublishError503(t *testing.T) {
	p := &stubPublisher{healthy: true, publishErr: errors.New("broker gone")}
	h := newHandler(t, p, 1<<20)
	if rec := doPush(t, h, "application/json", `{"a":1}`); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("publish error: got %d, want 503", rec.Code)
	}
}

func TestPush_Success202(t *testing.T) {
	p := &stubPublisher{healthy: true}
	h := newHandler(t, p, 1<<20)
	body := `{"lot_id":"L-42","weight_kg":120}`
	rec := doPush(t, h, "application/json", body)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("got %d, want 202; body: %s", rec.Code, rec.Body.String())
	}
	if len(p.published) != 1 || string(p.published[0]) != body {
		t.Fatalf("published = %q, want the verbatim body", p.published)
	}
	var resp struct {
		PayloadHash string `json:"payload_hash"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response body: %v", err)
	}
	sum := sha256.Sum256([]byte(body))
	if want := "sha256:" + hex.EncodeToString(sum[:]); resp.PayloadHash != want {
		t.Errorf("payload_hash = %q, want %q", resp.PayloadHash, want)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("response Content-Type = %q, want application/json", ct)
	}
}

func TestHealth(t *testing.T) {
	p := &stubPublisher{healthy: true}
	h := newHandler(t, p, 1<<20)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("healthy: got %d, want 200", rec.Code)
	}

	p.healthy = false
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("unhealthy: got %d, want 503", rec.Code)
	}

	// health is GET-only.
	req = httptest.NewRequest(http.MethodPost, "/health", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /health: got %d, want 405", rec.Code)
	}
}

func TestUnknownRoute404(t *testing.T) {
	h := newHandler(t, &stubPublisher{healthy: true}, 1<<20)
	req := httptest.NewRequest(http.MethodGet, "/nope", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown route: got %d, want 404", rec.Code)
	}
}
