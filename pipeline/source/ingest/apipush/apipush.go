// Package apipush is the reference HTTP push adapter for external ingestion
// (pipeline/source/ingest/README.md): POST push accepts a JSON payload and
// publishes the bytes verbatim to a Source Process's input queue; GET health
// reports the underlying transport's liveness.
//
// The adapter is a transport bridge, nothing more. It does not transform the
// payload (boundary translation is the calling adapter's own logic, applied
// BEFORE the bytes reach this endpoint) and it does not sign (the downstream
// Source ingest runtime issues the FirstDrop — see pipeline/source/ingest).
// It therefore depends only on the transport.Publisher seam: an extension
// repository can read this package as the canonical example of bridging an
// external protocol onto the pipeline contract.
//
// The strict canonical-JSON gate here is validation, not transformation: the
// published bytes are exactly the received bytes. The Source runtime's own
// gate (ingest.go Stage 2) stays authoritative; this one exists so an HTTP
// client gets a synchronous 400 instead of a silently StatusErrored async
// event it cannot observe.
//
// Delivery semantics are the broker's: the adapter does not buffer or retry,
// and a 202 means "published", not "signed" — FirstDrop issuance is
// asynchronous. Authentication is deliberately out of scope: the deployment
// mounts this handler behind its own middleware (`cmd/pipeline` wraps it with
// the L1 PDP check).
package apipush

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"

	"github.com/provin-line/oss/canon"
	"github.com/provin-line/oss/pipeline/transport"
)

// ErrMissingPublisher is returned by New when Config.Publisher is nil.
var ErrMissingPublisher = errors.New("apipush: Publisher is required")

// ErrInvalidBodyCap is returned by New when Config.MaxBodyBytes is not positive.
var ErrInvalidBodyCap = errors.New("apipush: MaxBodyBytes must be positive")

// Config holds all construction-time configuration for the push adapter.
type Config struct {
	// Publisher delivers accepted payloads to the Source Process's input queue
	// (its ingress subject). Required.
	Publisher transport.Publisher

	// MaxBodyBytes caps the request body (reader-enforced, so chunked bodies
	// are bounded too). Required > 0.
	MaxBodyBytes int

	// Logger receives diagnostic output. nil = slog.Default().
	Logger *slog.Logger
}

// Handler is the HTTP push adapter. Construct with New. Routes are relative
// to the mount point: "POST /push" and "GET /health" — a node mounts one
// Handler per push-enabled loop under a per-loop prefix (http.StripPrefix).
type Handler struct {
	cfg    Config
	logger *slog.Logger
	mux    *http.ServeMux
}

// New validates cfg and returns a ready-to-mount Handler.
func New(cfg Config) (*Handler, error) {
	if cfg.Publisher == nil {
		return nil, ErrMissingPublisher
	}
	if cfg.MaxBodyBytes <= 0 {
		return nil, ErrInvalidBodyCap
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	h := &Handler{cfg: cfg, logger: logger, mux: http.NewServeMux()}
	h.mux.HandleFunc("/push", h.push)
	h.mux.HandleFunc("/health", h.health)
	return h, nil
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

// push runs the pinned gate order (each gate short-circuits): method (405) →
// media type (415) → body cap (413) → empty (400) → strict JSON (400) →
// publish (503) → 202 with the payload's content address.
func (h *Handler) push(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// The media type must be application/json; parameters (charset etc.) are
	// accepted and ignored. Missing or unparsable headers fail the gate — the
	// payload profile is JSON (profile norm), so an undeclared body is refused
	// rather than sniffed.
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	// Reader-enforced cap: never trust ContentLength (chunked bodies carry none).
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, int64(h.cfg.MaxBodyBytes)))
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, fmt.Sprintf("body exceeds %d bytes", h.cfg.MaxBodyBytes), http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(body) == 0 {
		http.Error(w, "empty body: a FirstDrop payload is never empty (profile norm)", http.StatusBadRequest)
		return
	}
	// Strict canonical-JSON gate (duplicate keys, trailing data, precision
	// drift). Validation only — the published bytes are the received bytes.
	var strictIn interface{}
	if err := canon.NewStrictDecoder(body).Decode(&strictIn); err != nil {
		http.Error(w, "strict JSON decode: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := h.cfg.Publisher.Publish(body); err != nil {
		h.logger.Error("apipush: publish failed", "err", err)
		http.Error(w, "publish failed", http.StatusServiceUnavailable)
		return
	}
	sum := sha256.Sum256(body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	// The content address of the accepted bytes — equal to the FirstDrop's
	// inputHash/outputHash (verbatim ingestion), so the client can correlate
	// the asynchronously issued credential.
	fmt.Fprintf(w, "{\"payload_hash\":%q}\n", "sha256:"+hex.EncodeToString(sum[:]))
}

// health reports transport liveness: 200 when the Publisher can serve
// traffic, 503 otherwise. Deployments typically leave this route
// unauthenticated (orchestrator probes carry no bearer).
func (h *Handler) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.cfg.Publisher.Healthy() {
		http.Error(w, "transport unhealthy", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
}
