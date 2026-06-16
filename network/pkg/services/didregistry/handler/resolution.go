package handler

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/network/pkg/services/didregistry"
	"github.com/provin-line/oss/network/pkg/services/didregistry/store"
)

// Resolver is the read view the raw-HTTP resolution endpoint needs.
// *didregistry.Service satisfies it.
type Resolver interface {
	ResolveDID(ctx context.Context, didStr string) (*did.DIDDocument, error)
}

// NewResolutionHandler serves W3C-style DID resolution over raw HTTP at
// GET /did/{segments}/did.json. The path segments between /did/ and /did.json
// are the did:dplaax segments after the registry (so /did/org/acme/pipeline/p1/
// did.json resolves did:dplaax:{registry}:org:acme:pipeline:p1); the registry is
// this server's own canonical identity. The body is the canonical DID Document
// JSON (application/did+json). Malformed DIDs are 400, misses are 404, and the
// path traversal guard is the did:dplaax parser the service applies (an unsafe
// segment fails to parse → 400).
func NewResolutionHandler(r Resolver, registry string) http.Handler {
	return &resolutionHandler{r: r, registry: registry}
}

type resolutionHandler struct {
	r        Resolver
	registry string
}

func (h *resolutionHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rest, ok := strings.CutPrefix(req.URL.Path, "/did/")
	if !ok {
		http.NotFound(w, req)
		return
	}
	rest, ok = strings.CutSuffix(rest, "/did.json")
	if !ok || rest == "" {
		http.NotFound(w, req)
		return
	}
	didStr := "did:dplaax:" + h.registry + ":" + strings.Join(strings.Split(rest, "/"), ":")
	doc, err := h.r.ResolveDID(req.Context(), didStr)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound):
			http.NotFound(w, req)
		case errors.Is(err, didregistry.ErrInvalidArgument), errors.Is(err, didregistry.ErrUnauthorized):
			http.Error(w, "invalid did", http.StatusBadRequest)
		default:
			http.Error(w, "resolution error", http.StatusInternalServerError)
		}
		return
	}
	body, err := doc.MarshalJSON()
	if err != nil {
		http.Error(w, "marshal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/did+json")
	_, _ = w.Write(body)
}
